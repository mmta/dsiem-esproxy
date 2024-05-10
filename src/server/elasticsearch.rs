use std::sync::{atomic::Ordering, Arc};

use anyhow::{anyhow, Result};
use arcstr::ArcStr;
use chrono::{DateTime, Utc};
use dsiem::backlog::Backlog;
use mini_moka::sync::Cache;
use serde::Serialize;
use serde_json::{json, Value};
use tracing::{debug, error, info, warn};

use super::{app_error::AppError, AppState};

pub(crate) async fn send_alarm(
    state: &AppState,
    alarm: Arc<Backlog>,
    auth_header: Option<&str>,
) -> Result<(), AppError> {
    // upsert template once if enabled
    if state.upsert_template.load(Ordering::Relaxed) {
        info!("upserting siem_alarms template to {}", state.es.url);
        upsert_template(&state.es.url, auth_header).await.map_err(|e| {
            error!("failed to upsert siem_alarms template: {}", e);
            AppError::from(e)
        })?;
        state.upsert_template.store(false, Ordering::Relaxed);
    }

    let alarm_id = ArcStr::from(&alarm.id);
    let perm_index = if let Some(v) = state.cache.get(&alarm_id) {
        debug!(alarm.id, "using cached permanent index {}", v);
        v.clone()
    } else {
        match get_perm_index(&state.es.url, &state.es.id_index, auth_header, &alarm.id, &state.cache).await {
            Some(v) => v,
            _ => {
                let f = &format!("{}-{}", state.es.alarm_index, Utc::now().format("%Y.%m.%d"));
                f.into()
            }
        }
    };

    let mut msg = format!("sending alarm to {}/{}", state.es.url, perm_index);

    if auth_header.is_some() {
        msg.push_str(" with supplied authorization header");
    }
    debug!(alarm.id, "{}", msg);

    post_to_es(&state.es.url, &perm_index, auth_header, alarm).await.map_err(|e| {
        warn!(alarm.id = alarm_id.to_string(), "failed to send alarm: {}", e);
        AppError::from(e)
    })
}

async fn upsert_template(es_url: &str, auth_header: Option<&str>) -> Result<()> {
    let siem_alarms_template = json!({
        "index_patterns" : [ "siem_alarms-*" ],
        "version" : 1,
        "settings" : {
        "number_of_replicas": 0,
        "number_of_shards": 1,
        "index.refresh_interval" : "1s"
        },
        "aliases" : {
            "siem_alarms" : {},
            "siem_alarms_id_lookup" : {}
        },
        "mappings": {
            "dynamic_templates": [
            {
                "strings_as_keywords": {
                "match_mapping_type": "string",
                "mapping": {
                    "type": "text",
                    "norms": false,
                    "fields": {
                    "keyword": {
                        "type": "keyword",
                        "ignore_above": 256
                    }
                    }
                }
                }
            }
            ],
            "properties": {
            "src_ips": { "type": "ip" },
            "dst_ips": { "type": "ip" }
            }
        }
    });

    let client = reqwest::Client::new();
    let template_url = format!("{}/_template/{}", es_url, "siem_alarms");

    // check if template already exists
    let mut req = client.get(&template_url);
    if let Some(auth) = auth_header {
        req = req.header("Authorization", auth);
    }
    let result = req.send().await?;
    if result.status().is_success() {
        debug!("siem_alarms template already exists");
        return Ok(());
    }
    let mut req = client.put(&template_url);
    if let Some(auth) = auth_header {
        req = req.header("Authorization", auth);
    }
    let result = req.json(&siem_alarms_template).send().await?;
    if result.status().is_success() {
        info!("siem_alarms template uploaded successfully");
        Ok(())
    } else {
        Err(anyhow::anyhow!("failed to upload siem_alarms template: {}", result.status()))
    }
}

#[derive(serde::Deserialize, Serialize, Debug)]
struct Param {
    alarm: Arc<Backlog>,
    // this will be passed as a parameter to the painless script
    // to set the @timestamp, which should point to the time the alarm was received
    // by Elasticsearch
    now_millis_ts: u64,
}

#[derive(serde::Deserialize, Serialize, Debug)]
struct ScriptBlock {
    lang: String,
    source: String,
    params: Param,
}

#[derive(serde::Deserialize, Serialize, Debug)]
struct UpsertAlarm {
    scripted_upsert: bool,
    upsert: serde_json::Value,
    script: ScriptBlock,
}

async fn post_to_es(
    es_url: &str,
    index: &str,
    auth_header: Option<&str>,
    alarm: Arc<Backlog>,
) -> Result<(), anyhow::Error> {
    let client = reqwest::Client::new();
    let mut req = client.post(format!("{}/{}/_update/{}", es_url, index, alarm.id));
    if let Some(auth) = auth_header {
        req = req.header("Authorization", auth);
    };
    let alarm_id = alarm.id.clone();
    let timestamp = DateTime::from_timestamp(alarm.created_time.load(Ordering::Relaxed), 0)
        .ok_or(anyhow!("alarm {} cannot convert created_time (unix) to timestamp (datetime)", alarm_id))?;
    let updated_time = DateTime::from_timestamp(alarm.update_time.load(Ordering::Relaxed), 0)
        .ok_or(anyhow!("alarm {} cannot convert update_time (unix) to updated_time (datetime)", alarm_id))?;

    let painless_script = r#"
      if ( ctx.op == 'update' ) {
          if (params.alarm.get('risk') < ctx._source.risk) {
              ctx.op = 'none';
              return
          } else if (params.alarm.get('risk') == ctx._source.risk) {
              ZonedDateTime old_tm = ZonedDateTime.parse(ctx._source.updated_time);
              ZonedDateTime new_tm = ZonedDateTime.parse(params.alarm.get('updated_time'));
              if (new_tm.isBefore(old_tm)) {
                  ctx.op = 'none';
                  return
              }
          }
      }
      ctx._source.title = params.alarm.get('title');
      ctx._source.kingdom = params.alarm.get('kingdom');
      ctx._source.category = params.alarm.get('category');

      ctx._source.perm_index = params.alarm.get('perm_index');
      ctx._source.timestamp = params.alarm.get('timestamp');
      ctx._source.updated_time = params.alarm.get('updated_time');

      ctx._source.risk = params.alarm.get('risk');
      ctx._source.risk_class = params.alarm.get('risk_class');
      ctx._source.src_ips = params.alarm.get('src_ips');
      ctx._source.dst_ips = params.alarm.get('dst_ips');
      ctx._source.networks = params.alarm.get('networks');
      ctx._source.rules = params.alarm.get('rules');
      if (params.alarm.get('intel_hits') != null) {
          ctx._source.intel_hits = params.alarm.get('intel_hits')
      }
      if (params.alarm.get('vulnerabilities') != null) {
          ctx._source.vulnerabilities = params.alarm.get('vulnerabilities')
      }
      if (params.alarm.get('custom_data') != null) {
          ctx._source.custom_data = params.alarm.get('custom_data')
      }
      if (ctx._source.status == null) {
          ctx._source.status = params.alarm.get('status');
      }
      if (ctx._source.tag == null) {
          ctx._source.tag = params.alarm.get('tag');
      }

      Instant instant = Instant.ofEpochMilli(params['now_millis_ts']);
      ctx._source['@timestamp'] = ZonedDateTime.ofInstant(instant, ZoneId.of('Z'));
  "#;

    let now_millis_ts = Utc::now().timestamp_millis() as u64;
    let data = UpsertAlarm {
        scripted_upsert: true,
        upsert: serde_json::json!({}),
        script: ScriptBlock {
            lang: "painless".to_owned(),
            params: Param { alarm, now_millis_ts },
            source: painless_script.to_owned(),
        },
    };

    let mut val = serde_json::to_value(data).unwrap();
    val["script"]["params"]["alarm"]["timestamp"] = serde_json::Value::String(timestamp.to_rfc3339());
    val["script"]["params"]["alarm"]["updated_time"] = serde_json::Value::String(updated_time.to_rfc3339());
    val["script"]["params"]["alarm"]["perm_index"] = serde_json::Value::String(index.to_owned());

    let result = req.json(&val).send().await?;
    if result.status().is_success() {
        info!(alarm.id = alarm_id, "alarm sent successfully");
        Ok(())
    } else {
        Err(anyhow::anyhow!("failed to send alarm: {}", result.status()))
    }
}

#[derive(serde::Deserialize, Default, Debug)]
struct IdSearchResult {
    _index: String,
    _type: String,
    _id: String,
}

async fn get_perm_index(
    es_url: &str,
    index: &str,
    auth_token: Option<&str>,
    id: &str,
    cache: &Cache<ArcStr, ArcStr>,
) -> Option<ArcStr> {
    let client = reqwest::Client::new();
    let mut req = client.get(format!("{}/{}/_search?q=_id:{}", es_url, index, id));
    if let Some(auth) = auth_token {
        req = req.header("Authorization", auth);
    };

    let resp = req
        .send()
        .await
        .map_err(|e| {
            // network related error
            warn!("failed to get permanent index: {}", e);
            e
        })
        .ok()?;

    if !resp.status().is_success() {
        let status = resp.status();
        let mut msg = format!("failed to get permanent index, status code: {}", status);
        let resp_body = resp.text().await.unwrap_or_default();
        if let Ok(v) = serde_json::from_str::<Value>(&resp_body) {
            let err_msg = v["error"]["reason"].as_str().unwrap_or_default();
            if !err_msg.is_empty() {
                msg.push_str(&format!(", message: {}", err_msg));
            }
        };
        // warn only when the status is not 404. 404 is expected on new alarm.
        match status {
            reqwest::StatusCode::NOT_FOUND => warn!(alarm.id = id, "{}", msg),
            _ => debug!(alarm.id = id, "{}", msg),
        };
        return None;
    }
    match resp.json::<Value>().await {
        Ok(v) => {
            let first = v["hits"]["hits"].as_array().and_then(|arr| arr.first());
            first
                .and_then(|v| serde_json::from_value::<IdSearchResult>(v.clone()).ok())
                .map(|v| {
                    debug!(alarm.id = id, "found permanent index: {}", v._index);
                    cache.insert(id.into(), v._index.clone().into());
                    Some(v._index.into())
                })
                .unwrap_or_else(|| {
                    warn!(alarm.id = id, "failed to get permanent index: no hits");
                    None
                })
        }
        Err(e) => {
            warn!("failed to get permanent index: {}", e);
            None
        }
    }
}
