use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{anyhow, Result};
use arcstr::ArcStr;
use axum::{
    extract::{ConnectInfo, FromRequest, State},
    http::{header::HeaderMap, StatusCode},
    routing::post,
    Router,
};
use chrono::prelude::*;
use dsiem::backlog::Backlog;
use mini_moka::sync::Cache;
use serde::Serialize;
use serde_json::{json, Value};
use tower_http::timeout::TimeoutLayer;
use tracing::{debug, error, info, warn};

mod app_error;
mod validate;

use app_error::AppError;

#[derive(Clone)]
pub struct AppState {
    pub _test_env: bool,
    pub elasticsearch_url: ArcStr,
    // index to use for alarm location (perm_index) lookup
    pub id_index: ArcStr,
    // index to use for alarm insert/update
    pub alarm_index: ArcStr,
    // valid entries for status and tag
    pub valid_status: Arc<Vec<ArcStr>>,
    pub valid_tag: Arc<Vec<ArcStr>>,
    // cache for storing alarm ID lookup results
    pub cache: Cache<ArcStr, ArcStr>,
    // whether we should put the siem_alarms template
    pub upsert_template: Arc<AtomicBool>,
}

pub fn app(
    _test_env: bool,
    elasticsearch_url: &str,
    id_index: &str,
    alarm_index: &str,
    valid_status: Vec<String>,
    valid_tag: Vec<String>,
    upsert_template: bool,
) -> Result<Router> {
    // Time to live (TTL): 24 hours
    // Time to idle (TTI):  30 minutes
    let cache =
        Cache::builder().time_to_live(Duration::from_secs(86400)).time_to_idle(Duration::from_secs(1800)).build();
    let upsert_template = Arc::new(AtomicBool::new(upsert_template));

    let state = AppState {
        _test_env,
        elasticsearch_url: elasticsearch_url.into(),
        id_index: id_index.into(),
        alarm_index: alarm_index.into(),
        valid_status: Arc::new(valid_status.iter().map(|s| s.into()).collect()),
        valid_tag: Arc::new(valid_tag.iter().map(|s| s.into()).collect()),
        cache,
        upsert_template,
    };

    fn routes(state: AppState) -> Router {
        Router::new().route("/alarms", post(alarms_handler)).route("/alarms/", post(alarms_handler)).with_state(state)
    }

    let app = routes(state).layer(TimeoutLayer::new(Duration::from_secs(5)));
    Ok(app)
}

// create an extractor that internally uses `axum::Json` but has a custom
// rejection
#[derive(FromRequest)]
#[from_request(via(axum::Json), rejection(AppError))]
pub struct JsonExtractor<T>(T);

pub async fn alarms_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    JsonExtractor(value): JsonExtractor<Value>,
) -> Result<(), AppError> {
    let auth_header = headers.get("Authorization").map(|v| v.to_str().unwrap_or_default());

    // upsert template once if enabled
    if state.upsert_template.load(Ordering::Relaxed) {
        info!("upserting siem_alarms template to {}", state.elasticsearch_url);
        upsert_siem_alarms_template(&state.elasticsearch_url, auth_header).await.map_err(|e| {
            error!("failed to upsert siem_alarms template: {}", e);
            AppError::from(e)
        })?;
        state.upsert_template.store(false, Ordering::Relaxed);
    }

    let alarms = if !value.is_array() {
        let alarm: Backlog = serde_json::from_value(value).map_err(|e| {
            let s = e.to_string();
            error!("cannot read alarm, json parse error: {}", s);
            AppError::new(StatusCode::BAD_REQUEST, &s)
        })?;
        Vec::from([alarm])
    } else {
        serde_json::from_value(value).map_err(|e| {
            let s = e.to_string();
            error!("cannot read events, json parse error: {}", s);
            AppError::new(StatusCode::BAD_REQUEST, &s)
        })?
    };

    info!("{} alarm(s) received from {}", alarms.len(), addr);
    for alarm in alarms {
        debug!(alarm.id, "processing alarm");

        validate::validate_alarm(&alarm, &state.valid_status, &state.valid_tag).map_err(|e| {
            let s = e.to_string();
            error!(alarm.id, "validate error: {}", s);
            AppError::new(StatusCode::BAD_REQUEST, &s)
        })?;
        let alarm_id = ArcStr::from(alarm.id.clone());
        let perm_index = if let Some(v) = state.cache.get(&alarm_id) {
            debug!(alarm.id, "using cached permanent index {}", v);
            v.clone()
        } else {
            match get_perm_index(&state.elasticsearch_url, &state.id_index, auth_header, &alarm.id, &state.cache).await
            {
                Some(v) => v,
                _ => {
                    let f = &format!("{}-{}", state.alarm_index, Utc::now().format("%Y.%m.%d"));
                    f.into()
                }
            }
        };

        let mut msg = format!("sending alarm to {}/{}", state.elasticsearch_url, perm_index);

        if auth_header.is_some() {
            msg.push_str(" with supplied authorization header");
        }
        debug!(alarm.id, "{}", msg);

        send_alarm(&state.elasticsearch_url, &perm_index, auth_header, alarm).await.map_err(|e| {
            warn!(alarm.id = alarm_id.to_string(), "failed to send alarm: {}", e);
            AppError::from(e)
        })?;
    }
    Result::Ok(())
}

async fn upsert_siem_alarms_template(es_url: &str, auth_header: Option<&str>) -> Result<()> {
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
    alarm: Backlog,
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

async fn send_alarm(es_url: &str, index: &str, auth_header: Option<&str>, alarm: Backlog) -> Result<(), anyhow::Error> {
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

#[derive(serde::Deserialize, Default)]
struct IdSearchResult {
    _index: String,
    _type: String,
    _id: String,
    found: bool,
}

async fn get_perm_index(
    es_url: &str,
    index: &str,
    auth_token: Option<&str>,
    id: &str,
    cache: &Cache<ArcStr, ArcStr>,
) -> Option<ArcStr> {
    let client = reqwest::Client::new();
    let mut req = client.get(format!("{}/{}/_doc/{}?_source=_id", es_url, index, id));
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
    match resp.json::<IdSearchResult>().await {
        Ok(v) => {
            debug!(alarm.id = id, "found permanent index: {}", v._index);
            cache.insert(id.into(), v._index.clone().into());
            if v.found {
                Some(v._index.into())
            } else {
                None
            }
        }
        Err(e) => {
            warn!("failed to get permanent index: {}", e);
            None
        }
    }
}
