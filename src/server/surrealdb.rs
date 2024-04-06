use std::sync::{atomic::Ordering, Arc};

use anyhow::{anyhow, Result};
use chrono::DateTime;
use dsiem::backlog::Backlog;
use json_value_remove::Remove;
use serde::Serialize;
use serde_json::Value;
use tracing::{debug, error, info, trace, warn};

use super::{app_error::AppError, AppState};

pub(crate) async fn send_alarm(
    state: &AppState,
    alarm: Arc<Backlog>,
    auth_header: Option<&str>,
) -> Result<(), AppError> {
    // upsert schema once if enabled
    if state.upsert_schema.load(Ordering::Relaxed) {
        info!(
            "upserting dsiem schema to {}, namespace: {}, database: {}",
            state.surrealdb.url, state.surrealdb.namespace, state.surrealdb.db
        );
        upsert_schema(&state.surrealdb.url, &state.surrealdb.namespace, &state.surrealdb.db, auth_header)
            .await
            .map_err(|e| {
                error!("failed to upsert dsiem schema: {}", e);
                AppError::from(e)
            })?;
        state.upsert_schema.store(false, Ordering::Relaxed);
    }

    let mut msg = format!("sending alarm to {}", state.surrealdb.url);
    if auth_header.is_some() {
        msg.push_str(" with supplied authorization header");
    }
    let alarm_id = alarm.id.clone();
    debug!(alarm.id, "{}", msg);
    post_to_surrealdb(
        &state.surrealdb.url,
        &state.surrealdb.namespace,
        &state.surrealdb.db,
        &state.surrealdb.alarm_table,
        (state.valid_status[0].to_string(), state.valid_tag[0].to_string()),
        auth_header,
        alarm,
    )
    .await
    .map_err(|e| {
        warn!(alarm.id = alarm_id, "failed to send alarm: {}", e);
        AppError::from(e)
    })
}

async fn upsert_schema(surrealdb_url: &str, ns: &str, db: &str, auth_header: Option<&str>) -> Result<()> {
    let client = reqwest::Client::new();
    let mut req = client
        .post(format!("{}/import", surrealdb_url))
        .header("NS", ns)
        .header("DB", db)
        .header("Accept", "application/json");
    if let Some(auth) = auth_header {
        req = req.header("Authorization", auth);
    }

    let schema = r#"
      DEFINE TABLE IF NOT EXISTS alarm SCHEMALESS CHANGEFEED 1d;
      DEFINE TABLE IF NOT EXISTS event SCHEMALESS;
      DEFINE TABLE IF NOT EXISTS alarm_event SCHEMALESS;
      DEFINE INDEX IF NOT EXISTS alarm_id ON TABLE alarm COLUMNS alarm_id UNIQUE;
      DEFINE INDEX IF NOT EXISTS event_id ON TABLE event COLUMNS event_id UNIQUE;
  "#;

    let result = req.body(schema.to_owned()).send().await?;
    if result.status().is_success() {
        info!("dsiem schema uploaded successfully");
    } else {
        let status = result.status();
        let msg = result.text().await.unwrap_or_default();
        return Err(anyhow!("failed to upload dsiem schema: {}: {}", status, msg));
    }
    Ok(())
}

#[derive(serde::Deserialize, Serialize, Debug)]
struct SurrealDBResult {
    pub result: Vec<Value>,
    pub status: String,
}
async fn post_to_surrealdb(
    surrealdb_url: &str,
    ns: &str,
    db: &str,
    table: &str,
    initial_status_tag: (String, String),
    auth_header: Option<&str>,
    alarm: Arc<Backlog>,
) -> Result<(), anyhow::Error> {
    // TODO: handle tag and status
    // should just pass the initial value of those, and if existing record equals to
    // it then replace it with the new one
    let client = reqwest::Client::new();

    let mut req = client
        .get(format!("{}/key/{}/{}", surrealdb_url, table, alarm.id))
        .header("NS", ns)
        .header("DB", db)
        .header("Accept", "application/json")
        .header("Content-Type", "application/json");
    if let Some(auth) = auth_header {
        req = req.header("Authorization", auth);
    };
    let result = req.send().await?;
    let status = result.status();
    let mut alarm_status = initial_status_tag.0;
    let mut alarm_tag = initial_status_tag.1;

    let mut should_create = false;
    // surrealdb doesnt use 404 for not found, it returns 200 with empty result
    if status.is_success() {
        let v = result.json::<Vec<SurrealDBResult>>().await?;
        let res = &v[0];
        debug!("SurrealDB response from ID check is status = {}, is empty = {}", res.status, res.result.is_empty());
        if res.status == "OK" {
            if res.result.is_empty() {
                info!(alarm.id, "no existing alarm found");
                should_create = true;
            } else {
                info!(alarm.id, "existing alarm found");
                let existing_risk = &res.result[0]["risk"].to_string().parse::<u8>().unwrap_or(0);
                if *existing_risk > alarm.risk.load(Ordering::Relaxed) {
                    info!(
                        alarm.id,
                        "skipping update since existing alarm has higher risk, existing: {}, new: {}",
                        existing_risk,
                        alarm.risk.load(Ordering::Relaxed)
                    );
                    return Ok(());
                } else {
                    debug!("existing risk: {}, new risk: {}", existing_risk, alarm.risk.load(Ordering::Relaxed));
                }
                let updated_time = &res.result[0]["updated_time"].to_string().replace('"', "");
                let updated_ts = DateTime::parse_from_rfc3339(updated_time)?.timestamp();
                let new_ts = alarm.update_time.load(Ordering::Relaxed);
                if updated_ts >= new_ts {
                    info!(alarm.id, "skipping update since existing alarm has ≥ updated_time: {}", updated_time);
                    return Ok(());
                } else {
                    debug!("existing updated_time: {}, new updated_time: {}", updated_ts, new_ts);
                }
                let existing_status = res.result[0]["status"].to_string().replace('"', "");
                let existing_tag = res.result[0]["tag"].to_string().replace('"', "");
                if existing_status != alarm_status {
                    alarm_status = existing_status;
                }
                if existing_tag != alarm_tag {
                    alarm_tag = existing_tag;
                }
            }
        } else {
            return Err(anyhow!("failed checking if alarm {} already exist: {:?}", alarm.id, res));
        }
    }

    debug!("will now upsert alarm, should create: {}", should_create);
    let url = format!("{}/key/{}/{}", surrealdb_url, table, alarm.id);
    let mut req = if should_create { client.post(url) } else { client.put(url) }
        .header("NS", ns)
        .header("DB", db)
        .header("Accept", "application/json")
        .header("Content-Type", "application/json");
    if let Some(auth) = auth_header {
        req = req.header("Authorization", auth);
    };
    let alarm_id = alarm.id.clone();
    let timestamp = DateTime::from_timestamp(alarm.created_time.load(Ordering::Relaxed), 0)
        .ok_or(anyhow!("alarm {} cannot convert created_time (unix) to timestamp (datetime)", alarm_id))?;
    let updated_time = DateTime::from_timestamp(alarm.update_time.load(Ordering::Relaxed), 0)
        .ok_or(anyhow!("alarm {} cannot convert update_time (unix) to updated_time (datetime)", alarm_id))?;

    let mut val = serde_json::to_value(alarm)?;
    val["timestamp"] = serde_json::Value::String(timestamp.to_rfc3339());
    val["updated_time"] = serde_json::Value::String(updated_time.to_rfc3339());
    val["status"] = serde_json::Value::String(alarm_status);
    val["tag"] = serde_json::Value::String(alarm_tag);
    _ = val.remove("/created_time");
    _ = val.remove("/update_time");

    trace!("alarm : {}", val.to_string());

    let result = req.json(&val).send().await?;
    let status = result.status();
    if status.is_success() {
        let v = result.json::<Vec<SurrealDBResult>>().await?;
        let res = &v[0];
        if res.status == "OK" {
            info!(alarm.id = alarm_id, "alarm sent successfully");
            Ok(())
        } else {
            Err(anyhow!("failed to send alarm: {:?}", res))
        }
    } else {
        Err(anyhow::anyhow!("failed to send alarm: {}", result.status()))
    }
}
