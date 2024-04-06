use std::{
    net::SocketAddr,
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};

use anyhow::Result;
use arcstr::ArcStr;
use axum::{
    extract::{ConnectInfo, FromRequest, State},
    http::{header::HeaderMap, StatusCode},
    routing::post,
    Router,
};
use mini_moka::sync::Cache;
use serde_json::Value;
use tower_http::timeout::TimeoutLayer;
use tracing::{debug, error, info};

mod app_error;
mod elasticsearch;
mod surrealdb;
mod validate;

use app_error::AppError;
use dsiem::backlog::Backlog;

#[derive(Clone)]
pub struct AppState {
    pub _test_env: bool,
    pub es: Arc<ESSink>,
    pub surrealdb: Arc<SurrealDBSink>,
    pub valid_status: Arc<Vec<ArcStr>>,
    pub valid_tag: Arc<Vec<ArcStr>>,
    // cache for storing alarm ID lookup results
    pub cache: Cache<ArcStr, ArcStr>,
    // whether we should put the siem_alarms template to ES
    pub upsert_template: Arc<AtomicBool>,
    // whether we should put the dsiem schema template to SurrealDB
    pub upsert_schema: Arc<AtomicBool>,
}

#[derive(Clone)]
pub struct ESSink {
    pub url: ArcStr,
    pub enabled: bool,
    pub id_index: ArcStr,
    pub alarm_index: ArcStr,
    pub upsert_template: bool,
}
#[derive(Clone)]
pub struct SurrealDBSink {
    pub url: ArcStr,
    pub enabled: bool,
    pub namespace: ArcStr,
    pub db: ArcStr,
    pub alarm_table: ArcStr,
    pub upsert_schema: bool,
}
pub fn app(
    _test_env: bool,
    elasticsearch: ESSink,
    surrealdb: SurrealDBSink,
    valid_status: Vec<String>,
    valid_tag: Vec<String>,
) -> Result<Router> {
    // Time to live (TTL): 24 hours
    // Time to idle (TTI):  30 minutes
    let cache =
        Cache::builder().time_to_live(Duration::from_secs(86400)).time_to_idle(Duration::from_secs(1800)).build();
    let upsert_template = Arc::new(AtomicBool::new(elasticsearch.upsert_template));
    let upsert_schema = Arc::new(AtomicBool::new(surrealdb.upsert_schema));

    let state = AppState {
        _test_env,
        es: Arc::new(elasticsearch),
        surrealdb: Arc::new(surrealdb),
        valid_status: Arc::new(valid_status.iter().map(|s| s.into()).collect()),
        valid_tag: Arc::new(valid_tag.iter().map(|s| s.into()).collect()),
        cache,
        upsert_template,
        upsert_schema,
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
        let shared = Arc::new(alarm);
        if state.es.enabled {
            elasticsearch::send_alarm(&state, shared.clone(), auth_header).await?;
        };
        if state.surrealdb.enabled {
            surrealdb::send_alarm(&state, shared, auth_header).await?;
        }
    }
    Result::Ok(())
}
