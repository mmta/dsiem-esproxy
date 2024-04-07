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

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use axum::{
        body::Body,
        extract::connect_info::MockConnectInfo,
        http::{self, Request, StatusCode},
    };
    use serde_json::json;
    use tokio::join;
    use tower::{Service, ServiceExt};
    use tracing_test::traced_test;

    use super::*; // for `call`, `oneshot`, and `ready`

    #[tokio::test]
    #[traced_test]
    async fn test_alarm_handler() {
        let mut app = app(
            true,
            ESSink {
                url: ArcStr::from("http://localhost:19200"),
                enabled: true,
                id_index: ArcStr::from("siem_alarm_lookup"),
                alarm_index: ArcStr::from("siem_alarm"),
                upsert_template: true,
            },
            SurrealDBSink {
                url: ArcStr::from("http://localhost:18000"),
                enabled: true,
                namespace: ArcStr::from("default"),
                db: ArcStr::from("dsiem"),
                alarm_table: ArcStr::from("alarm"),
                upsert_schema: true,
            },
            vec!["Open".to_string(), "In Progress".to_string(), "Closed".to_string()],
            vec!["Identified Threat".to_string(), "Valid Threat".to_string()],
        )
        .unwrap()
        .layer(MockConnectInfo(SocketAddr::from(([1, 3, 3, 7], 666))))
        .into_service();

        // HTTP 400
        let b = Body::from(serde_json::to_vec(&json!({})).unwrap());
        let request = Request::builder()
            .uri("/alarms")
            .header(http::header::CONTENT_TYPE, "Application/Json")
            .method(http::Method::POST)
            .body(b)
            .unwrap();
        let response = app.ready().await.unwrap().call(request).await.expect("request failed");
        assert!(logs_contain("missing field `alarm_id`"));
        assert!(response.status() == StatusCode::BAD_REQUEST);

        let mut es =
            mockito::Server::new_with_opts_async(mockito::ServerOpts { port: 19200, ..Default::default() }).await;
        let _m1 = es.mock("GET", mockito::Matcher::Any).with_status(200).create_async();
        let _m2 = es.mock("POST", mockito::Matcher::Any).with_status(200).create_async();

        let res = r#"[{
            "result": [
                {
                    "risk": 0,
                    "updated_time": "2023-03-31T14:46:10.000Z"
                }
            ],
            "status": "OK"
        }]"#;
        let mut sdb =
            mockito::Server::new_with_opts_async(mockito::ServerOpts { port: 18000, ..Default::default() }).await;
        let _m3 = sdb
            .mock("POST", mockito::Matcher::Any)
            .with_body(res)
            .with_header("content-type", "application/json")
            .with_status(200)
            .create_async();
        let _m4 = sdb
            .mock("PUT", mockito::Matcher::Any)
            .with_body(res)
            .with_header("content-type", "application/json")
            .with_status(200)
            .create_async();
        let _m5 = sdb
            .mock("GET", mockito::Matcher::Any)
            .with_body(res)
            .with_header("content-type", "application/json")
            .with_status(200)
            .create_async();

        join!(_m1, _m2, _m3, _m4, _m5);

        let alarm = json!({
            "alarm_id": "id1",
            "title": "foo",
            "sensor": "foo",
            "src_ip": "10.0.0.3",
            "dst_ip": "10.0.0.2",
            "status": "Open",
            "tag": "Identified Threat",
            "kingdom": "foo",
            "category": "bar",
            "created_time": 1696264365,
            "update_time": 1696264370,
            "risk": 1,
            "risk_class": "Low",
            "src_ips": ["127.0.0.1"],
            "dst_ips": ["127.0.0.1"],
            "networks": ["0.0.0.0"],
            "rules": [{
                "stage": 1,
                "name": "foo",
                "occurrence": 1,
                "plugin_id": 1001,
                "plugin_sid": [ 1, 2 ],
                "from": "0.0.0.0",
                "to": "0.0.0.0",
                "port_from": "ANY",
                "port_to": "ANY",
                "protocol": "ANY",
                "type": "PluginRule",
                "reliability": 1,
                "timeout": 0,
            }]

        });
        let b = Body::from(serde_json::to_vec(&alarm).unwrap());
        let request = Request::builder()
            .uri("/alarms")
            .header(http::header::CONTENT_TYPE, "Application/Json")
            .header(http::header::AUTHORIZATION, "Basic Zm9vOmJhcgo=")
            .method(http::Method::POST)
            .body(b)
            .unwrap();
        let response = app.ready().await.unwrap().call(request).await.expect("request failed");
        assert!(response.status() == StatusCode::OK); // alarm accepted

        // test multiple alarms
        let alarms = Vec::from([alarm.clone(), alarm.clone()]);
        let b = Body::from(serde_json::to_vec(&alarms).unwrap());
        let request = Request::builder()
            .uri("/alarms")
            .header(http::header::CONTENT_TYPE, "Application/Json")
            .method(http::Method::POST)
            .body(b)
            .unwrap();
        let response = app.ready().await.unwrap().call(request).await.expect("request failed");
        assert!(response.status() == StatusCode::OK); // alarm accepted
    }
}
