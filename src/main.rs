use std::{
    net::{IpAddr, SocketAddr},
    process::ExitCode,
    str::FromStr,
    time::Duration,
};

use anyhow::{anyhow, Result};
use clap::{arg, command, Args, Parser, Subcommand};
use dsiem::{
    cmd_utils::{ctrlc_handler, log_startup_err, Validator as validator},
    tracer,
};
use tokio::{sync::broadcast, task::JoinSet, time::sleep};
use tracing::{debug, error, info};

mod server;

#[derive(Parser)]
#[command(
    author("https://github.com/defenxor/dsiem-esproxy"),
    version,
    about = "Dsiem Elasticsearch proxy",
    long_about = "Dsiem Elasticsearch proxy\n\nProxy alarm update request to Elasticsearch"
)]
struct Cli {
    #[command(subcommand)]
    subcommand: SubCommands,
    /// Increase logging verbosity
    #[arg(short('v'), long, action = clap::ArgAction::Count)]
    verbosity: u8,
    /// Enable debug output, for compatibility purpose
    #[arg(long = "debug", env = "DSIEM_DEBUG", value_name = "boolean", default_value_t = false)]
    debug: bool,
    /// Enable trace output, for compatibility purpose
    #[arg(long = "trace", env = "DSIEM_TRACE", value_name = "boolean", default_value_t = false)]
    trace: bool,
    /// Enable json-lines log output
    #[arg(short('j'), long = "json", env = "DSIEM_JSON", value_name = "boolean", default_value_t = false)]
    use_json: bool,
    /// Testing environment flag
    #[arg(long = "test-env", value_name = "boolean", default_value_t = false)]
    test_env: bool,
}

#[derive(Subcommand)]
enum SubCommands {
    #[command(about = "Start Dsiem ES proxy", long_about = "Start the Dsiem ES proxy server", name = "serve")]
    ServeCommand(ServeArgs),
}

#[derive(Args, Debug)]
struct ServeArgs {
    /// IP address for the HTTP server to listen on
    #[arg(
        short('a'),
        long = "ip-address",
        env = "DSIEM_ESPROXY_ADDRESS",
        value_name = "ip",
        default_value = "0.0.0.0"
    )]
    address: String,

    /// TCP port for the HTTP server to listen on
    #[arg(short('p'), long = "tcp-port", env = "DSIEM_ESPROXY_PORT", value_name = "tcp", default_value_t = 8181)]
    port: u16,
    /// Elasticsearch endpoint
    #[arg(
        short('e'),
        long = "es-endpoint",
        env = "DSIEM_ESPROXY_ELASTICSEARCH",
        value_name = "url",
        default_value = "http://localhost:9200"
    )]
    elasticsearch: String,
    /// Whether to use enable alarm output to Elasticsearch
    #[arg(
        long = "use-elasticsearch",
        value_name = "boolean",
        env = "DSIEM_ESPROXY_USE_ELASTICSEARCH",
        default_value_t = false
    )]
    use_elasticsearch: bool,
    /// Elasticsearch index for alarm id lookup
    #[arg(
        short('x'),
        long = "es-id-index",
        env = "DSIEM_ESPROXY_ID_INDEX",
        value_name = "url",
        default_value = "siem_alarms_id_lookup"
    )]
    id_index: String,
    /// Elasticsearch index for upserting alarms
    #[arg(
        short('i'),
        long = "es-alarm-index",
        env = "DSIEM_ESPROXY_ALARM_INDEX",
        value_name = "url",
        default_value = "siem_alarms"
    )]
    alarm_index: String,
    /// Valid alarm status
    #[arg(
        short('s'),
        long,
        env = "DSIEM_STATUS",
        value_name = "comma separated strings",
        use_value_delimiter = true,
        value_delimiter = ',',
        default_value = "Open,In-Progress,Closed"
    )]
    status: Vec<String>,
    /// Valid alarm tags
    #[arg(
        short('t'),
        long,
        env = "DSIEM_TAGS",
        value_name = "comma separated strings",
        use_value_delimiter = true,
        value_delimiter = ',',
        default_value = "Identified Threat,False Positive,Valid Threat,Security Incident"
    )]
    tag: Vec<String>,
    /// whether to upsert the default index_alarms template to elasticsearch
    #[arg(long = "upsert-index-alarms-template", value_name = "boolean", default_value_t = true)]
    upsert_template: bool,
    /// SurrealDB endpoint
    #[arg(
        short('b'),
        long = "surrealdb-endpoint",
        env = "DSIEM_ESPROXY_SURREALDB",
        value_name = "url",
        default_value = "http://localhost:8000"
    )]
    surrealdb: String,
    /// SurrealDB namespace
    #[arg(long = "surrealdb-ns", env = "DSIEM_ESPROXY_SURREALDB_NS", value_name = "string", default_value = "default")]
    surrealdb_ns: String,
    /// SurrealDB database
    #[arg(long = "surrealdb-db", env = "DSIEM_ESPROXY_SURREALDB_DB", value_name = "string", default_value = "dsiem")]
    surrealdb_db: String,
    /// SurrealDB table name for alarms
    #[arg(
        long = "surrealdb-table",
        env = "DSIEM_ESPROXY_SURREALDB_TABLE",
        value_name = "string",
        default_value = "alarm"
    )]
    surrealdb_table: String,
    /// Whether to use enable alarm output to SurrealDB. Note that
    /// --use-elasticsearch must be explicitly set to false to use SurrealDB
    #[arg(
        long = "use-surrealdb",
        value_name = "boolean",
        env = "DSIEM_ESPROXY_USE_SURREALDB",
        default_value_t = false
    )]
    use_surrealdb: bool,
    /// whether to upsert a default dsiem schema to surrealdb
    #[arg(long = "upsert-dsiem-schema", value_name = "boolean", default_value_t = true)]
    upsert_schema: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    match serve(true, true, Cli::parse()).await.is_ok() {
        true => ExitCode::SUCCESS,
        false => ExitCode::FAILURE,
    }
}

async fn serve(listen: bool, require_logging: bool, args: Cli) -> Result<()> {
    let test_env = args.test_env;

    let SubCommands::ServeCommand(mut sargs) = args.subcommand;

    let verbosity = validator::log_verbosity(args.trace, args.debug, args.verbosity);
    let log_format = validator::log_format(args.use_json);

    let otel_config = tracer::OtelConfig {
        tracing_enabled: false,
        otlp_endpoint: "".to_string(),
        service_name: "".to_string(),
        ..Default::default()
    };
    let subscriber = tracer::setup(verbosity, log_format, otel_config.clone())
        .map_err(|e| log_startup_err("setting up tracer", e))?;
    if let Err(e) = tracing::subscriber::set_global_default(subscriber) {
        if require_logging {
            return Err(log_startup_err("setting up global tracer", e.into()));
        }
    }

    let mut set = JoinSet::new();

    IpAddr::from_str(sargs.address.as_str()).map_err(|e| log_startup_err("parsing address parameter", e.into()))?;

    if sargs.port == 0 {
        return Err(log_startup_err("parsing port parameter", anyhow!("port cannot be 0")));
    }

    let (cancel_tx, _) = broadcast::channel::<()>(1);

    ctrlc_handler(cancel_tx.clone(), !test_env).map_err(|e| log_startup_err("setting up ctrl-c handler", e))?;

    let addr = sargs.address + ":" + sargs.port.to_string().as_str();

    if !sargs.use_surrealdb {
        sargs.use_elasticsearch = true;
    }
    if sargs.use_elasticsearch {
        info!("using elasticsearch sink: {}", sargs.elasticsearch);
    }
    if sargs.use_surrealdb {
        info!("using surrealdb sink: {}", sargs.surrealdb);
    }
    info!("starting dsiem es-proxy server listening on {}", addr);
    debug!("debugging on");

    let c = cancel_tx.clone();
    set.spawn(async move {
        let app = server::app(
            test_env,
            server::ESSink {
                url: sargs.elasticsearch.into(),
                enabled: sargs.use_elasticsearch,
                upsert_template: sargs.upsert_template,
                id_index: sargs.id_index.into(),
                alarm_index: sargs.alarm_index.into(),
            },
            server::SurrealDBSink {
                url: sargs.surrealdb.into(),
                enabled: sargs.use_surrealdb,
                namespace: sargs.surrealdb_ns.into(),
                db: sargs.surrealdb_db.into(),
                alarm_table: sargs.surrealdb_table.into(),
                upsert_schema: sargs.upsert_schema,
            },
            sargs.status,
            sargs.tag,
        )?;
        let listener = tokio::net::TcpListener::bind(addr.clone()).await?;
        let signal = async move {
            let mut rx = c.subscribe();
            let _ = rx.recv().await;
        };
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .with_graceful_shutdown(signal)
            .await
            .map_err(|e| anyhow!("serve error: {:?}", e))
    });

    if listen {
        while let Some(Ok(res)) = set.join_next().await {
            if let Err(e) = res {
                error!("{:?}", e);
                _ = cancel_tx.send(());
                return Err(e);
            }
        }
    } else {
        set.try_join_next();
        sleep(Duration::from_secs(1)).await; // gives time for all spawns to
                                             // await
    }

    Ok(())
}
