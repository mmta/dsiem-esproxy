// This test uses docker compose to spawn vector, dsiem-frontend, dsiem-backend,
// elasticsearch, and surrealdb. After that, it spawns dsiem-esproxy and waits
// for vector to send logs to it. Then it checks if the expected alarm is
// present in elasticsearch and surrealdb.

use std::{
    env::current_exe,
    net::{IpAddr, SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::Command,
    thread::sleep,
    time::Duration,
};

use colored::Colorize;
use serde::Deserialize;

// as defined in the compose file
const ES_PORT: u16 = 9200;
const SDB_PORT: u16 = 8000;

const PROXY_PORT: u16 = 8181;

struct ComposeCleaner {}
impl Drop for ComposeCleaner {
    fn drop(&mut self) {
        let (_, test_dir) = get_dirs();
        assert!(run_in_shell(
            "docker compose down -v",
            test_dir.to_string_lossy().as_ref(),
            "failed to run docker compose down"
        )
        .success());
    }
}

#[derive(Default)]
struct BinSpawner {
    proxy: Option<std::process::Child>,
}
impl Drop for BinSpawner {
    fn drop(&mut self) {
        if let Some(f) = &mut self.proxy {
            assert!(f.kill().is_ok());
            assert!(f.wait().is_ok());
        }
    }
}

fn print(msg: &str, exclude_newline: bool) {
    if exclude_newline {
        print!("{}", msg.bold().green());
    } else {
        println!("{}", msg.bold().green());
    }
}

fn local_listener_ready(port: u16) -> bool {
    let addr = SocketAddr::from((IpAddr::V4("127.0.0.1".parse().unwrap()), port));
    TcpStream::connect_timeout(&addr, Duration::from_secs(3)).is_ok()
}

#[test]
fn test_e2e_vector_through_proxy_to_es_surrealdb() {
    let (debug_dir, test_dir) = get_dirs();
    let test_dir_str = test_dir.to_string_lossy().to_string();

    // ensure that the binary exist
    let bin = &"dsiem-esproxy";
    assert!(Path::exists(&debug_dir.join(bin)));

    let _cleaner = ComposeCleaner {};

    assert!(run_in_shell("docker compose up -d", &test_dir_str, "failed to run docker compose up").success());

    print("waiting for docker services to start", false);
    sleep(Duration::from_secs(15));

    print("checking if services ports are open", false);
    for port in &[ES_PORT, SDB_PORT] {
        print(&format!("checking port {} .. ", port), true);
        assert!(local_listener_ready(*port));
        print("up", false);
    }

    let mut proxy_cleaner = BinSpawner::default();

    print("running dsiem-esproxy", false);
    // add -vv before serve for more verbose output
    let proxy_cmd = "exec ./dsiem-esproxy -v serve --use-elasticsearch --use-surrealdb";
    let proxy = spawn_in_shell(proxy_cmd, debug_dir.to_string_lossy().as_ref(), "failed to run dsiem-esproxy");
    proxy_cleaner.proxy = Some(proxy);

    sleep(Duration::from_secs(1));
    print("checking if esproxy port is open .. ", true);
    assert!(local_listener_ready(PROXY_PORT));
    print("up", false);

    print("waiting for vector to send all the test logs", false);
    sleep(Duration::from_secs(15));

    print("checking result in Elasticsearch", false);
    check_elasticsearch();

    print("checking result in Surrealdb", false);
    check_surrealdb();

    print("test passed, waiting for cleanup to complete ..", false);
}

fn check_elasticsearch() {
    let client = reqwest::blocking::Client::new();
    let res =
        client.get(format!("http://localhost:{}/siem_alarms/_search", ES_PORT)).send().expect("Failed to send request");
    assert!(res.status().is_success());
    let val = res.json::<serde_json::Value>().expect("Failed to parse response");
    assert_eq!(val["hits"]["total"]["value"], 1);
    let alarm = &val["hits"]["hits"][0]["_source"];
    assert_eq!(alarm["title"], "Random netdevice, malware detected");
    assert_eq!(alarm["risk_class"], "Medium");
    assert_eq!(alarm["status"], "Open");
}

#[derive(Deserialize)]
struct SurrealdbEvent {
    stage: u8,
}
#[derive(Deserialize)]
struct SurrealdbAlarm {
    events: Vec<SurrealdbEvent>,
    status: String,
    risk_class: String,
    title: String,
}

fn check_surrealdb() {
    let client = reqwest::blocking::Client::new();

    let query = r#"
        SELECT
            alarm_id,
            title,
            status,
            risk_class,
            (SELECT event, stage FROM alarm_event WHERE alarm = $parent.id) AS events
        FROM
            alarm
        "#;
    let res = client
        .post(format!("http://localhost:{}/sql", SDB_PORT))
        .header("NS", "default")
        .header("DB", "dsiem")
        .header("Accept", "application/json")
        .body(query)
        .send()
        .expect("Failed to send request");
    assert!(res.status().is_success());
    let val = res.json::<serde_json::Value>().expect("Failed to parse response");

    let alarm = &val[0]["result"][0];
    let alarm: SurrealdbAlarm = serde_json::from_value(alarm.clone()).expect("Failed to parse alarm");
    assert_eq!(alarm.status, "Open");
    assert_eq!(alarm.risk_class, "Medium");
    assert_eq!(alarm.title, "Random netdevice, malware detected");
    let stage_1_count = alarm.events.iter().filter(|e| e.stage == 1).count();
    let stage_2_count = alarm.events.iter().filter(|e| e.stage == 2).count();
    let stage_3_count = alarm.events.iter().filter(|e| e.stage == 3).count();
    assert_eq!(stage_1_count, 1);
    assert_eq!(stage_2_count, 3);
    assert!(stage_3_count > 3);
}

fn run_in_shell(cmd: &str, dir: &str, fail_msg: &str) -> std::process::ExitStatus {
    let cmd = format!("cd {} && {}", dir, cmd);
    let out = Command::new("sh").arg("-c").arg(cmd).output().expect(fail_msg);
    out.status
}

fn spawn_in_shell(cmd: &str, dir: &str, fail_msg: &str) -> std::process::Child {
    let cmd = format!("cd {} && {}", dir, cmd);
    let out = Command::new("sh").arg("-c").arg(cmd).spawn().expect(fail_msg);
    out
}

fn get_dirs() -> (PathBuf, PathBuf) {
    // this should be in deps
    let current_exe = current_exe().unwrap();
    // get to debug
    let debug_dir = current_exe.parent().unwrap().parent().expect("Failed to get debug dir").to_owned();

    // get to test fixtures directory
    let root_dir = if debug_dir.ends_with("dsiem-esproxy/target/debug") {
        // for cargo test/nextest
        debug_dir.parent().unwrap().parent().unwrap()
    } else {
        // for cargo llvm-cov test/nextest
        debug_dir.parent().unwrap().parent().unwrap().parent().unwrap()
    };
    let test_dir = root_dir.join("tests");
    (debug_dir, test_dir)
}
