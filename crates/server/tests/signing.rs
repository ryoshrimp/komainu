#![cfg(feature = "pg-tests")]
//! Acceptance tests of the signing keys on the server: `serve` and `key` (server.md).

mod common;

use std::path::Path;
use std::time::{Duration, Instant};

const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

fn append(config: &Path, extra: &str) {
    let mut body = std::fs::read_to_string(config).expect("read");
    body.push_str(extra);
    std::fs::write(config, body).expect("write");
}

async fn wait_ready(ops: std::net::SocketAddr, child: &mut common::ServeProcess) {
    let http = reqwest::Client::new();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(response) = http.get(format!("http://{ops}/healthz")).send().await
            && response.status() == 200
        {
            return;
        }
        child.assert_running();
        assert!(Instant::now() < deadline, "server did not start");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn keys(config: &Path) -> Vec<serde_json::Value> {
    let output = common::run(config, &["key", "list", "--format", "json"], None);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    serde_json::from_str(&common::stdout(&output)).expect("json")
}

#[tokio::test(flavor = "multi_thread")]
async fn serve_publishes_jwks_and_key_commands_manage_keys() {
    let db = common::start_db().await;
    let (listen, ops) = (common::free_addr(), common::free_addr());
    let config = common::write_config(&db.url, listen, ops);
    append(
        &config,
        &format!("\n[signing]\nencryption_key = \"{KEY}\"\nalgorithms = [\"ES256\"]\n"),
    );

    let mut child = common::ServeProcess::spawn(&config);
    wait_ready(ops, &mut child).await;

    let http = reqwest::Client::new();
    let jwks: serde_json::Value = http
        .get(format!("http://{listen}/jwks"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .map(|t| serde_json::from_str(&t).expect("json"))
        .unwrap();
    let published = jwks["keys"].as_array().expect("keys");
    assert_eq!(published.len(), 1, "{jwks}");
    assert_eq!(published[0]["alg"], "ES256");
    assert_eq!(published[0]["use"], "sig");

    let metadata: serde_json::Value = http
        .get(format!(
            "http://{listen}/.well-known/oauth-authorization-server"
        ))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .map(|t| serde_json::from_str(&t).expect("json"))
        .unwrap();
    assert_eq!(metadata["jwks_uri"], format!("http://{listen}/jwks"));

    let listed = keys(&config);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["status"], "active");
    assert_eq!(published[0]["kid"], listed[0]["kid"]);

    let output = common::run(&config, &["key", "rotate", "--alg", "ES256"], None);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let listed = keys(&config);
    assert_eq!(listed.len(), 2);
    let retired = listed
        .iter()
        .find(|k| k["status"] == "retired")
        .expect("retired key");
    assert!(listed.iter().any(|k| k["status"] == "active"));

    let kid = retired["kid"].as_str().unwrap();
    let output = common::run(&config, &["key", "revoke", kid], None);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(keys(&config).len(), 1);

    let output = common::run(&config, &["key", "revoke", kid], None);
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    let output = common::run(&config, &["key", "rotate", "--alg", "RS256"], None);
    assert_eq!(output.status.code(), Some(2), "{output:?}");

    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!all.contains(KEY));
}

#[tokio::test(flavor = "multi_thread")]
async fn disabled_grant_types_are_absent_from_metadata() {
    let db = common::start_db().await;
    let (listen, ops) = (common::free_addr(), common::free_addr());
    let config = common::write_config(&db.url, listen, ops);
    let body = std::fs::read_to_string(&config).unwrap();
    std::fs::write(
        &config,
        format!("[oauth]\ndisabled_grant_types = [\"client_credentials\"]\n{body}"),
    )
    .unwrap();

    let mut child = common::ServeProcess::spawn(&config);
    wait_ready(ops, &mut child).await;
    let metadata: serde_json::Value = reqwest::get(format!(
        "http://{listen}/.well-known/oauth-authorization-server"
    ))
    .await
    .unwrap()
    .text()
    .await
    .map(|t| serde_json::from_str(&t).expect("json"))
    .unwrap();
    let grants = metadata["grant_types_supported"].to_string();
    assert!(!grants.contains("client_credentials"), "{grants}");
    assert!(grants.contains("authorization_code"), "{grants}");
}
