#![cfg(feature = "pg-tests")]
//! Acceptance tests of `serve` and the ops listener.

mod common;

use std::process::Command;
use std::time::{Duration, Instant};

#[tokio::test(flavor = "multi_thread")]
async fn serve_health_metrics_and_sigterm() {
    let db = common::start_db().await;
    let (listen, ops) = (common::free_addr(), common::free_addr());
    let config = common::write_config(&db.url, listen, ops);

    // Create a client for the /token call.
    let out = common::stdout(&common::run(
        &config,
        &[
            "client",
            "create",
            "--name",
            "demo",
            "--grant-type",
            "client_credentials",
            "--scope",
            "read",
        ],
        None,
    ));
    let field = |name: &str| {
        out.lines()
            .find_map(|l| l.strip_prefix(&format!("{name}: ")))
            .expect("field")
            .to_owned()
    };

    let mut child = common::ServeProcess::spawn(&config);

    let http = reqwest::Client::new();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(response) = http.get(format!("http://{ops}/healthz")).send().await
            && response.status() == 200
        {
            break;
        }
        child.assert_running();
        assert!(Instant::now() < deadline, "server did not start");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let ready = http
        .get(format!("http://{ops}/readyz"))
        .send()
        .await
        .unwrap();
    assert_eq!(ready.status(), 200);

    let token = http
        .post(format!("http://{listen}/token"))
        .basic_auth(field("client_id"), Some(field("client_secret")))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("grant_type=client_credentials&scope=read")
        .send()
        .await
        .unwrap();
    assert_eq!(token.status(), 200);
    let body: serde_json::Value = serde_json::from_str(&token.text().await.unwrap()).unwrap();
    let access_token = body["access_token"].as_str().unwrap().to_owned();
    let revoked = http
        .post(format!("http://{listen}/revoke"))
        .basic_auth(field("client_id"), Some(field("client_secret")))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!("token={access_token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(revoked.status(), 200);
    let metrics = http
        .get(format!("http://{ops}/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(metrics.contains("komainu_http_requests_total"), "{metrics}");
    assert!(
        metrics.contains("komainu_token_requests_total"),
        "{metrics}"
    );
    assert!(
        metrics.contains("komainu_revocation_requests_total"),
        "{metrics}"
    );

    let started = Instant::now();
    let killed = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("kill");
    assert!(killed.success());
    let status = tokio::task::spawn_blocking(move || child.wait())
        .await
        .unwrap();
    assert_eq!(status.code(), Some(0));
    assert!(started.elapsed() < Duration::from_secs(30));
}
