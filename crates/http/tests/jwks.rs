//! Acceptance tests of `GET /jwks` and the `jwks_uri` metadata member.

mod common;

use axum::http::StatusCode;
use common::{BASE, Harness, app_config, ctx, get};
use komainu_application::{AuthorizationService, SigningConfig, TokenService};
use komainu_domain::{SigningAlgorithm, SigningPolicy};
use komainu_http::{AppState, HttpConfig};
use komainu_testkit::TestEnv;
use serde_json::Value;

fn signing_env() -> TestEnv {
    let config =
        SigningConfig::new(vec![SigningAlgorithm::Es256], SigningPolicy::default()).unwrap();
    TestEnv::new(app_config()).with_signing(config)
}

/// A harness whose state got the signing key service, like `komainu::KomainuBuilder` does.
fn signing_harness() -> Harness {
    let env = signing_env();
    let service = env.deps.signing_keys.clone().unwrap();
    let harness = Harness::from_config(env, HttpConfig::new(BASE).unwrap());
    let state = harness.state.clone().with_signing_keys(service);
    Harness {
        router: komainu_http::router(state.clone()),
        state,
        ..harness
    }
}

fn json(body: &str) -> Value {
    serde_json::from_str(body).unwrap()
}

#[tokio::test]
async fn serves_the_keys_with_headers() {
    let harness = signing_harness();
    let service = harness.env.deps.signing_keys.clone().unwrap();
    service.rotate_due(&ctx()).await.unwrap();

    let reply = harness.send(get("/jwks", "")).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply.header("content-type"),
        Some("application/json;charset=UTF-8")
    );
    assert_eq!(reply.header("cache-control"), Some("public, max-age=300"));
    assert_eq!(reply.header("access-control-allow-origin"), Some("*"));
    assert_eq!(reply.body, &*service.jwks_json().await.unwrap());
    let keys = json(&reply.body)["keys"].as_array().unwrap().clone();
    assert_eq!(keys.len(), 1);
    assert!(!keys[0]["kid"].as_str().unwrap().is_empty());
    assert_eq!(keys[0]["use"], "sig");
    assert_eq!(keys[0]["alg"], "ES256");
}

#[tokio::test]
async fn no_keys_yet_is_an_empty_set() {
    let reply = signing_harness().send(get("/jwks", "")).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(json(&reply.body), serde_json::json!({"keys": []}));
}

#[tokio::test]
async fn without_signing_keys_it_is_404_and_the_metadata_has_no_jwks_uri() {
    let harness = Harness::new();
    let reply = harness.send(get("/jwks", "")).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert!(reply.body.is_empty());
    assert!(harness.state.metadata().jwks_uri.is_none());
    let metadata = harness
        .send(get("/.well-known/oauth-authorization-server", ""))
        .await;
    assert!(json(&metadata.body).get("jwks_uri").is_none());
}

#[tokio::test]
async fn metadata_has_jwks_uri_with_signing_keys() {
    let harness = signing_harness();
    let reply = harness
        .send(get("/.well-known/oauth-authorization-server", ""))
        .await;
    assert_eq!(
        json(&reply.body)["jwks_uri"],
        "https://auth.example.com/jwks"
    );
    assert_eq!(
        harness.state.metadata().jwks_uri.as_deref(),
        Some("https://auth.example.com/jwks")
    );
}

#[tokio::test]
async fn store_failure_is_a_500() {
    let harness = signing_harness();
    harness.env.store.fail_next();
    let reply = harness.send(get("/jwks", "")).await;
    assert_eq!(reply.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        reply.header("content-type"),
        Some("application/json;charset=UTF-8")
    );
    assert_eq!(reply.header("cache-control"), Some("no-store"));
    assert_eq!(reply.header("pragma"), Some("no-cache"));
    assert_eq!(
        json(&reply.body),
        serde_json::json!({"error": "server_error"})
    );
}

#[test]
fn new_alone_does_not_enable_jwks() {
    let env = signing_env();
    let state = AppState::new(
        AuthorizationService::new(env.deps.clone()),
        TokenService::new(env.deps.clone()),
        HttpConfig::new(BASE).unwrap(),
    );
    assert!(state.metadata().jwks_uri.is_none());
}
