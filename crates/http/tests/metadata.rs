//! Acceptance tests of `GET /.well-known/oauth-authorization-server` (RFC 8414).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::{Harness, app_config, get};
use komainu_http::HttpConfig;
use komainu_testkit::TestEnv;
use serde_json::{Value, json};

const PATH: &str = "/.well-known/oauth-authorization-server";

fn json_body(body: &str) -> Value {
    serde_json::from_slice::<Value>(body.as_bytes()).unwrap()
}

fn request(method: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(PATH)
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn serves_the_document_with_headers() {
    let harness = Harness::from_config(
        TestEnv::new(app_config().with_allow_public_clients(true)),
        HttpConfig::new(common::BASE).unwrap(),
    );
    let reply = harness.send(get(PATH, "")).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply.header("content-type"),
        Some("application/json;charset=UTF-8")
    );
    assert_eq!(reply.header("access-control-allow-origin"), Some("*"));
    assert_eq!(reply.header("cache-control"), Some("public, max-age=3600"));
    assert!(reply.header("pragma").is_none());
    let expected = json!({
        "issuer": "https://auth.example.com",
        "authorization_endpoint": "https://auth.example.com/authorize",
        "token_endpoint": "https://auth.example.com/token",
        "revocation_endpoint": "https://auth.example.com/revoke",
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "revocation_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["read", "write"]
    });
    assert_eq!(json_body(&reply.body), expected);
    let with_query = harness.send(get(&format!("{PATH}?foo=bar"), "")).await;
    assert_eq!(with_query.status, StatusCode::OK);
    assert_eq!(json_body(&with_query.body), expected);
}

#[tokio::test]
async fn issuer_keeps_the_path_of_public_base_url() {
    let harness = Harness::from_config(
        TestEnv::new(app_config()),
        HttpConfig::new("https://example.com/auth").unwrap(),
    );
    let body = json_body(&harness.send(get(PATH, "")).await.body);
    assert_eq!(body["issuer"], "https://example.com/auth");
    assert_eq!(
        body["authorization_endpoint"],
        "https://example.com/auth/authorize"
    );
    assert_eq!(body["token_endpoint"], "https://example.com/auth/token");
    assert_eq!(
        body["revocation_endpoint"],
        "https://example.com/auth/revoke"
    );
}

#[tokio::test]
async fn public_clients_are_off_by_default() {
    let harness = Harness::new();
    let body = json_body(&harness.send(get(PATH, "")).await.body);
    let methods = json!(["client_secret_basic", "client_secret_post"]);
    assert_eq!(body["token_endpoint_auth_methods_supported"], methods);
    assert_eq!(body["revocation_endpoint_auth_methods_supported"], methods);
}

#[tokio::test]
async fn scopes_key_is_absent_without_scopes() {
    let harness = Harness::from_config(
        TestEnv::new(komainu_application::ApplicationConfig::default()),
        HttpConfig::new(common::BASE).unwrap(),
    );
    let body = json_body(&harness.send(get(PATH, "")).await.body);
    assert!(body.get("scopes_supported").is_none());
}

#[tokio::test]
async fn post_is_not_allowed_and_head_has_no_body() {
    let harness = Harness::new();
    let post = harness.send(request("POST")).await;
    assert_eq!(post.status, StatusCode::METHOD_NOT_ALLOWED);
    assert!(post.header("access-control-allow-origin").is_none());
    assert!(post.header("cache-control").is_none());

    let head = harness.send(request("HEAD")).await;
    assert_eq!(head.status, StatusCode::OK);
    assert_eq!(head.header("access-control-allow-origin"), Some("*"));
    assert_eq!(head.header("cache-control"), Some("public, max-age=3600"));
    assert_eq!(
        head.header("content-type"),
        Some("application/json;charset=UTF-8")
    );
    assert!(head.body.is_empty());
}

#[tokio::test]
async fn rust_value_equals_the_served_body() {
    let harness = Harness::new();
    let body = json_body(&harness.send(get(PATH, "")).await.body);
    assert_eq!(
        serde_json::to_value(harness.state.metadata()).unwrap(),
        body
    );
}
