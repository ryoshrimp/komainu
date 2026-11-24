//! Acceptance tests for `POST /token` and the common middleware (http.md acceptance criteria;
//! design F-3, F-4, F-5, F-8, N-8).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::*;
use komainu_domain::GrantType;

fn basic(id: &str, secret: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{id}:{secret}")))
}

fn token_request(auth: Option<&str>, body: &str) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(auth) = auth {
        builder = builder.header(header::AUTHORIZATION, auth);
    }
    builder.body(Body::from(body.to_owned())).unwrap()
}

async fn cc_client(h: &Harness) -> Registered {
    let mut input = confidential(&[GrantType::ClientCredentials]);
    input.redirect_uris.clear();
    h.register(input).await
}

#[tokio::test]
async fn client_credentials_with_basic_succeeds() {
    let h = Harness::new();
    let c = cc_client(&h).await;
    let reply = h
        .send(token_request(
            Some(&basic(&c.id(), &c.secret())),
            "grant_type=client_credentials&scope=read",
        ))
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply.header("content-type"),
        Some("application/json;charset=UTF-8")
    );
    assert_eq!(reply.header("cache-control"), Some("no-store"));
    assert_eq!(reply.header("pragma"), Some("no-cache"));
    let json: serde_json::Value = serde_json::from_str(&reply.body).unwrap();
    assert_token_field_is_b64token(&json, "access_token");
    assert!(reply.body.contains("\"token_type\":\"Bearer\""));
    assert!(reply.body.contains("\"expires_in\":3600"));
    assert!(reply.body.contains("\"scope\":\"read\""));
    assert!(!reply.body.contains("refresh_token"));
}

#[tokio::test]
async fn wrong_secret_gives_401_with_www_authenticate() {
    let h = Harness::new();
    let c = cc_client(&h).await;
    let reply = h
        .send(token_request(
            Some(&basic(&c.id(), "wrong")),
            "grant_type=client_credentials",
        ))
        .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        reply.header("www-authenticate"),
        Some(r#"Basic realm="komainu""#)
    );
    assert!(reply.body.contains("\"error\":\"invalid_client\""));
    assert_eq!(reply.header("cache-control"), Some("no-store"));
}

#[tokio::test]
async fn basic_plus_body_secret_is_invalid_request() {
    let h = Harness::new();
    let c = cc_client(&h).await;
    let reply = h
        .send(token_request(
            Some(&basic(&c.id(), &c.secret())),
            &format!("grant_type=client_credentials&client_secret={}", c.secret()),
        ))
        .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert!(reply.body.contains("\"error\":\"invalid_request\""));
}

#[tokio::test]
async fn percent_encoded_basic_credentials_are_decoded() {
    let h = Harness::new();
    let c = cc_client(&h).await;
    let encode = |value: &str| {
        // Encode every character, so the decoder must undo the escapes.
        value
            .bytes()
            .map(|b| format!("%{b:02X}"))
            .collect::<String>()
    };
    let reply = h
        .send(token_request(
            Some(&basic(&encode(&c.id()), &encode(&c.secret()))),
            "grant_type=client_credentials",
        ))
        .await;
    assert_eq!(reply.status, StatusCode::OK);

    let malformed = h
        .send(token_request(
            Some(&basic(&c.id(), "%zz")),
            "grant_type=client_credentials",
        ))
        .await;
    assert_eq!(malformed.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn non_form_content_type_is_invalid_request() {
    let h = Harness::new();
    let c = cc_client(&h).await;
    let request = Request::builder()
        .method("POST")
        .uri("/token")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, basic(&c.id(), &c.secret()))
        .body(Body::from("{}"))
        .unwrap();
    let reply = h.send(request).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert!(reply.body.contains("\"error\":\"invalid_request\""));
    assert_eq!(reply.header("cache-control"), Some("no-store"));
}

/// Runs authorize -> login -> decision and returns the issued authorization code.
/// Creates user alice; call once per Harness.
async fn obtain_code(h: &Harness, c: &Registered) -> String {
    h.create_user("alice").await;
    let started = h.send(get(&authorize_uri(&c.id(), ""), "")).await;
    let rid = query_param(started.location(), "request_id").unwrap();
    let csrf = started.cookie_value("komainu_csrf").unwrap();
    let csrf_cookie = format!("komainu_csrf={csrf}");
    let login = h
        .send(post_form(
            "/login",
            &csrf_cookie,
            &format!("request_id={rid}&csrf_token={csrf}&username=alice&password=correct+horse"),
        ))
        .await;
    let session = login.cookie_value("komainu_session").unwrap();
    let decision = h
        .send(post_form(
            "/authorize/decision",
            &format!("{csrf_cookie}; komainu_session={session}"),
            &format!("request_id={rid}&csrf_token={csrf}&decision=approve"),
        ))
        .await;
    query_param(decision.location(), "code").unwrap()
}

fn code_exchange_body(code: &str) -> String {
    format!(
        "grant_type=authorization_code&code={code}&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&code_verifier=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )
}

#[tokio::test]
async fn reused_authorization_code_is_invalid_grant() {
    let h = Harness::new();
    let c = h
        .register(confidential(&[GrantType::AuthorizationCode]))
        .await;
    let code = obtain_code(&h, &c).await;
    let body = code_exchange_body(&code);
    let auth = basic(&c.id(), &c.secret());
    let first = h.send(token_request(Some(&auth), &body)).await;
    assert_eq!(first.status, StatusCode::OK);
    let second = h.send(token_request(Some(&auth), &body)).await;
    assert_eq!(second.status, StatusCode::BAD_REQUEST);
    assert!(second.body.contains("\"error\":\"invalid_grant\""));
}

/// Mirrors `is_b64token` in `crates/application/src/ids.rs`; keep the two in sync.
/// RFC 6750 §2.1: `b64token = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="`
fn is_b64token(s: &str) -> bool {
    let body = s.trim_end_matches('=');
    !body.is_empty()
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~+/".contains(&b))
}

fn assert_token_field_is_b64token(json: &serde_json::Value, field: &str) {
    let token = json[field]
        .as_str()
        .unwrap_or_else(|| panic!("{field} missing in {json}"));
    assert!(is_b64token(token), "{field} is not a b64token: {token}");
}

#[tokio::test]
async fn authorization_code_tokens_are_bearer_b64tokens() {
    let h = Harness::new();
    let c = h
        .register(confidential(&[
            GrantType::AuthorizationCode,
            GrantType::RefreshToken,
        ]))
        .await;
    let code = obtain_code(&h, &c).await;
    let reply = h
        .send(token_request(
            Some(&basic(&c.id(), &c.secret())),
            &code_exchange_body(&code),
        ))
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.header("cache-control"), Some("no-store"));
    let json: serde_json::Value = serde_json::from_str(&reply.body).unwrap();
    assert_eq!(json["token_type"], "Bearer");
    assert_token_field_is_b64token(&json, "access_token");
    assert_token_field_is_b64token(&json, "refresh_token");
}

#[tokio::test]
async fn request_id_header_is_echoed_and_used_in_audit() {
    let h = Harness::new();
    let c = cc_client(&h).await;
    let mut request = token_request(
        Some(&basic(&c.id(), &c.secret())),
        "grant_type=client_credentials",
    );
    request
        .headers_mut()
        .insert("x-request-id", "abc-123".parse().unwrap());
    let reply = h.send(request).await;
    assert_eq!(reply.header("x-request-id"), Some("abc-123"));
    assert!(
        h.env
            .store
            .audit_events()
            .iter()
            .any(|event| event.request_id == "abc-123")
    );

    let without = h
        .send(token_request(
            Some(&basic(&c.id(), &c.secret())),
            "grant_type=client_credentials",
        ))
        .await;
    let generated = without.header("x-request-id").expect("generated id");
    assert!(is_uuid_v7(generated), "not a UUIDv7: {generated}");
}

#[tokio::test]
async fn invalid_request_id_header_is_replaced_with_a_uuid_v7() {
    let h = Harness::new();
    let c = cc_client(&h).await;
    let too_long = "a".repeat(129);
    for invalid in ["has space", "", too_long.as_str(), "caf\u{e9}"] {
        let mut request = token_request(
            Some(&basic(&c.id(), &c.secret())),
            "grant_type=client_credentials",
        );
        request
            .headers_mut()
            .insert("x-request-id", invalid.parse().unwrap());
        let reply = h.send(request).await;
        let id = reply.header("x-request-id").expect("request id");
        assert!(is_uuid_v7(id), "{invalid:?} was not replaced: {id}");
    }
    // The boundary: 128 visible characters are kept.
    let longest = "a".repeat(128);
    let mut request = token_request(None, "grant_type=client_credentials");
    request
        .headers_mut()
        .insert("x-request-id", longest.parse().unwrap());
    let reply = h.send(request).await;
    assert_eq!(reply.header("x-request-id"), Some(longest.as_str()));
}

fn is_uuid_v7(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| id.get_version_num() == 7)
}

#[tokio::test]
async fn oversized_body_is_rejected_with_413() {
    let h = Harness::new();
    let body = format!("grant_type=client_credentials&x={}", "a".repeat(17 * 1024));
    let reply = h.send(token_request(None, &body)).await;
    assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);
}
