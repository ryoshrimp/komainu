//! Acceptance tests for `POST /revoke` (token-revocation design F-1, F-7, F-9, F-10, F-11).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::*;
use komainu_application::{AdminService, AuditKind, TokenService};
use komainu_domain::{ClientType, GrantType, TokenEndpointAuthMethod};
use komainu_http::HttpConfig;
use komainu_testkit::TestEnv;

fn basic(id: &str, secret: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{id}:{secret}")))
}

fn post(uri: &str, content_type: &str, auth: Option<&str>, body: &str) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, content_type);
    if let Some(auth) = auth {
        builder = builder.header(header::AUTHORIZATION, auth);
    }
    builder.body(Body::from(body.to_owned())).unwrap()
}

fn form(uri: &str, auth: Option<&str>, body: &str) -> Request<Body> {
    post(uri, "application/x-www-form-urlencoded", auth, body)
}

async fn cc_client(h: &Harness) -> Registered {
    let mut input = confidential(&[GrantType::ClientCredentials]);
    input.redirect_uris.clear();
    h.register(input).await
}

async fn issue(h: &Harness, c: &Registered) -> String {
    let reply = h
        .send(form(
            "/token",
            Some(&basic(&c.id(), &c.secret())),
            "grant_type=client_credentials",
        ))
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_str(&reply.body).unwrap();
    json["access_token"].as_str().unwrap().to_owned()
}

async fn alive(h: &Harness, token: &str) -> bool {
    TokenService::new(h.env.deps.clone())
        .verify_access_token(token)
        .await
        .unwrap()
        .is_some()
}

fn failed_audits(h: &Harness) -> usize {
    h.env
        .store
        .audit_events()
        .iter()
        .filter(|e| e.kind == AuditKind::ClientAuthenticationFailed)
        .count()
}

fn assert_error(reply: &Reply, status: StatusCode, code: &str) {
    assert_eq!(reply.status, status);
    assert!(
        reply.body.contains(&format!("\"error\":\"{code}\"")),
        "{}",
        reply.body
    );
    assert_eq!(reply.header("cache-control"), Some("no-store"));
    assert_eq!(reply.header("pragma"), Some("no-cache"));
    assert_eq!(
        reply.header("content-type"),
        Some("application/json;charset=UTF-8")
    );
}

#[tokio::test]
async fn revoking_with_basic_returns_empty_200_and_kills_the_token() {
    let h = Harness::new();
    let c = cc_client(&h).await;
    let token = issue(&h, &c).await;
    let reply = h
        .send(form(
            "/revoke",
            Some(&basic(&c.id(), &c.secret())),
            &format!("token={token}&token_type_hint=access_token"),
        ))
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.body, "");
    assert_eq!(reply.header("content-type"), None);
    assert_eq!(reply.header("cache-control"), Some("no-store"));
    assert_eq!(reply.header("pragma"), Some("no-cache"));
    assert!(!alive(&h, &token).await);
}

#[tokio::test]
async fn revoking_with_body_credentials_and_unknown_token_succeeds() {
    let h = Harness::new();
    let mut input = confidential(&[GrantType::ClientCredentials]);
    input.redirect_uris.clear();
    input.auth_method = TokenEndpointAuthMethod::ClientSecretPost;
    let c = h.register(input).await;
    let issued = h
        .send(form(
            "/token",
            None,
            &format!(
                "grant_type=client_credentials&client_id={}&client_secret={}",
                c.id(),
                c.secret()
            ),
        ))
        .await;
    let json: serde_json::Value = serde_json::from_str(&issued.body).unwrap();
    let token = json["access_token"].as_str().unwrap().to_owned();
    let unknown = h
        .send(form(
            "/revoke",
            None,
            &format!(
                "token=no-such-token&client_id={}&client_secret={}",
                c.id(),
                c.secret()
            ),
        ))
        .await;
    assert_eq!(unknown.status, StatusCode::OK);
    assert!(alive(&h, &token).await);
    let reply = h
        .send(form(
            "/revoke",
            None,
            &format!(
                "token={token}&client_id={}&client_secret={}",
                c.id(),
                c.secret()
            ),
        ))
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(!alive(&h, &token).await);
}

#[tokio::test]
async fn another_clients_token_is_invalid_grant_and_audited() {
    let h = Harness::new();
    let a = cc_client(&h).await;
    let b = h
        .register_named("Other App", {
            let mut input = confidential(&[GrantType::ClientCredentials]);
            input.redirect_uris.clear();
            input
        })
        .await;
    let token = issue(&h, &a).await;
    let reply = h
        .send(form(
            "/revoke",
            Some(&basic(&b.id(), &b.secret())),
            &format!("token={token}"),
        ))
        .await;
    assert_error(&reply, StatusCode::BAD_REQUEST, "invalid_grant");
    assert!(alive(&h, &token).await);
    let audited = h
        .env
        .store
        .audit_events()
        .iter()
        .any(|e| e.kind == AuditKind::TokenRevocationClientMismatch);
    assert!(audited);
}

#[tokio::test]
async fn client_authentication_failures_are_401_or_400() {
    let h = Harness::new();
    let c = cc_client(&h).await;
    let token = issue(&h, &c).await;
    let body = format!("token={token}");

    let wrong = h
        .send(form("/revoke", Some(&basic(&c.id(), "wrong")), &body))
        .await;
    assert_error(&wrong, StatusCode::UNAUTHORIZED, "invalid_client");
    assert_eq!(
        wrong.header("www-authenticate"),
        Some(r#"Basic realm="komainu""#)
    );

    let anonymous = h.send(form("/revoke", None, &body)).await;
    assert_error(&anonymous, StatusCode::UNAUTHORIZED, "invalid_client");
    assert_eq!(anonymous.header("www-authenticate"), None);
    assert!(alive(&h, &token).await);
}

#[tokio::test]
async fn a_broken_basic_header_is_401_even_without_a_token() {
    let h = Harness::new();
    // Client authentication is decided before the token parameter is looked at (§4.1).
    let reply = h
        .send(form("/revoke", Some("Basic !!!not-base64!!!"), ""))
        .await;
    assert_error(&reply, StatusCode::UNAUTHORIZED, "invalid_client");
    assert_eq!(
        reply.header("www-authenticate"),
        Some(r#"Basic realm="komainu""#)
    );
}

#[tokio::test]
async fn post_disabled_and_public_client_failures_are_401() {
    let h = Harness::new();
    let mut input = confidential(&[GrantType::ClientCredentials]);
    input.redirect_uris.clear();
    input.auth_method = TokenEndpointAuthMethod::ClientSecretPost;
    let c = h.register(input).await;
    let issued = h
        .send(form(
            "/token",
            None,
            &format!(
                "grant_type=client_credentials&client_id={}&client_secret={}",
                c.id(),
                c.secret()
            ),
        ))
        .await;
    let json: serde_json::Value = serde_json::from_str(&issued.body).unwrap();
    let token = json["access_token"].as_str().unwrap().to_owned();

    // Wrong secret in the body: 401 without WWW-Authenticate.
    let wrong = h
        .send(form(
            "/revoke",
            None,
            &format!("token={token}&client_id={}&client_secret=wrong", c.id()),
        ))
        .await;
    assert_error(&wrong, StatusCode::UNAUTHORIZED, "invalid_client");
    assert_eq!(wrong.header("www-authenticate"), None);
    assert_eq!(failed_audits(&h), 1);
    assert!(alive(&h, &token).await);

    // Disabled client. disable_client itself revokes the client's grants (ClientDisabled), so
    // the token is already dead here; the request is judged by its 401 and the audit.
    h.admin.disable_client(&ctx(), &c.id).await.unwrap();
    let disabled = h
        .send(form(
            "/revoke",
            None,
            &format!(
                "token={token}&client_id={}&client_secret={}",
                c.id(),
                c.secret()
            ),
        ))
        .await;
    assert_error(&disabled, StatusCode::UNAUTHORIZED, "invalid_client");
    assert_eq!(failed_audits(&h), 2);
}

#[tokio::test]
async fn public_client_is_refused_when_public_clients_are_off() {
    // Public clients are allowed while registering and for the positive control.
    let env = TestEnv::new(app_config().with_allow_public_clients(true));
    let mut input = confidential(&[GrantType::AuthorizationCode]);
    input.client_type = ClientType::Public;
    input.auth_method = TokenEndpointAuthMethod::None;
    let public_id = AdminService::new(env.deps.clone())
        .register_client(&ctx(), input)
        .await
        .unwrap()
        .client
        .id;
    let body = format!("token=unissued&client_id={}", public_id.as_inner());
    let strict_env = TestEnv {
        deps: komainu_application::Dependencies {
            config: std::sync::Arc::new(app_config()),
            ..env.deps.clone()
        },
        store: env.store.clone(),
        clock: env.clock.clone(),
    };
    let config = || HttpConfig::new(BASE).unwrap().with_cookie_secure(false);
    let allowed = Harness::from_config(env, config());
    let ok = allowed.send(form("/revoke", None, &body)).await;
    assert_eq!(ok.status, StatusCode::OK);
    assert_eq!(failed_audits(&allowed), 0);

    let strict = Harness::from_config(strict_env, config());
    let reply = strict.send(form("/revoke", None, &body)).await;
    assert_error(&reply, StatusCode::UNAUTHORIZED, "invalid_client");
    assert_eq!(failed_audits(&strict), 1);
}

#[tokio::test]
async fn malformed_requests_are_invalid_request() {
    let h = Harness::new();
    let c = cc_client(&h).await;
    let token = issue(&h, &c).await;
    let auth = basic(&c.id(), &c.secret());
    let bad = StatusCode::BAD_REQUEST;

    // Not a form.
    let json = h
        .send(post("/revoke", "application/json", Some(&auth), "{}"))
        .await;
    assert_error(&json, bad, "invalid_request");
    // No token.
    let none = h.send(form("/revoke", Some(&auth), "")).await;
    assert_error(&none, bad, "invalid_request");
    // Duplicated token.
    let dup = h
        .send(form(
            "/revoke",
            Some(&auth),
            &format!("token={token}&token={token}"),
        ))
        .await;
    assert_error(&dup, bad, "invalid_request");
    // Duplicated client_id / client_secret.
    let dup_id = h
        .send(form(
            "/revoke",
            None,
            &format!(
                "token={token}&client_id={0}&client_id={0}&client_secret={1}",
                c.id(),
                c.secret()
            ),
        ))
        .await;
    assert_error(&dup_id, bad, "invalid_request");
    let dup_secret = h
        .send(form(
            "/revoke",
            None,
            &format!(
                "token={token}&client_id={}&client_secret={1}&client_secret={1}",
                c.id(),
                c.secret()
            ),
        ))
        .await;
    assert_error(&dup_secret, bad, "invalid_request");
    // Basic plus a body secret.
    let both = h
        .send(form(
            "/revoke",
            Some(&auth),
            &format!("token={token}&client_secret={}", c.secret()),
        ))
        .await;
    assert_error(&both, bad, "invalid_request");
    // Basic id differs from the body client_id.
    let mismatch = h
        .send(form(
            "/revoke",
            Some(&auth),
            &format!("token={token}&client_id=someone-else"),
        ))
        .await;
    assert_error(&mismatch, bad, "invalid_request");
    // A body secret without a client_id.
    let secret_only = h
        .send(form(
            "/revoke",
            None,
            &format!("token={token}&client_secret={}", c.secret()),
        ))
        .await;
    assert_error(&secret_only, bad, "invalid_request");
    assert!(alive(&h, &token).await);
}
