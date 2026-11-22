//! Acceptance tests for the authorization endpoints, login, consent, logout and the common
//! headers (http.md acceptance criteria; design F-1, F-2, N-6, N-7).

mod common;

use axum::http::StatusCode;
use common::*;
use komainu_domain::GrantType;

const SECURITY_HEADERS: [(&str, &str); 5] = [
    ("x-frame-options", "DENY"),
    (
        "content-security-policy",
        "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
    ),
    ("cache-control", "no-store"),
    ("referrer-policy", "no-referrer"),
    ("x-content-type-options", "nosniff"),
];

fn assert_security_headers(reply: &Reply) {
    for (name, value) in SECURITY_HEADERS {
        assert_eq!(reply.header(name), Some(value), "header {name}");
    }
}

struct Started {
    request_id: String,
    csrf: String,
}

async fn setup(h: &Harness) -> Registered {
    h.create_user("alice").await;
    h.register(confidential(&[GrantType::AuthorizationCode]))
        .await
}

async fn start(h: &Harness, client: &Registered) -> (Reply, Started) {
    let reply = h.send(get(&authorize_uri(&client.id(), ""), "")).await;
    assert_eq!(reply.status, StatusCode::FOUND);
    let request_id = query_param(reply.location(), "request_id").expect("request_id");
    let csrf = reply.cookie_value("komainu_csrf").expect("csrf cookie");
    (reply, Started { request_id, csrf })
}

fn login_body(s: &Started, password: &str) -> String {
    format!(
        "request_id={}&csrf_token={}&username=alice&password={}",
        s.request_id,
        s.csrf,
        password.replace(' ', "+")
    )
}

#[tokio::test]
async fn full_authorization_code_flow() {
    let h = Harness::new();
    let client = setup(&h).await;
    let (reply, s) = start(&h, &client).await;
    assert_eq!(
        reply.location(),
        format!("{BASE}/login?request_id={}", s.request_id)
    );
    let csrf_cookie = reply.set_cookie("komainu_csrf").unwrap();
    assert!(csrf_cookie.contains("HttpOnly"));
    assert!(csrf_cookie.contains("SameSite=Lax"));
    assert!(csrf_cookie.contains("Path=/"));
    assert!(csrf_cookie.contains("Max-Age=600"));
    assert!(!csrf_cookie.contains("Secure"));
    let csrf_cookie_header = format!("komainu_csrf={}", s.csrf);

    let form = h
        .send(get(
            &format!("/login?request_id={}", s.request_id),
            &csrf_cookie_header,
        ))
        .await;
    assert_eq!(form.status, StatusCode::OK);
    assert!(form.body.contains("Example App"));
    assert!(form.body.contains(&format!("value=\"{}\"", s.csrf)));
    assert!(form.body.contains(&format!("action=\"{BASE}/login\"")));

    let login = h
        .send(post_form(
            "/login",
            &csrf_cookie_header,
            &login_body(&s, PASSWORD),
        ))
        .await;
    assert_eq!(login.status, StatusCode::FOUND);
    assert_eq!(
        login.location(),
        format!("{BASE}/authorize/resume?request_id={}", s.request_id)
    );
    let session_cookie = login.set_cookie("komainu_session").unwrap();
    assert!(session_cookie.contains("HttpOnly"));
    assert!(session_cookie.contains("Max-Age=28800"));
    let session = login.cookie_value("komainu_session").unwrap();
    let cookies = format!("komainu_csrf={}; komainu_session={session}", s.csrf);

    let consent = h
        .send(get(
            &format!("/authorize/resume?request_id={}", s.request_id),
            &cookies,
        ))
        .await;
    assert_eq!(consent.status, StatusCode::OK);
    assert!(consent.body.contains("Read your data"));

    let decision = h
        .send(post_form(
            "/authorize/decision",
            &cookies,
            &format!(
                "request_id={}&csrf_token={}&decision=approve",
                s.request_id, s.csrf
            ),
        ))
        .await;
    assert_eq!(decision.status, StatusCode::FOUND);
    let location = decision.location();
    assert!(location.starts_with("https://app.example/cb?"));
    assert_eq!(query_param(location, "code").unwrap().len(), 43);
    assert_eq!(query_param(location, "state").as_deref(), Some("xyz"));
}

#[tokio::test]
async fn deny_redirects_with_access_denied() {
    let h = Harness::new();
    let client = setup(&h).await;
    let (_, s) = start(&h, &client).await;
    let csrf_cookie = format!("komainu_csrf={}", s.csrf);
    let login = h
        .send(post_form("/login", &csrf_cookie, &login_body(&s, PASSWORD)))
        .await;
    let session = login.cookie_value("komainu_session").unwrap();
    let cookies = format!("{csrf_cookie}; komainu_session={session}");
    let decision = h
        .send(post_form(
            "/authorize/decision",
            &cookies,
            &format!(
                "request_id={}&csrf_token={}&decision=deny",
                s.request_id, s.csrf
            ),
        ))
        .await;
    assert_eq!(decision.status, StatusCode::FOUND);
    assert_eq!(
        query_param(decision.location(), "error").as_deref(),
        Some("access_denied")
    );
}

#[tokio::test]
async fn unknown_client_is_a_400_page_without_redirect() {
    let h = Harness::new();
    let reply = h
        .send(get(
            &authorize_uri("00000000-0000-0000-0000-000000000000", ""),
            "",
        ))
        .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert!(reply.header("location").is_none());
    assert_security_headers(&reply);
}

#[tokio::test]
async fn unknown_scope_redirects_with_invalid_scope() {
    let h = Harness::new();
    let client = setup(&h).await;
    let reply = h
        .send(get(&authorize_uri(&client.id(), "&scope=unknown"), ""))
        .await;
    assert_eq!(reply.status, StatusCode::FOUND);
    let location = reply.location();
    assert!(location.starts_with("https://app.example/cb?"));
    assert_eq!(
        query_param(location, "error").as_deref(),
        Some("invalid_scope")
    );
    assert!(query_param(location, "error_description").is_some());
    assert_eq!(query_param(location, "state").as_deref(), Some("xyz"));
}

#[tokio::test]
async fn login_with_wrong_csrf_or_no_cookie_is_rejected() {
    let h = Harness::new();
    let client = setup(&h).await;
    let (_, s) = start(&h, &client).await;
    let body = login_body(&s, PASSWORD);

    let mismatch = h
        .send(post_form(
            "/login",
            "komainu_csrf=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            &body,
        ))
        .await;
    assert_eq!(mismatch.status, StatusCode::BAD_REQUEST);
    assert!(mismatch.set_cookie("komainu_session").is_none());

    let no_cookie = h.send(post_form("/login", "", &body)).await;
    assert_eq!(no_cookie.status, StatusCode::BAD_REQUEST);
    assert!(no_cookie.set_cookie("komainu_session").is_none());
}

#[tokio::test]
async fn wrong_password_renders_the_form_again() {
    let h = Harness::new();
    let client = setup(&h).await;
    let (_, s) = start(&h, &client).await;
    let reply = h
        .send(post_form(
            "/login",
            &format!("komainu_csrf={}", s.csrf),
            &login_body(&s, "wrong"),
        ))
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.body.contains("Invalid username or password."));
    assert!(reply.body.contains("value=\"alice\""));
    assert!(reply.set_cookie("komainu_session").is_none());
    assert_security_headers(&reply);
}

#[tokio::test]
async fn cookies_get_secure_when_configured() {
    let h = Harness::with(true, 16 * 1024);
    let client = setup(&h).await;
    let (reply, s) = start(&h, &client).await;
    assert!(
        reply
            .set_cookie("komainu_csrf")
            .unwrap()
            .contains("; Secure")
    );
    let login = h
        .send(post_form(
            "/login",
            &format!("komainu_csrf={}", s.csrf),
            &login_body(&s, PASSWORD),
        ))
        .await;
    assert!(
        login
            .set_cookie("komainu_session")
            .unwrap()
            .contains("; Secure")
    );
}

#[tokio::test]
async fn html_screens_carry_security_headers() {
    let h = Harness::new();
    let client = setup(&h).await;
    let (_, s) = start(&h, &client).await;
    let csrf_cookie = format!("komainu_csrf={}", s.csrf);
    let login_page = h
        .send(get(
            &format!("/login?request_id={}", s.request_id),
            &csrf_cookie,
        ))
        .await;
    assert_security_headers(&login_page);

    let login = h
        .send(post_form("/login", &csrf_cookie, &login_body(&s, PASSWORD)))
        .await;
    let session = login.cookie_value("komainu_session").unwrap();
    let consent = h
        .send(get(
            &format!("/authorize/resume?request_id={}", s.request_id),
            &format!("{csrf_cookie}; komainu_session={session}"),
        ))
        .await;
    assert_eq!(consent.status, StatusCode::OK);
    assert_security_headers(&consent);

    let error = h.send(get("/login?request_id=nope", "")).await;
    assert_eq!(error.status, StatusCode::BAD_REQUEST);
    assert_security_headers(&error);
}

#[tokio::test]
async fn consent_screen_escapes_the_client_name() {
    let h = Harness::new();
    h.create_user("alice").await;
    let client = h
        .register_named(
            "<script>alert(1)</script>",
            confidential(&[GrantType::AuthorizationCode]),
        )
        .await;
    let (_, s) = start(&h, &client).await;
    let csrf_cookie = format!("komainu_csrf={}", s.csrf);
    let login = h
        .send(post_form("/login", &csrf_cookie, &login_body(&s, PASSWORD)))
        .await;
    let session = login.cookie_value("komainu_session").unwrap();
    let consent = h
        .send(get(
            &format!("/authorize/resume?request_id={}", s.request_id),
            &format!("{csrf_cookie}; komainu_session={session}"),
        ))
        .await;
    // askama 0.16 writes numeric references (&#60;) instead of &lt;; both are equivalent HTML.
    assert!(consent.body.contains("&#60;script&#62;"));
    assert!(!consent.body.contains("<script>"));
}

#[tokio::test]
async fn logout_deletes_the_session_cookie() {
    let h = Harness::new();
    let client = setup(&h).await;
    let (_, s) = start(&h, &client).await;
    let csrf_cookie = format!("komainu_csrf={}", s.csrf);
    let login = h
        .send(post_form("/login", &csrf_cookie, &login_body(&s, PASSWORD)))
        .await;
    let session = login.cookie_value("komainu_session").unwrap();
    let reply = h
        .send(post_form(
            "/logout",
            &format!("komainu_session={session}"),
            "",
        ))
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.body.contains("Signed out."));
    assert!(
        reply
            .set_cookie("komainu_session")
            .unwrap()
            .contains("Max-Age=0")
    );
    assert_security_headers(&reply);
}
