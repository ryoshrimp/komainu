//! A custom `ScreenRenderer` replaces the screens without changing protocol behavior
//! (design F-5, F-7).

mod common;

use std::sync::{Arc, Mutex};

use common::*;
use komainu_domain::GrantType;
use komainu_http::{
    ConsentScreen, ErrorKind, ErrorScreen, LoggedOutScreen, LoginErrorKind, LoginScreen,
    RenderError, ScreenRenderer,
};

#[derive(Debug, Clone)]
enum Call {
    Login {
        action: String,
        csrf_token: String,
        request_id: String,
        username: String,
        error: Option<LoginErrorKind>,
    },
    Consent {
        action: String,
        csrf_token: String,
    },
    Error {
        kind: ErrorKind,
        status: u16,
        accept_language: Option<String>,
    },
    LoggedOut,
}

#[derive(Default)]
struct Recorder {
    calls: Mutex<Vec<Call>>,
    fail_login: bool,
}

impl Recorder {
    fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }
}

impl ScreenRenderer for Recorder {
    fn login(&self, s: &LoginScreen<'_>) -> Result<String, RenderError> {
        self.calls.lock().unwrap().push(Call::Login {
            action: s.form.action.to_owned(),
            csrf_token: s.form.csrf_token.to_owned(),
            request_id: s.form.authorization_request_id.to_owned(),
            username: s.username.to_owned(),
            error: s.error,
        });
        if self.fail_login {
            return Err(RenderError::new("boom"));
        }
        Ok("<p>login</p>".to_owned())
    }

    fn consent(&self, s: &ConsentScreen<'_>) -> Result<String, RenderError> {
        self.calls.lock().unwrap().push(Call::Consent {
            action: s.form.action.to_owned(),
            csrf_token: s.form.csrf_token.to_owned(),
        });
        Ok("<p>consent</p>".to_owned())
    }

    fn error(&self, s: &ErrorScreen<'_>) -> Result<String, RenderError> {
        self.calls.lock().unwrap().push(Call::Error {
            kind: s.kind,
            status: s.status,
            accept_language: s.request.accept_language.map(str::to_owned),
        });
        Ok("<p>error</p>".to_owned())
    }

    fn logged_out(&self, _s: &LoggedOutScreen<'_>) -> Result<String, RenderError> {
        self.calls.lock().unwrap().push(Call::LoggedOut);
        Ok("<p>logged out</p>".to_owned())
    }
}

fn harness(recorder: &Arc<Recorder>) -> Harness {
    Harness::with_screens(recorder.clone())
}

struct Started {
    request_id: String,
    csrf: String,
}

async fn start(h: &Harness) -> Started {
    h.create_user("alice").await;
    let client = h
        .register(confidential(&[GrantType::AuthorizationCode]))
        .await;
    let reply = h.send(get(&authorize_uri(&client.id(), ""), "")).await;
    Started {
        request_id: query_param(reply.location(), "request_id").unwrap(),
        csrf: reply.cookie_value("komainu_csrf").unwrap(),
    }
}

fn login_body(s: &Started, password: &str) -> String {
    format!(
        "request_id={}&csrf_token={}&username=alice&password={}",
        s.request_id,
        s.csrf,
        password.replace(' ', "+")
    )
}

fn assert_html(reply: &Reply, status: u16, body: &str) {
    assert_eq!(reply.status.as_u16(), status);
    assert_eq!(reply.body, body);
    assert_eq!(
        reply.header("content-type"),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(reply.header("x-frame-options"), Some("DENY"));
    assert!(reply.header("content-security-policy").is_some());
    assert_eq!(reply.header("cache-control"), Some("no-store"));
}

#[tokio::test]
async fn four_screens_use_the_custom_renderer() {
    let rec = Arc::new(Recorder::default());
    let h = harness(&rec);
    let s = start(&h).await;
    let csrf_cookie = format!("komainu_csrf={}", s.csrf);

    let login = h
        .send(get(
            &format!("/login?request_id={}", s.request_id),
            &csrf_cookie,
        ))
        .await;
    assert_html(&login, 200, "<p>login</p>");

    let session = h
        .send(post_form("/login", &csrf_cookie, &login_body(&s, PASSWORD)))
        .await
        .cookie_value("komainu_session")
        .unwrap();
    let cookies = format!("{csrf_cookie}; komainu_session={session}");
    let consent = h
        .send(get(
            &format!("/authorize/resume?request_id={}", s.request_id),
            &cookies,
        ))
        .await;
    assert_html(&consent, 200, "<p>consent</p>");

    let error = h.send(get("/login?request_id=bad", "")).await;
    assert_html(&error, 400, "<p>error</p>");

    let logout = h
        .send(post_form(
            "/logout",
            &format!("komainu_session={session}"),
            "",
        ))
        .await;
    assert_html(&logout, 200, "<p>logged out</p>");
    assert!(logout.set_cookie("komainu_session").is_some());

    let calls = rec.calls();
    let Call::Login {
        action,
        csrf_token,
        request_id,
        username,
        error,
    } = &calls[0]
    else {
        panic!("login first: {calls:?}");
    };
    assert_eq!(action, &format!("{BASE}/login"));
    assert_eq!(csrf_token, &s.csrf);
    assert_eq!(request_id, &s.request_id);
    assert_eq!((username.as_str(), *error), ("", None));
    let Call::Consent { action, csrf_token } = &calls[1] else {
        panic!("consent second: {calls:?}");
    };
    assert_eq!(action, &format!("{BASE}/authorize/decision"));
    assert_eq!(csrf_token, &s.csrf);
}

#[tokio::test]
async fn consent_from_authorize_sets_the_csrf_cookie_like_the_default() {
    let rec = Arc::new(Recorder::default());
    let h = harness(&rec);
    let s = start(&h).await;
    let csrf_cookie = format!("komainu_csrf={}", s.csrf);
    let session = h
        .send(post_form("/login", &csrf_cookie, &login_body(&s, PASSWORD)))
        .await
        .cookie_value("komainu_session")
        .unwrap();
    // A fresh GET /authorize with the session shows the consent screen and sets a new CSRF cookie.
    let client_id = {
        let c = h
            .register(confidential(&[GrantType::AuthorizationCode]))
            .await;
        c.id()
    };
    let reply = h
        .send(get(
            &authorize_uri(&client_id, ""),
            &format!("komainu_session={session}"),
        ))
        .await;
    assert_html(&reply, 200, "<p>consent</p>");
    assert!(reply.set_cookie("komainu_csrf").is_some());
}

#[tokio::test]
async fn invalid_credentials_pass_the_sent_username() {
    let rec = Arc::new(Recorder::default());
    let h = harness(&rec);
    let s = start(&h).await;
    let reply = h
        .send(post_form(
            "/login",
            &format!("komainu_csrf={}", s.csrf),
            &login_body(&s, "wrong"),
        ))
        .await;
    assert_html(&reply, 200, "<p>login</p>");
    let Some(Call::Login {
        username, error, ..
    }) = rec.calls().pop()
    else {
        panic!("login call");
    };
    assert_eq!(username, "alice");
    assert_eq!(error, Some(LoginErrorKind::InvalidCredentials));
}

#[tokio::test]
async fn login_post_without_csrf_token_is_request_not_found() {
    let rec = Arc::new(Recorder::default());
    let h = harness(&rec);
    let s = start(&h).await;
    let cookie = format!("komainu_csrf={}", s.csrf);
    let body = format!("request_id={}&username=alice&password=x", s.request_id);
    let reply = h.send(post_form("/login", &cookie, &body)).await;
    assert_html(&reply, 400, "<p>error</p>");
    let mismatch = h
        .send(post_form(
            "/login",
            &cookie,
            &format!(
                "request_id={}&csrf_token=other&username=alice&password=x",
                s.request_id
            ),
        ))
        .await;
    assert_eq!(mismatch.status.as_u16(), 400);
    let kinds: Vec<_> = rec
        .calls()
        .into_iter()
        .filter_map(|c| match c {
            Call::Error { kind, status, .. } => Some((kind, status)),
            _ => None,
        })
        .collect();
    assert_eq!(
        kinds,
        [
            (ErrorKind::RequestNotFound, 400),
            (ErrorKind::CsrfMismatch, 400)
        ]
    );
}

#[tokio::test]
async fn store_failure_is_temporarily_unavailable() {
    let rec = Arc::new(Recorder::default());
    let h = harness(&rec);
    let s = start(&h).await;
    h.env.store.fail_next();
    let reply = h
        .send(get(
            &format!("/login?request_id={}", s.request_id),
            &format!("komainu_csrf={}", s.csrf),
        ))
        .await;
    assert_html(&reply, 500, "<p>error</p>");
    assert!(matches!(
        rec.calls().last(),
        Some(Call::Error {
            kind: ErrorKind::TemporarilyUnavailable,
            status: 500,
            ..
        })
    ));
}

#[tokio::test]
async fn accept_language_is_passed_through() {
    let rec = Arc::new(Recorder::default());
    let h = harness(&rec);
    let mut request = get("/login?request_id=bad", "");
    request
        .headers_mut()
        .insert("accept-language", "ja".parse().unwrap());
    h.send(request).await;
    h.send(get("/login?request_id=bad", "")).await;
    let langs: Vec<_> = rec
        .calls()
        .into_iter()
        .filter_map(|c| match c {
            Call::Error {
                kind,
                accept_language,
                ..
            } => {
                assert_eq!(kind, ErrorKind::RequestNotFound);
                Some(accept_language)
            }
            _ => None,
        })
        .collect();
    assert_eq!(langs, [Some("ja".to_owned()), None]);
}

#[tokio::test]
async fn render_failure_is_a_plain_500_without_error_screen() {
    let rec = Arc::new(Recorder {
        fail_login: true,
        ..Recorder::default()
    });
    let h = harness(&rec);
    let s = start(&h).await;
    let reply = h
        .send(get(
            &format!("/login?request_id={}", s.request_id),
            &format!("komainu_csrf={}", s.csrf),
        ))
        .await;
    assert_eq!(reply.status.as_u16(), 500);
    assert_eq!(
        reply.header("content-type"),
        Some("text/plain; charset=utf-8")
    );
    assert_eq!(reply.body, "Internal Server Error");
    assert!(rec.calls().iter().all(|c| !matches!(c, Call::Error { .. })));
}
