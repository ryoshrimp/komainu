#![cfg(feature = "pg-tests")]
//! End-to-end scenario: a real `komainu serve` process, driven over HTTP with reqwest and
//! the admin CLI, covering F-1 to F-12 and checking that no secret reaches the log (N-3).

mod common;

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use komainu_adapter_postgres::PgUnitOfWorkFactory;
use komainu_server::{config, wiring};
use reqwest::header::{CACHE_CONTROL, LOCATION, PRAGMA, SET_COOKIE, WWW_AUTHENTICATE};
use reqwest::{Client, Response, StatusCode, redirect::Policy};
use url::Url;
use url::form_urlencoded;

const REDIRECT_URI: &str = "https://app.example/cb";
const PASSWORD: &str = "e2e-correct-horse-battery";
const WRONG_PASSWORD: &str = "e2e-wrong-password-value";
const WRONG_SECRET: &str = "e2e-not-the-client-secret";

/// A running `komainu serve` process whose output is collected into a buffer.
struct Server {
    child: Child,
    logs: Arc<Mutex<Vec<u8>>>,
    readers: Vec<std::thread::JoinHandle<()>>,
}

/// Copies everything `stream` yields into `sink` until it closes.
fn collect(
    mut stream: impl Read + Send + 'static,
    sink: Arc<Mutex<Vec<u8>>>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut chunk = [0u8; 8192];
        while let Ok(n) = stream.read(&mut chunk) {
            if n == 0 {
                break;
            }
            sink.lock().unwrap().extend_from_slice(&chunk[..n]);
        }
    })
}

impl Server {
    fn start(config: &Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_komainu"))
            .env_clear()
            // Debug level makes the leak check stricter than the default `info`.
            .env("KOMAINU_LOG__FORMAT", "json")
            .env("KOMAINU_LOG__FILTER", "debug")
            .arg("--config")
            .arg(config)
            .arg("serve")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn komainu");
        // tracing-subscriber writes to stdout; stderr is collected too, to be safe.
        let logs = Arc::new(Mutex::new(Vec::new()));
        let readers = vec![
            collect(child.stdout.take().expect("stdout"), Arc::clone(&logs)),
            collect(child.stderr.take().expect("stderr"), Arc::clone(&logs)),
        ];
        Self {
            child,
            logs,
            readers,
        }
    }

    /// Panics with the collected output when the process has already exited.
    fn assert_running(&mut self) {
        if let Some(status) = self.child.try_wait().expect("try_wait") {
            let logs = String::from_utf8_lossy(&self.logs.lock().unwrap()).into_owned();
            panic!("komainu serve exited early with {status}:\n{logs}");
        }
    }

    /// Sends SIGTERM, waits for exit code 0 and returns everything the server logged.
    fn stop(mut self) -> String {
        let killed = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()
            .expect("kill");
        assert!(killed.success());
        let status = self.child.wait().expect("wait");
        assert_eq!(status.code(), Some(0));
        for reader in self.readers.drain(..) {
            reader.join().unwrap();
        }
        let bytes = self.logs.lock().unwrap().clone();
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        // Only reached when the test failed before `stop`.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Standard base64 with padding, as used in the `Authorization: Basic` header.
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn field(out: &str, name: &str) -> String {
    out.lines()
        .find_map(|l| l.strip_prefix(&format!("{name}: ")))
        .unwrap_or_else(|| panic!("no {name} in {out}"))
        .to_owned()
}

/// Registers a client with the CLI and returns `(client_id, client_secret)`.
fn create_client(config: &Path, args: &[&str]) -> (String, String) {
    let mut full = vec!["client", "create"];
    full.extend_from_slice(args);
    let output = common::run(config, &full, None);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let out = common::stdout(&output);
    (field(&out, "client_id"), field(&out, "client_secret"))
}

fn form(pairs: &[(&str, &str)]) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for (key, value) in pairs {
        serializer.append_pair(key, value);
    }
    serializer.finish()
}

/// Value of the hidden input `name` in an HTML page.
fn hidden(html: &str, name: &str) -> String {
    let marker = format!("name=\"{name}\" value=\"");
    let start = html
        .find(&marker)
        .unwrap_or_else(|| panic!("no {name} in {html}"))
        + marker.len();
    let end = html[start..].find('"').expect("closing quote") + start;
    html[start..end].to_owned()
}

/// Value of the cookie `name` in the `Set-Cookie` headers of a response.
fn set_cookie(response: &Response, name: &str) -> Option<String> {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|v| v.strip_prefix(&format!("{name}=")))
        .map(|v| v.split(';').next().unwrap_or("").to_owned())
}

fn location(response: &Response) -> Url {
    let value = response
        .headers()
        .get(LOCATION)
        .expect("Location header")
        .to_str()
        .unwrap();
    Url::parse(value).unwrap()
}

fn query(url: &Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}

struct Harness {
    http: Client,
    base: String,
    ops: String,
}

impl Harness {
    fn authorize_url(&self, client_id: &str, scope: &str, extra: &[(&str, &str)]) -> String {
        let mut pairs = vec![
            ("response_type", "code"),
            ("client_id", client_id),
            ("redirect_uri", REDIRECT_URI),
            ("scope", scope),
            ("state", "xyz"),
        ];
        pairs.extend_from_slice(extra);
        format!("{}/authorize?{}", self.base, form(&pairs))
    }

    async fn authorize(&self, client_id: &str, scope: &str) -> Response {
        self.http
            .get(self.authorize_url(client_id, scope, &[]))
            .send()
            .await
            .unwrap()
    }

    async fn post_form(&self, path: &str, pairs: &[(&str, &str)]) -> Response {
        self.http
            .post(format!("{}{path}", self.base))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(form(pairs))
            .send()
            .await
            .unwrap()
    }

    /// `POST /token` with HTTP Basic credentials.
    async fn token(
        &self,
        client: (&str, &str),
        pairs: &[(&str, &str)],
        request_id: Option<&str>,
    ) -> (StatusCode, reqwest::header::HeaderMap, serde_json::Value) {
        let mut request = self
            .http
            .post(format!("{}/token", self.base))
            .basic_auth(client.0, Some(client.1))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(form(pairs));
        if let Some(id) = request_id {
            request = request.header("x-request-id", id);
        }
        let response = request.send().await.unwrap();
        let (status, headers) = (response.status(), response.headers().clone());
        let body = response.text().await.unwrap();
        (status, headers, serde_json::from_str(&body).unwrap())
    }

    async fn exchange_code(&self, client: (&str, &str), code: &str) -> serde_json::Value {
        let (status, headers, body) = self
            .token(
                client,
                &[
                    ("grant_type", "authorization_code"),
                    ("code", code),
                    ("redirect_uri", REDIRECT_URI),
                ],
                None,
            )
            .await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(headers[CACHE_CONTROL], "no-store");
        assert_eq!(headers[PRAGMA], "no-cache");
        body
    }

    async fn refresh(
        &self,
        client: (&str, &str),
        refresh_token: &str,
    ) -> (StatusCode, serde_json::Value) {
        let (status, _, body) = self
            .token(
                client,
                &[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", refresh_token),
                ],
                None,
            )
            .await;
        (status, body)
    }
}

fn text(value: &serde_json::Value, key: &str) -> String {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("no {key} in {value}"))
        .to_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_full_scenario_and_no_secrets_in_logs() {
    let db = common::start_db().await;
    let (listen, ops) = (common::free_addr(), common::free_addr());
    let config_path = common::write_config(&db.url, listen, ops);

    // F-11: the CLI prints the credentials once.
    let (web_id, web_secret) = create_client(
        &config_path,
        &[
            "--name",
            "web",
            "--redirect-uri",
            REDIRECT_URI,
            "--grant-type",
            "authorization_code",
            "--grant-type",
            "refresh_token",
            "--scope",
            "read write",
        ],
    );
    let (quiet_id, quiet_secret) = create_client(
        &config_path,
        &[
            "--name",
            "quiet",
            "--redirect-uri",
            REDIRECT_URI,
            "--scope",
            "read",
            "--skip-consent",
        ],
    );
    let (svc_id, svc_secret) = create_client(
        &config_path,
        &[
            "--name",
            "service",
            "--grant-type",
            "client_credentials",
            "--scope",
            "read",
        ],
    );
    let output = common::run(&config_path, &["user", "create", "alice"], Some(PASSWORD));
    assert_eq!(output.status.code(), Some(0), "{output:?}");

    let mut server = Server::start(&config_path);
    let h = Harness {
        http: Client::builder()
            .cookie_store(true)
            .redirect(Policy::none())
            .build()
            .unwrap(),
        base: format!("http://{listen}"),
        ops: format!("http://{ops}"),
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(response) = h.http.get(format!("{}/readyz", h.ops)).send().await
            && response.status() == 200
        {
            break;
        }
        server.assert_running();
        assert!(Instant::now() < deadline, "server did not start");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Library access for F-4 / F-10 (verify_access_token) on the same database.
    let mut cfg = config::load(Some(&config_path)).unwrap();
    config::validate(&mut cfg).unwrap();
    let settings = wiring::Settings::from_config(cfg).unwrap();
    let services = wiring::services(
        PgUnitOfWorkFactory::new(db.pool.clone()),
        settings.application,
        settings.http,
    )
    .unwrap();
    let verify = |token: String| {
        let token_service = services.app_state.token.clone();
        async move { token_service.verify_access_token(&token).await.unwrap() }
    };

    let web = (web_id.as_str(), web_secret.as_str());
    let mut secrets: Vec<(&str, String)> = vec![
        ("password", PASSWORD.into()),
        ("wrong password", WRONG_PASSWORD.into()),
        ("wrong client secret", WRONG_SECRET.into()),
        ("web client secret", web_secret.clone()),
        ("quiet client secret", quiet_secret.clone()),
        ("service client secret", svc_secret.clone()),
    ];
    // The `Authorization: Basic` payload of every client must not reach the log either.
    for (label, id, secret) in [
        ("web basic credentials", &web_id, &web_secret),
        ("quiet basic credentials", &quiet_id, &quiet_secret),
        ("service basic credentials", &svc_id, &svc_secret),
    ] {
        secrets.push((label, base64_encode(format!("{id}:{secret}").as_bytes())));
    }

    // F-2: errors that must not redirect, and an error that redirects with the state.
    let response = h.authorize("no-such-client", "read").await;
    assert_eq!(response.status(), 400);
    assert!(response.headers().get(LOCATION).is_none());
    let bad_redirect = format!(
        "{}/authorize?{}",
        h.base,
        form(&[
            ("response_type", "code"),
            ("client_id", &web_id),
            ("redirect_uri", "https://evil.example/cb"),
        ])
    );
    let response = h.http.get(bad_redirect).send().await.unwrap();
    assert_eq!(response.status(), 400);
    assert!(response.headers().get(LOCATION).is_none());
    let response = h.authorize(&web_id, "unknown").await;
    assert_eq!(response.status(), 302);
    let to = location(&response);
    assert_eq!(to.as_str().split('?').next(), Some(REDIRECT_URI));
    assert_eq!(query(&to, "error").as_deref(), Some("invalid_scope"));
    assert_eq!(query(&to, "state").as_deref(), Some("xyz"));

    // F-1: authorize -> login (wrong password first) -> consent -> code.
    let response = h.authorize(&web_id, "read write").await;
    assert_eq!(response.status(), 302);
    let csrf = set_cookie(&response, "komainu_csrf").expect("csrf cookie");
    secrets.push(("csrf token", csrf));
    let login_url = location(&response);
    assert_eq!(login_url.path(), "/login");
    let request_id = query(&login_url, "request_id").unwrap();
    let page = h.http.get(login_url).send().await.unwrap();
    assert_eq!(page.status(), 200);
    assert_eq!(page.headers()["x-frame-options"], "DENY");
    let page = page.text().await.unwrap();
    let csrf_token = hidden(&page, "csrf_token");
    assert_eq!(hidden(&page, "request_id"), request_id);

    // F-12 (login.failed): a failed login re-renders the form.
    let response = h
        .post_form(
            "/login",
            &[
                ("request_id", &request_id),
                ("csrf_token", &csrf_token),
                ("username", "alice"),
                ("password", WRONG_PASSWORD),
            ],
        )
        .await;
    assert_eq!(response.status(), 200);
    assert!(
        response
            .text()
            .await
            .unwrap()
            .contains("Invalid username or password.")
    );
    let response = h
        .post_form(
            "/login",
            &[
                ("request_id", &request_id),
                ("csrf_token", &csrf_token),
                ("username", "alice"),
                ("password", PASSWORD),
            ],
        )
        .await;
    assert_eq!(response.status(), 302);
    let session = set_cookie(&response, "komainu_session").expect("session cookie");
    assert!(!session.is_empty());
    secrets.push(("session cookie", session));
    let resume = location(&response);
    assert_eq!(resume.path(), "/authorize/resume");
    let response = h.http.get(resume).send().await.unwrap();
    assert_eq!(response.status(), 200);
    let page = response.text().await.unwrap();
    assert!(page.contains("Allow"));
    let response = h
        .post_form(
            "/authorize/decision",
            &[
                ("request_id", &hidden(&page, "request_id")),
                ("csrf_token", &hidden(&page, "csrf_token")),
                ("decision", "approve"),
            ],
        )
        .await;
    assert_eq!(response.status(), 302);
    let to = location(&response);
    assert_eq!(to.as_str().split('?').next(), Some(REDIRECT_URI));
    assert_eq!(query(&to, "state").as_deref(), Some("xyz"));
    let code1 = query(&to, "code").unwrap();
    assert_eq!(code1.len(), 43);
    secrets.push(("code 1", code1.clone()));

    // F-3: the code becomes an access token and a refresh token.
    let tokens1 = h.exchange_code(web, &code1).await;
    assert_eq!(tokens1["token_type"], "Bearer");
    assert_eq!(tokens1["expires_in"], 3600);
    assert_eq!(tokens1["scope"], "read write");
    let (access1, refresh1) = (
        text(&tokens1, "access_token"),
        text(&tokens1, "refresh_token"),
    );
    secrets.push(("access token 1", access1.clone()));
    secrets.push(("refresh token 1", refresh1.clone()));
    let info = verify(access1.clone()).await.expect("valid access token");
    assert_eq!(info.scope.to_string(), "read write");
    // F-10: an unknown token is `None`.
    assert!(verify("e2e-unknown-access-token".into()).await.is_none());

    // F-4: the second use of the code fails and revokes what the first one issued.
    let (status, _, body) = h
        .token(
            web,
            &[
                ("grant_type", "authorization_code"),
                ("code", &code1),
                ("redirect_uri", REDIRECT_URI),
            ],
            None,
        )
        .await;
    assert_eq!(status, 400);
    assert_eq!(body["error"], "invalid_grant");
    assert!(verify(access1).await.is_none());
    let (status, body) = h.refresh(web, &refresh1).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant"))
    );

    // F-9: the consent is remembered, so the same scope goes straight to a code.
    let response = h.authorize(&web_id, "read write").await;
    assert_eq!(response.status(), 302);
    let code2 = query(&location(&response), "code").expect("code without consent screen");
    secrets.push(("code 2", code2.clone()));
    let tokens2 = h.exchange_code(web, &code2).await;
    let (access2, refresh2) = (
        text(&tokens2, "access_token"),
        text(&tokens2, "refresh_token"),
    );
    secrets.push(("access token 2", access2.clone()));
    secrets.push(("refresh token 2", refresh2.clone()));

    // F-6: refresh rotates the token.
    let (status, tokens3) = h.refresh(web, &refresh2).await;
    assert_eq!(status, 200, "{tokens3}");
    let (access3, refresh3) = (
        text(&tokens3, "access_token"),
        text(&tokens3, "refresh_token"),
    );
    secrets.push(("access token 3", access3.clone()));
    secrets.push(("refresh token 3", refresh3.clone()));
    assert_ne!(refresh3, refresh2);
    assert!(verify(access3.clone()).await.is_some());

    // F-7: replaying the rotated token fails and kills the whole series.
    let (status, body) = h.refresh(web, &refresh2).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant"))
    );
    let (status, body) = h.refresh(web, &refresh3).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant"))
    );
    assert!(verify(access2).await.is_none());
    assert!(verify(access3).await.is_none());

    // F-9: a `skip_consent` client never shows the consent screen.
    let response = h.authorize(&quiet_id, "read").await;
    assert_eq!(response.status(), 302);
    let code = query(&location(&response), "code").expect("code for skip_consent client");
    secrets.push(("code quiet", code));

    // Logout ends the session: the next authorization asks for a login again.
    let response = h
        .http
        .post(format!("{}/logout", h.base))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(response.text().await.unwrap().contains("Signed out."));
    let response = h.authorize(&web_id, "read write").await;
    assert_eq!(response.status(), 302);
    assert_eq!(location(&response).path(), "/login");

    // F-5: client credentials; no refresh token. N-8: the request id is echoed and audited.
    let (status, headers, body) = h
        .token(
            (&svc_id, &svc_secret),
            &[("grant_type", "client_credentials"), ("scope", "read")],
            Some("e2e-request-1"),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(headers["x-request-id"], "e2e-request-1");
    assert!(body.get("refresh_token").is_none());
    assert_eq!(body["scope"], "read");
    let service_token = text(&body, "access_token");
    secrets.push(("service access token", service_token.clone()));
    assert!(verify(service_token.clone()).await.is_some());

    // F-8: bad Basic credentials, and Basic together with a body secret.
    let (status, headers, body) = h
        .token(
            (&svc_id, WRONG_SECRET),
            &[("grant_type", "client_credentials")],
            None,
        )
        .await;
    assert_eq!(status, 401);
    assert_eq!(headers[WWW_AUTHENTICATE], "Basic realm=\"komainu\"");
    assert_eq!(body["error"], "invalid_client");
    let (status, _, body) = h
        .token(
            (&svc_id, &svc_secret),
            &[
                ("grant_type", "client_credentials"),
                ("client_secret", &svc_secret),
            ],
            None,
        )
        .await;
    assert_eq!(status, 400);
    assert_eq!(body["error"], "invalid_request");

    // F-11: disabling the client invalidates its tokens.
    let output = common::run(&config_path, &["client", "disable", &svc_id], None);
    assert_eq!(output.status.code(), Some(0));
    assert!(verify(service_token).await.is_none());

    // F-12: one audit row per event kind, and no secret inside any row (N-3).
    let rows: Vec<(String, i64)> =
        sqlx::query_as("SELECT kind, count(*) FROM audit_events GROUP BY kind")
            .fetch_all(&db.pool)
            .await
            .unwrap();
    let audit: BTreeMap<String, i64> = rows.into_iter().collect();
    for kind in [
        "client.registered",
        "client.disabled",
        "user.created",
        "login.failed",
        "login.succeeded",
        "logout",
        "consent.granted",
        "authorization_code.issued",
        "authorization_code.replay_detected",
        "refresh_token.replay_detected",
        "token.issued",
        "client_authentication.failed",
    ] {
        assert!(
            audit.get(kind).copied().unwrap_or(0) >= 1,
            "{kind}: {audit:?}"
        );
    }
    // Counts follow from the scenario above.
    for (kind, count) in [
        ("client.registered", 3),
        ("client.disabled", 1),
        ("user.created", 1),
        ("login.failed", 1),
        ("login.succeeded", 1),
        ("logout", 1),
        ("consent.granted", 1),
        // code 1, code 2 (remembered consent) and the skip_consent client's code.
        ("authorization_code.issued", 3),
        ("authorization_code.replay_detected", 1),
        ("refresh_token.replay_detected", 1),
        // Both replays revoke their grant, and disabling the service client revokes its grant.
        ("grant.revoked", 3),
        ("client_authentication.failed", 1),
        // Two code exchanges, one refresh and the client credentials call.
        ("token.issued", 4),
    ] {
        assert_eq!(audit.get(kind).copied(), Some(count), "{kind}: {audit:?}");
    }
    let (request_id,): (String,) = sqlx::query_as(
        "SELECT request_id FROM audit_events WHERE kind = 'token.issued' AND client_id = $1",
    )
    .bind(&svc_id)
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(request_id, "e2e-request-1");
    let (audit_text,): (String,) =
        sqlx::query_as("SELECT coalesce(string_agg(t::text, E'\\n'), '') FROM audit_events t")
            .fetch_one(&db.pool)
            .await
            .unwrap();

    // N-3: stop the server, then search its whole log for every secret value.
    let logs = server.stop();
    assert!(logs.contains("komainu started"), "no startup line");
    assert!(logs.contains("\"path\":\"/token\""), "no request log lines");
    assert!(logs.contains("http_request"), "no request span");
    assert!(
        logs.contains("\"level\":\"DEBUG\""),
        "the debug filter produced no DEBUG line"
    );
    for (label, value) in &secrets {
        assert!(value.len() >= 8, "{label} is too short to be meaningful");
        assert_eq!(
            logs.matches(value.as_str()).count(),
            0,
            "{label} leaked into the log"
        );
        assert_eq!(
            audit_text.matches(value.as_str()).count(),
            0,
            "{label} leaked into audit_events"
        );
    }
}
