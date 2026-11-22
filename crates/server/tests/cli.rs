#![cfg(feature = "pg-tests")]
//! Acceptance tests of the admin CLI (server.md, CLI).

mod common;

use komainu_adapter_postgres::PgUnitOfWorkFactory;
use komainu_application::{ClientAuthentication, TokenRequest};
use komainu_domain::Secret;
use komainu_server::{config, wiring};
use std::path::PathBuf;

struct Env {
    db: common::TestDb,
    config: PathBuf,
}

async fn env() -> Env {
    let db = common::start_db().await;
    let config = common::write_config(&db.url, common::free_addr(), common::free_addr());
    Env { db, config }
}

impl Env {
    fn run(&self, args: &[&str]) -> std::process::Output {
        common::run(&self.config, args, None)
    }

    async fn audit(&self, kind: &str) -> (i64, Option<String>) {
        let (count,): (i64,) = sqlx::query_as("SELECT count(*) FROM audit_events WHERE kind = $1")
            .bind(kind)
            .fetch_one(&self.db.pool)
            .await
            .unwrap();
        let actor: Option<(String,)> =
            sqlx::query_as("SELECT actor FROM audit_events WHERE kind = $1 LIMIT 1")
                .bind(kind)
                .fetch_optional(&self.db.pool)
                .await
                .unwrap();
        (count, actor.map(|a| a.0))
    }

    fn services(&self) -> wiring::Services {
        let mut cfg = config::load(Some(&self.config)).unwrap();
        config::validate(&mut cfg).unwrap();
        let settings = wiring::Settings::from_config(cfg).unwrap();
        wiring::services(
            PgUnitOfWorkFactory::new(self.db.pool.clone()),
            settings.application,
            settings.http,
        )
        .unwrap()
    }
}

fn field<'a>(out: &'a str, name: &str) -> &'a str {
    out.lines()
        .find_map(|l| l.strip_prefix(&format!("{name}: ")))
        .unwrap_or_else(|| panic!("no {name} in {out}"))
}

const CREATE: [&str; 7] = [
    "client",
    "create",
    "--name",
    "demo",
    "--grant-type",
    "client_credentials",
    "--scope",
];

fn create_args(scope: &str) -> Vec<&str> {
    let mut args = CREATE.to_vec();
    args.push(scope);
    args
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_client_create_prints_credentials_that_work_and_audits() {
    let env = env().await;
    let output = env.run(&create_args("read"));
    assert_eq!(output.status.code(), Some(0));
    let out = common::stdout(&output);
    let id = field(&out, "client_id").to_owned();
    let secret = field(&out, "client_secret").to_owned();
    // Exactly the two lines `client_id:` and `client_secret:`.
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 2, "{out}");
    assert!(lines[0].starts_with("client_id: "), "{out}");
    assert!(lines[1].starts_with("client_secret: "), "{out}");
    let token = env
        .services()
        .app_state
        .token
        .exchange(
            &wiring::background_context(),
            ClientAuthentication::Basic {
                client_id: id,
                secret: Secret::new(secret),
            },
            TokenRequest {
                grant_type: Some("client_credentials".into()),
                scope: Some("read".into()),
                ..TokenRequest::default()
            },
        )
        .await;
    assert!(token.is_ok());
    assert_eq!(
        env.audit("client.registered").await,
        (1, Some("admin".into()))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_client_show_hides_secret_and_unknown_id_exits_3() {
    let env = env().await;
    let out = common::stdout(&env.run(&create_args("read")));
    let id = field(&out, "client_id").to_owned();
    let secret = field(&out, "client_secret").to_owned();
    let shown = env.run(&["client", "show", &id]);
    assert_eq!(shown.status.code(), Some(0));
    // `auth_method` legitimately prints `client_secret_basic`; the secret itself has its own key.
    let text = common::stdout(&shown);
    assert!(!text.contains("client_secret:"), "{text}");
    let json = common::stdout(&env.run(&["client", "show", &id, "--output", "json"]));
    assert!(!json.contains("\"client_secret\""), "{json}");
    assert!(!text.contains(&secret) && !json.contains(&secret));
    let missing = env.run(&["client", "show", "00000000-0000-0000-0000-000000000000"]);
    assert_eq!(missing.status.code(), Some(3));
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_invalid_redirect_uri_and_unknown_scope_exit_2() {
    let env = env().await;
    let output = env.run(&[
        "client",
        "create",
        "--name",
        "x",
        "--redirect-uri",
        "https://app.example/cb#frag",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(env.run(&create_args("admin")).status.code(), Some(2));
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_user_create_twice_exits_4_and_audits() {
    let env = env().await;
    let create = || {
        common::run(
            &env.config,
            &["user", "create", "alice"],
            Some("password123"),
        )
    };
    assert_eq!(create().status.code(), Some(0));
    assert_eq!(create().status.code(), Some(4));
    assert_eq!(env.audit("user.created").await, (1, Some("admin".into())));
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_client_disable_invalidates_issued_access_tokens() {
    let env = env().await;
    let out = common::stdout(&env.run(&create_args("read")));
    let id = field(&out, "client_id").to_owned();
    let secret = field(&out, "client_secret").to_owned();
    let services = env.services();
    let token = services
        .app_state
        .token
        .exchange(
            &wiring::background_context(),
            ClientAuthentication::Basic {
                client_id: id.clone(),
                secret: Secret::new(secret),
            },
            TokenRequest {
                grant_type: Some("client_credentials".into()),
                scope: Some("read".into()),
                ..TokenRequest::default()
            },
        )
        .await
        .expect("exchange");
    let access = token.access_token.expose().to_owned();
    assert!(
        services
            .app_state
            .token
            .verify_access_token(&access)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(env.run(&["client", "disable", &id]).status.code(), Some(0));
    assert!(
        services
            .app_state
            .token
            .verify_access_token(&access)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        env.audit("client.disabled").await,
        (1, Some("admin".into()))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_each_admin_command_adds_one_audit_row() {
    let env = env().await;
    let out = common::stdout(&env.run(&create_args("read")));
    let id = field(&out, "client_id").to_owned();
    let cases: [(&[&str], &str); 4] = [
        (
            &["client", "update", &id, "--name", "renamed"],
            "client.updated",
        ),
        (&["client", "rotate-secret", &id], "client.secret_rotated"),
        (&["client", "disable", &id], "client.disabled"),
        (&["client", "enable", &id], "client.enabled"),
    ];
    for (args, kind) in cases {
        assert_eq!(env.run(args).status.code(), Some(0), "{args:?}");
        assert_eq!(env.audit(kind).await, (1, Some("admin".into())), "{kind}");
    }
    let user = |args: &[&str]| common::run(&env.config, args, Some("password123"));
    assert_eq!(user(&["user", "create", "bob"]).status.code(), Some(0));
    let cases: [(&[&str], &str); 4] = [
        (&["user", "set-password", "bob"], "user.password_changed"),
        (&["user", "disable", "bob"], "user.disabled"),
        (&["user", "enable", "bob"], "user.enabled"),
        (&["user", "create", "carol"], "user.created"),
    ];
    for (args, kind) in cases {
        assert_eq!(user(args).status.code(), Some(0), "{args:?}");
        let expected = if kind == "user.created" { 2 } else { 1 };
        let (count, actor) = env.audit(kind).await;
        assert_eq!(
            (count, actor.as_deref()),
            (expected, Some("admin")),
            "{kind}"
        );
    }
}
