#![cfg(feature = "pg-tests")]
//! Acceptance tests of the admin CLI (server.md, CLI).

mod common;

use komainu::adapter_postgres::PgUnitOfWorkFactory;
use komainu::application::{ClientAuthentication, TokenRequest};
use komainu::domain::Secret;
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
        .komainu
        .token()
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
        .komainu
        .token()
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
            .komainu
            .token()
            .verify_access_token(&access)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(env.run(&["client", "disable", &id]).status.code(), Some(0));
    assert!(
        services
            .komainu
            .token()
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

const JWKS: &str = r#"{"keys":[{"kty":"EC","crv":"P-256","kid":"k1","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}]}"#;

#[tokio::test(flavor = "multi_thread")]
async fn cli_private_key_jwt_client_create_show_and_misuse() {
    let env = env().await;
    let dir = std::env::temp_dir().join(format!("komainu-cli-jwks-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("jwks.json");
    std::fs::write(&file, JWKS).unwrap();
    let path = file.to_str().unwrap();
    let mut args = create_args("read");
    args.extend(["--auth-method", "private_key_jwt"]);

    let with_file = [args.clone(), vec!["--jwks-file", path]].concat();
    let created = env.run(&with_file);
    assert_eq!(created.status.code(), Some(0));
    let out = common::stdout(&created);
    assert!(!out.contains("client_secret"), "{out}");
    let id = field(&out, "client_id").to_owned();
    let shown = common::stdout(&env.run(&["client", "show", &id]));
    assert_eq!(field(&shown, "auth_method"), "private_key_jwt");
    assert_eq!(field(&shown, "keys"), "jwks (1 keys)");
    let json = common::stdout(&env.run(&["client", "show", &id, "--output", "json"]));
    assert!(
        json.contains("\"type\": \"jwks\"") || json.contains("\"type\":\"jwks\""),
        "{json}"
    );

    let by_uri = [
        args.clone(),
        vec!["--jwks-uri", "https://client.example.com/jwks"],
    ]
    .concat();
    assert_eq!(env.run(&by_uri).status.code(), Some(0));

    // Neither, both, or keys with a secret method.
    assert_eq!(env.run(&args).status.code(), Some(2));
    let both = [
        args.clone(),
        vec![
            "--jwks-file",
            path,
            "--jwks-uri",
            "https://client.example.com/jwks",
        ],
    ]
    .concat();
    assert_eq!(env.run(&both).status.code(), Some(2));
    let secret_with_keys = [create_args("read"), vec!["--jwks-file", path]].concat();
    assert_eq!(env.run(&secret_with_keys).status.code(), Some(2));
    // Unreadable file, invalid JSON, no keys, a private key.
    let missing = [args.clone(), vec!["--jwks-file", "/nonexistent/jwks.json"]].concat();
    assert_eq!(env.run(&missing).status.code(), Some(2));
    for (name, text) in [
        ("bad.json", "not json".to_owned()),
        ("empty.json", r#"{"keys":[]}"#.to_owned()),
        (
            "private.json",
            JWKS.replace("\"kid\"", "\"d\":\"AQ\",\"kid\""),
        ),
    ] {
        let f = dir.join(name);
        std::fs::write(&f, text).unwrap();
        let bad = [args.clone(), vec!["--jwks-file", f.to_str().unwrap()]].concat();
        assert_eq!(env.run(&bad).status.code(), Some(2), "{name}");
    }
    // 11 keys.
    let keys: Vec<String> = (0..11)
        .map(|i| {
            JWKS.trim_start_matches(r#"{"keys":["#)
                .trim_end_matches("]}")
                .replace("k1", &format!("k{i}"))
        })
        .collect();
    let many = dir.join("many.json");
    std::fs::write(&many, format!(r#"{{"keys":[{}]}}"#, keys.join(","))).unwrap();
    let eleven = [args.clone(), vec!["--jwks-file", many.to_str().unwrap()]].concat();
    assert_eq!(env.run(&eleven).status.code(), Some(2));
    // A plain http jwks_uri.
    let http = [
        args.clone(),
        vec!["--jwks-uri", "http://client.example.com/jwks"],
    ]
    .concat();
    assert_eq!(env.run(&http).status.code(), Some(2));
    // rotate-secret does not apply.
    assert_eq!(
        env.run(&["client", "rotate-secret", &id]).status.code(),
        Some(2)
    );
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_issuer_lifecycle_and_exit_codes() {
    let env = env().await;
    let dir = std::env::temp_dir().join(format!("komainu-cli-issuer-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("jwks.json");
    std::fs::write(&file, JWKS).unwrap();
    let path = file.to_str().unwrap();
    let created = env.run(&[
        "client",
        "create",
        "--name",
        "demo",
        "--grant-type",
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "--scope",
        "read",
    ]);
    assert_eq!(created.status.code(), Some(0));
    let client = field(&common::stdout(&created), "client_id").to_owned();
    let idp = "https://idp.example.org";

    // create: ok, duplicate (4), unknown client (2), no client (2), bad JWKS (2).
    let create = |id: &str, client: &str| {
        env.run(&[
            "issuer",
            "create",
            "--issuer",
            id,
            "--jwks-file",
            path,
            "--client",
            client,
        ])
    };
    let out = create(idp, &client);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(create(idp, &client).status.code(), Some(4));
    let unknown = "00000000-0000-7000-8000-000000000000";
    assert_eq!(
        create("https://idp2.example.org", unknown).status.code(),
        Some(2)
    );
    let no_client = env.run(&[
        "issuer",
        "create",
        "--issuer",
        "https://idp3.example.org",
        "--jwks-file",
        path,
    ]);
    assert_eq!(no_client.status.code(), Some(2));
    let bad = dir.join("bad.json");
    std::fs::write(&bad, "not json").unwrap();
    let bad_jwks = env.run(&[
        "issuer",
        "create",
        "--issuer",
        "https://idp4.example.org",
        "--jwks-file",
        bad.to_str().unwrap(),
        "--client",
        &client,
    ]);
    assert_eq!(bad_jwks.status.code(), Some(2));
    assert_eq!(env.audit("issuer.registered").await.0, 1);
    // 101 allowed clients exceed the limit of 100.
    let mut many = vec![
        "issuer",
        "create",
        "--issuer",
        "https://idp5.example.org",
        "--jwks-file",
        path,
    ];
    let ids: Vec<String> = (0..101)
        .map(|i| format!("00000000-0000-7000-8000-{i:012}"))
        .collect();
    for id in &ids {
        many.extend(["--client", id]);
    }
    assert_eq!(env.run(&many).status.code(), Some(2));

    // show / list.
    let shown = common::stdout(&env.run(&["issuer", "show", idp]));
    assert_eq!(field(&shown, "status"), "active");
    assert_eq!(field(&shown, "clients"), client);
    assert_eq!(field(&shown, "keys"), "1");
    let json = common::stdout(&env.run(&["issuer", "show", idp, "--output", "json"]));
    assert!(json.contains("\"allowed_clients\""), "{json}");
    assert!(common::stdout(&env.run(&["issuer", "list"])).contains(idp));
    assert_eq!(
        env.run(&["issuer", "show", "https://none.example.org"])
            .status
            .code(),
        Some(3)
    );

    // update / disable / enable.
    let update = env.run(&["issuer", "update", idp, "--client", &client]);
    assert_eq!(update.status.code(), Some(0));
    assert_eq!(env.run(&["issuer", "update", idp]).status.code(), Some(2));
    assert_eq!(env.run(&["issuer", "disable", idp]).status.code(), Some(0));
    let shown = common::stdout(&env.run(&["issuer", "show", idp]));
    assert_eq!(field(&shown, "status"), "disabled");
    assert_eq!(env.run(&["issuer", "enable", idp]).status.code(), Some(0));

    // map-subject / list-subjects / unmap-subject.
    let map = |user: &str| {
        env.run(&[
            "issuer",
            "map-subject",
            idp,
            "--subject",
            "ext-1",
            "--username",
            user,
        ])
    };
    assert_eq!(map("alice").status.code(), Some(3));
    let user = common::run(
        &env.config,
        &["user", "create", "alice"],
        Some("password123"),
    );
    assert_eq!(user.status.code(), Some(0));
    assert_eq!(map("alice").status.code(), Some(0));
    assert_eq!(map("alice").status.code(), Some(0));
    let subjects = common::stdout(&env.run(&["issuer", "list-subjects", idp]));
    assert_eq!(subjects.lines().count(), 1, "{subjects}");
    assert!(subjects.contains("ext-1") && subjects.contains("alice"));
    let unmap = ["issuer", "unmap-subject", idp, "--subject", "ext-1"];
    assert_eq!(env.run(&unmap).status.code(), Some(0));
    assert_eq!(env.run(&unmap).status.code(), Some(3));
    assert_eq!(env.audit("issuer.subject_mapped").await.0, 2);
    std::fs::remove_dir_all(dir).ok();
}
