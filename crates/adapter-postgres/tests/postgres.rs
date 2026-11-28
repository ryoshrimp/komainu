#![cfg(feature = "pg-tests")]

mod common;

use std::borrow::Cow;
use std::collections::BTreeMap;

use common::*;
use komainu_adapter_postgres::{PgStoreConfig, PgUnitOfWorkFactory, connect, migrate};
use komainu_application::*;
use komainu_application::{
    ApplicationConfig, BuiltinAuthenticator, ClientAuthentication, Dependencies, RequestContext,
    TokenError, TokenRequest, TokenService,
};
use komainu_domain::*;
use sqlx::migrate::{Migration, MigrationType, Migrator};
use sqlx::{Row, SqlSafeStr};

async fn commit_with<F>(db: &TestDb, f: F)
where
    F: for<'a> FnOnce(&'a mut dyn UnitOfWork) -> BoxFuture<'a, ()>,
{
    let mut uow = db.factory.begin().await.unwrap();
    f(&mut *uow).await;
    uow.commit().await.unwrap();
}

#[tokio::test]
async fn migrate_twice_succeeds() {
    let db = start_raw().await;
    migrate(&db.pool).await.unwrap();
    migrate(&db.pool).await.unwrap();
    let config = PgStoreConfig::new(Secret::new(db.url.clone()));
    let pool = connect(&config).await.unwrap();
    migrate(&pool).await.unwrap();
    PgUnitOfWorkFactory::new(pool).ping().await.unwrap();
}

#[tokio::test]
async fn migrate_upgrades_from_0001() {
    let db = start_raw().await;
    let init = Migration::new(
        1,
        Cow::Borrowed("init"),
        MigrationType::Simple,
        include_str!("../migrations/0001_init.sql").into_sql_str(),
        false,
    );
    Migrator::with_migrations(vec![init])
        .run(&db.pool)
        .await
        .unwrap();
    migrate(&db.pool).await.unwrap();
    migrate(&db.pool).await.unwrap();
    seed_client(&db, "c1").await;
    commit_with(&db, |uow| {
        Box::pin(async move {
            let mut grant = Grant::from_record(grant_record(1, "c1"));
            uow.grants().insert(&grant).await.unwrap();
            grant.revoke(RevocationReason::ClientRequest, t(5));
            uow.grants().update(&grant).await.unwrap();
        })
    })
    .await;
}

#[tokio::test]
async fn migrate_0003_drops_pending_codes_and_requests() {
    let db = start_raw().await;
    let migration = |version, name: &'static str, sql: &'static str| {
        Migration::new(
            version,
            Cow::Borrowed(name),
            MigrationType::Simple,
            sql.into_sql_str(),
            false,
        )
    };
    Migrator::with_migrations(vec![
        migration(1, "init", include_str!("../migrations/0001_init.sql")),
        migration(
            2,
            "client_request_revocation",
            include_str!("../migrations/0002_client_request_revocation.sql"),
        ),
    ])
    .run(&db.pool)
    .await
    .unwrap();
    for sql in [
        "INSERT INTO clients (id, name, client_type, auth_method, redirect_uris, grant_types, \
         allowed_scopes, default_scopes, skip_consent, status, created_at, updated_at) \
         VALUES ('c1', 'n', 'public', 'none', '{}', '{}', '{}', '{}', false, 'active', now(), now())",
        "INSERT INTO grants (id, client_id, scope, origin, origin_code_hash, status, created_at) \
         VALUES ('00000000-0000-0000-0000-000000000001', 'c1', '{}', 'authorization_code', \
         decode(repeat('01', 32), 'hex'), 'active', now())",
        "INSERT INTO authorization_requests (id, client_id, redirect_uri, redirect_uri_provided, \
         scope, csrf_token_hash, status, created_at, updated_at, expires_at) \
         VALUES ('00000000-0000-0000-0000-000000000002', 'c1', 'https://a.example/cb', true, '{}', \
         decode(repeat('02', 32), 'hex'), 'pending', now(), now(), now())",
        "INSERT INTO authorization_codes (id, client_id, subject, redirect_uri, \
         redirect_uri_provided, scope, status, grant_id, redeemed_at, issued_at, expires_at) \
         VALUES (decode(repeat('03', 32), 'hex'), 'c1', 'alice', 'https://a.example/cb', true, \
         '{}', 'redeemed', '00000000-0000-0000-0000-000000000001', now(), now(), now())",
    ] {
        sqlx::query(sql).execute(&db.pool).await.unwrap();
    }
    migrate(&db.pool).await.unwrap();
    for (table, sql, expected) in [
        (
            "authorization_requests",
            "SELECT count(*) AS n FROM authorization_requests",
            0,
        ),
        (
            "authorization_codes",
            "SELECT count(*) AS n FROM authorization_codes",
            0,
        ),
        ("clients", "SELECT count(*) AS n FROM clients", 1),
        ("grants", "SELECT count(*) AS n FROM grants", 1),
    ] {
        let count: i64 = sqlx::query(sql).fetch_one(&db.pool).await.unwrap().get("n");
        assert_eq!(count, expected, "{table}");
    }
}

#[tokio::test]
async fn audit_append_is_stored() {
    let db = start().await;
    let event = AuditEvent {
        id: uuid::Uuid::from_u128(1),
        occurred_at: t(0),
        kind: AuditKind::ClientRegistered,
        outcome: AuditOutcome::Success,
        actor: AuditActor::Admin,
        request_id: "req-1".to_owned(),
        client_ip: Some("192.0.2.1".parse().unwrap()),
        client_id: None,
        subject: None,
        details: BTreeMap::from([("k", "v".to_owned())]),
    };
    let kind = event.kind.as_str();
    commit_with(&db, |uow| {
        Box::pin(async move {
            uow.audit_log().append(&event).await.unwrap();
        })
    })
    .await;
    let count: i64 = sqlx::query("SELECT count(*) AS n FROM audit_events WHERE kind = $1")
        .bind(kind)
        .fetch_one(&db.pool)
        .await
        .unwrap()
        .get("n");
    assert_eq!(count, 1);
}

#[tokio::test]
async fn corrupted_enum_value_is_other() {
    let db = start().await;
    seed_client(&db, "c1").await;
    // Bypass the CHECK constraint to simulate a corrupted row.
    sqlx::query("ALTER TABLE clients DROP CONSTRAINT clients_status_check")
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE clients SET status = 'bogus'")
        .execute(&db.pool)
        .await
        .unwrap();
    let mut uow = db.factory.begin().await.unwrap();
    assert!(matches!(
        uow.clients().find(&cid("c1")).await,
        Err(StoreError::Other(m)) if m.contains("clients.status")
    ));
}

fn service(db: &TestDb) -> komainu_application::TokenService {
    use std::sync::Arc;
    let hasher = Arc::new(komainu_testkit::PlainPasswordHasher);
    let clock: Arc<dyn komainu_application::Clock> = Arc::new(komainu_adapter_std::SystemClock);
    let deps = Dependencies {
        store: Arc::new(db.factory.clone()),
        clock: clock.clone(),
        jwks: Arc::new(komainu_application::JwksResolver::new(None, clock)),
        subject_resolver: Arc::new(komainu_application::MappingTableSubjectResolver),
        signing_keys: None,
        random: Arc::new(komainu_adapter_std::OsSecureRandom),
        password_hasher: hasher.clone(),
        authenticator: Arc::new(BuiltinAuthenticator::new(hasher)),
        config: Arc::new(ApplicationConfig::default()),
    };
    TokenService::new(deps)
}

fn pkce() -> PkceChallenge {
    PkceChallenge::new(
        CodeChallenge::try_new("ZtNPunH49FD35FWYhT5Tv8I7vRKQJ8uxMaL0_9eHjNA".to_owned()).unwrap(),
        CodeChallengeMethod::S256,
    )
}

fn opaque(s: &str) -> OpaqueToken {
    OpaqueToken::try_new(Secret::new(s.to_owned())).unwrap()
}

async fn seed_code_and_client(db: &TestDb) {
    let mut client = client_record("c1");
    client.secret_hash = Some(opaque("client-secret").hash());
    let now = time::OffsetDateTime::now_utc();
    let code = AuthorizationCodeRecord {
        id: opaque("the-code").hash(),
        client_id: cid("c1"),
        subject: subject("alice"),
        redirect_uri: uri("https://a.example/cb"),
        redirect_uri_provided: true,
        scope: scope("read"),
        pkce: pkce(),
        status: AuthorizationCodeStatus::Issued,
        issued_at: now,
        expires_at: now + time::Duration::minutes(10),
    };
    commit_with(db, |uow| {
        Box::pin(async move {
            uow.clients()
                .insert(&Client::from_record(client))
                .await
                .unwrap();
            uow.authorization_codes()
                .insert(&AuthorizationCode::from_record(code))
                .await
                .unwrap();
        })
    })
    .await;
}

fn ctx() -> RequestContext {
    RequestContext {
        request_id: "r".to_owned(),
        client_ip: None,
    }
}

fn basic() -> ClientAuthentication {
    ClientAuthentication::Basic {
        client_id: "c1".to_owned(),
        secret: Secret::new("client-secret".to_owned()),
    }
}

/// Real `TokenService` on PostgreSQL: ten concurrent exchanges of one code yield exactly one
/// token response, the rest get `invalid_grant`, and the token tables hold one grant.
#[tokio::test]
async fn concurrent_code_exchange_issues_tokens_once() {
    let db = start().await;
    seed_code_and_client(&db).await;
    let svc = service(&db);
    let mut tasks = Vec::new();
    for _ in 0..10 {
        let svc = svc.clone();
        tasks.push(tokio::spawn(async move {
            svc.exchange(
                &ctx(),
                basic(),
                TokenRequest {
                    grant_type: Some("authorization_code".to_owned()),
                    code: Some("the-code".to_owned()),
                    redirect_uri: Some("https://a.example/cb".to_owned()),
                    code_verifier: Some("a".repeat(43)),
                    ..TokenRequest::default()
                },
            )
            .await
        }));
    }
    let (mut ok, mut invalid) = (0, 0);
    for task in tasks {
        match task.await.unwrap() {
            Ok(_) => ok += 1,
            Err(TokenError::InvalidGrant) => invalid += 1,
            Err(other) => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!((ok, invalid), (1, 9));
    let grants: i64 = sqlx::query("SELECT count(*) AS n FROM grants")
        .fetch_one(&db.pool)
        .await
        .unwrap()
        .get("n");
    assert_eq!(grants, 1);
    let row = sqlx::query("SELECT status, revocation_reason FROM grants")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(row.get::<String, _>("status"), "revoked");
    assert_eq!(row.get::<String, _>("revocation_reason"), "code_replay");
}

/// Counts rows of `table` whose `column` equals the SHA-256 `hash`.
async fn count_hash(db: &TestDb, table: &str, column: &str, hash: &TokenHash) -> i64 {
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT count(*) AS n FROM {table} WHERE {column} = $1"
    )))
    .bind(hash.as_bytes().to_vec())
    .fetch_one(&db.pool)
    .await
    .unwrap()
    .get("n")
}

/// Runs the whole flow (client registration, login, code, tokens) on PostgreSQL and checks that
/// tokens, codes, secrets and session ids are stored only as their SHA-256, that no plaintext
/// appears in any column, and that passwords are Argon2id PHC strings.
#[tokio::test]
async fn tokens_are_stored_hashed_only() {
    use std::sync::Arc;
    let db = start().await;
    let hasher = Arc::new(komainu_adapter_std::Argon2PasswordHasher::new().unwrap());
    let config = ApplicationConfig::default().with_scopes(vec![ScopeDefinition {
        name: ScopeToken::try_new("read".to_owned()).unwrap(),
        description: "read".to_owned(),
    }]);
    let clock: Arc<dyn komainu_application::Clock> = Arc::new(komainu_adapter_std::SystemClock);
    let deps = Dependencies {
        store: Arc::new(db.factory.clone()),
        clock: clock.clone(),
        jwks: Arc::new(komainu_application::JwksResolver::new(None, clock)),
        subject_resolver: Arc::new(komainu_application::MappingTableSubjectResolver),
        signing_keys: None,
        random: Arc::new(komainu_adapter_std::OsSecureRandom),
        password_hasher: hasher.clone(),
        authenticator: Arc::new(BuiltinAuthenticator::new(hasher)),
        config: Arc::new(config),
    };
    let admin = AdminService::new(deps.clone());
    let registered = admin
        .register_client(
            &ctx(),
            RegisterClient {
                name: ClientName::try_new("App".to_owned()).unwrap(),
                client_type: ClientType::Confidential,
                auth_method: TokenEndpointAuthMethod::ClientSecretBasic,
                redirect_uris: vec![uri("https://a.example/cb")],
                grant_types: std::collections::BTreeSet::from([
                    GrantType::AuthorizationCode,
                    GrantType::RefreshToken,
                ]),
                allowed_scopes: scope("read"),
                default_scopes: scope("read"),
                skip_consent: true,
                keys: None,
            },
        )
        .await
        .unwrap();
    let client_id = registered.client.id.as_inner().to_owned();
    let client_secret = registered.secret.unwrap();
    admin
        .create_user(
            &ctx(),
            Username::try_new("bob".to_owned()).unwrap(),
            NewPassword::try_new(Secret::new("correct horse".to_owned())).unwrap(),
        )
        .await
        .unwrap();

    let authz = AuthorizationService::new(deps.clone());
    let started = authz
        .start(
            &ctx(),
            AuthorizeParams {
                response_type: Some("code".to_owned()),
                client_id: Some(client_id.clone()),
                redirect_uri: Some("https://a.example/cb".to_owned()),
                scope: Some("read".to_owned()),
                code_challenge: Some(pkce().challenge().as_inner().to_owned()),
                code_challenge_method: Some("S256".to_owned()),
                ..AuthorizeParams::default()
            },
            None,
        )
        .await
        .unwrap();
    let AuthorizeOutcome::LoginRequired { request_id } = started.outcome else {
        panic!("login expected");
    };
    let csrf = started.csrf_token.unwrap();
    let logged_in = authz
        .login(
            &ctx(),
            request_id,
            &csrf,
            LoginCredentials {
                username: "bob".to_owned(),
                password: Secret::new("correct horse".to_owned()),
            },
        )
        .await
        .unwrap();
    let session = logged_in.session_token;
    let location = match authz
        .resume(&ctx(), request_id, Some(&session))
        .await
        .unwrap()
    {
        AuthorizeOutcome::Redirect { location } => location,
        AuthorizeOutcome::ConsentRequired { .. } => authz
            .decide(&ctx(), request_id, &csrf, Some(&session), true)
            .await
            .unwrap(),
        other => panic!("unexpected {other:?}"),
    };
    let code = location
        .split(['?', '&'])
        .find_map(|p| p.strip_prefix("code="))
        .expect("code in redirect")
        .to_owned();

    let response = TokenService::new(deps)
        .exchange(
            &ctx(),
            ClientAuthentication::Basic {
                client_id: client_id.clone(),
                secret: Secret::new(client_secret.expose().to_owned()),
            },
            TokenRequest {
                grant_type: Some("authorization_code".to_owned()),
                code: Some(code.clone()),
                redirect_uri: Some("https://a.example/cb".to_owned()),
                code_verifier: Some("a".repeat(43)),
                ..TokenRequest::default()
            },
        )
        .await
        .unwrap();
    let access = response.access_token;
    let refresh = response.refresh_token.unwrap();

    // Every stored identifier is the SHA-256 of the plaintext.
    let code_hash = opaque(&code).hash();
    for (table, column, token) in [
        ("access_tokens", "id", &access.hash()),
        ("refresh_tokens", "id", &refresh.hash()),
        ("authorization_codes", "id", &code_hash),
        ("clients", "secret_hash", &client_secret.hash()),
        ("login_sessions", "id", &session.hash()),
        ("authorization_requests", "csrf_token_hash", &csrf.hash()),
    ] {
        assert_eq!(
            count_hash(&db, table, column, token).await,
            1,
            "{table}.{column}"
        );
    }

    // No plaintext in any text, bytea, array or json column of any table.
    let columns = sqlx::query(
        "SELECT table_name, column_name, udt_name FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name NOT LIKE '\\_%'",
    )
    .fetch_all(&db.pool)
    .await
    .unwrap();
    assert!(!columns.is_empty());
    let plains = [
        access.expose().to_owned(),
        refresh.expose().to_owned(),
        session.expose().to_owned(),
        client_secret.expose().to_owned(),
        csrf.expose().to_owned(),
        code,
        "correct horse".to_owned(),
    ];
    for row in &columns {
        let (table, column, udt): (String, String, String) = (
            row.get("table_name"),
            row.get("column_name"),
            row.get("udt_name"),
        );
        let predicate = if udt == "bytea" {
            format!("position(convert_to($1, 'UTF8') in \"{column}\") > 0")
        } else {
            format!("strpos(\"{column}\"::text, $1) > 0")
        };
        for plain in &plains {
            let n: i64 = sqlx::query(sqlx::AssertSqlSafe(format!(
                "SELECT count(*) AS n FROM \"{table}\" WHERE {predicate}"
            )))
            .bind(plain)
            .fetch_one(&db.pool)
            .await
            .unwrap()
            .get("n");
            assert_eq!(n, 0, "plaintext found in {table}.{column}");
        }
    }

    let phc: String = sqlx::query("SELECT password_hash FROM users")
        .fetch_one(&db.pool)
        .await
        .unwrap()
        .get("password_hash");
    assert!(phc.starts_with("$argon2id$"));
}

/// Ten concurrent refreshes with one refresh token: exactly one rotation succeeds, the rest get
/// `invalid_grant` and the replay revokes the grant.
#[tokio::test]
async fn concurrent_refresh_rotates_once() {
    let db = start().await;
    seed_code_and_client(&db).await;
    let svc = service(&db);
    let first = svc
        .exchange(
            &ctx(),
            basic(),
            TokenRequest {
                grant_type: Some("authorization_code".to_owned()),
                code: Some("the-code".to_owned()),
                redirect_uri: Some("https://a.example/cb".to_owned()),
                code_verifier: Some("a".repeat(43)),
                ..TokenRequest::default()
            },
        )
        .await
        .unwrap();
    let refresh = first.refresh_token.unwrap().expose().to_owned();
    let mut tasks = Vec::new();
    for _ in 0..10 {
        let (svc, refresh) = (svc.clone(), refresh.clone());
        tasks.push(tokio::spawn(async move {
            svc.exchange(
                &ctx(),
                basic(),
                TokenRequest {
                    grant_type: Some("refresh_token".to_owned()),
                    refresh_token: Some(refresh),
                    ..TokenRequest::default()
                },
            )
            .await
        }));
    }
    let (mut ok, mut invalid) = (0, 0);
    for task in tasks {
        match task.await.unwrap() {
            Ok(_) => ok += 1,
            Err(TokenError::InvalidGrant) => invalid += 1,
            Err(other) => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!((ok, invalid), (1, 9));
    // The replayed token revokes the grant; the original is rotated and one successor exists.
    let row = sqlx::query("SELECT status, revocation_reason FROM grants")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(row.get::<String, _>("status"), "revoked");
    assert_eq!(
        row.get::<String, _>("revocation_reason"),
        "refresh_token_replay"
    );
    let rows = sqlx::query("SELECT status FROM refresh_tokens ORDER BY status")
        .fetch_all(&db.pool)
        .await
        .unwrap();
    let statuses: Vec<String> = rows.iter().map(|r| r.get("status")).collect();
    assert_eq!(statuses, ["active", "rotated"]);
}

#[tokio::test]
async fn migrate_0004_keeps_existing_clients_and_checks_keys() {
    let db = start_raw().await;
    let migration = |version, name: &'static str, sql: &'static str| {
        Migration::new(
            version,
            Cow::Borrowed(name),
            MigrationType::Simple,
            sql.into_sql_str(),
            false,
        )
    };
    Migrator::with_migrations(vec![
        migration(1, "init", include_str!("../migrations/0001_init.sql")),
        migration(
            2,
            "client_request_revocation",
            include_str!("../migrations/0002_client_request_revocation.sql"),
        ),
        migration(3, "pkce", include_str!("../migrations/0003_pkce.sql")),
    ])
    .run(&db.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO clients (id, name, client_type, auth_method, redirect_uris, grant_types, \
         allowed_scopes, default_scopes, skip_consent, status, created_at, updated_at) \
         VALUES ('c1', 'n', 'public', 'client_secret_basic', '{}', '{}', '{}', '{}', false, \
         'active', now(), now())",
    )
    .execute(&db.pool)
    .await
    .unwrap();
    migrate(&db.pool).await.unwrap();
    let mut uow = db.factory.begin().await.unwrap();
    let client = uow.clients().find(&cid("c1")).await.unwrap().unwrap();
    assert_eq!(
        client.to_record().auth_method,
        TokenEndpointAuthMethod::ClientSecretBasic
    );
    assert!(client.to_record().keys.is_none());
    drop(uow);

    // private_key_jwt without keys violates clients_keys_check.
    let result = sqlx::query(
        "INSERT INTO clients (id, name, client_type, auth_method, redirect_uris, grant_types, \
         allowed_scopes, default_scopes, skip_consent, status, created_at, updated_at) \
         VALUES ('c2', 'n', 'confidential', 'private_key_jwt', '{}', '{}', '{}', '{}', false, \
         'active', now(), now())",
    )
    .execute(&db.pool)
    .await;
    let error = result.unwrap_err();
    let db_error = error.as_database_error().expect("database error");
    assert_eq!(db_error.code().as_deref(), Some("23514"));
    assert_eq!(db_error.constraint(), Some("clients_keys_check"));
}

#[tokio::test]
async fn concurrent_used_assertion_record_has_one_winner() {
    let db = start().await;
    let assertion = UsedAssertion {
        kind: AssertionKind::AuthorizationGrant,
        issuer: "https://idp.example.com".to_owned(),
        jti: "j1".to_owned(),
        expires_at: t(100),
    };
    let mut first = db.factory.begin().await.unwrap();
    let mut second = db.factory.begin().await.unwrap();
    assert_eq!(
        first.used_assertions().record(&assertion).await.unwrap(),
        RecordOutcome::Recorded
    );
    // The second insert waits for the first unit of work to finish.
    let racing = tokio::spawn(async move {
        let outcome = second.used_assertions().record(&assertion).await.unwrap();
        second.commit().await.unwrap();
        outcome
    });
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    first.commit().await.unwrap();
    assert_eq!(racing.await.unwrap(), RecordOutcome::Replayed);
}
