#![cfg(feature = "pg-tests")]

mod common;

use std::collections::BTreeMap;

use common::*;
use komainu_adapter_postgres::{PgStoreConfig, PgUnitOfWorkFactory, connect, migrate};
use komainu_application::*;
use komainu_application::{
    ApplicationConfig, BuiltinAuthenticator, ClientAuthentication, Dependencies, RequestContext,
    TokenError, TokenRequest, TokenService,
};
use komainu_domain::*;
use sqlx::Row;

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
async fn client_user_session_roundtrip() {
    let db = start().await;
    let client = client_record("c1");
    let user = user_record(1, "alice");
    let session = LoginSessionRecord {
        id: hash(5),
        subject: subject("alice"),
        created_at: t(0),
        expires_at: t(60),
    };
    {
        let (c, u, s) = (client.clone(), user.clone(), session.clone());
        commit_with(&db, |uow| {
            Box::pin(async move {
                uow.clients().insert(&Client::from_record(c)).await.unwrap();
                uow.users().insert(&User::from_record(u)).await.unwrap();
                uow.login_sessions()
                    .insert(&LoginSession::from_record(s))
                    .await
                    .unwrap();
            })
        })
        .await;
    }
    let mut uow = db.factory.begin().await.unwrap();
    assert_eq!(
        uow.clients()
            .find(&client.id)
            .await
            .unwrap()
            .unwrap()
            .to_record(),
        client
    );
    assert_eq!(
        uow.clients()
            .find_for_update(&client.id)
            .await
            .unwrap()
            .unwrap()
            .to_record(),
        client
    );
    assert!(uow.clients().find(&cid("none")).await.unwrap().is_none());
    assert_eq!(
        uow.users()
            .find(user.id)
            .await
            .unwrap()
            .unwrap()
            .to_record(),
        user
    );
    assert_eq!(
        uow.users()
            .find_by_username(&user.username)
            .await
            .unwrap()
            .unwrap()
            .to_record(),
        user
    );
    assert_eq!(
        uow.login_sessions()
            .find(&session.id)
            .await
            .unwrap()
            .unwrap()
            .to_record(),
        session
    );
    // update and list
    let mut changed = client.clone();
    changed.status = ClientStatus::Disabled;
    changed.updated_at = t(5);
    uow.clients()
        .update(&Client::from_record(changed.clone()))
        .await
        .unwrap();
    uow.clients()
        .insert(&Client::from_record(client_record("c2")))
        .await
        .unwrap();
    let page = ListPage {
        after: None,
        limit: 10,
    };
    let ids: Vec<_> = uow
        .clients()
        .list(&page)
        .await
        .unwrap()
        .iter()
        .map(|c| c.to_record().id)
        .collect();
    assert_eq!(ids, vec![cid("c1"), cid("c2")]);
    let after = ListPage {
        after: Some(cid("c1")),
        limit: 1,
    };
    assert_eq!(uow.clients().list(&after).await.unwrap().len(), 1);
    let missing = Client::from_record(client_record("zzz"));
    assert!(matches!(
        uow.clients().update(&missing).await,
        Err(StoreError::Other(_))
    ));
    // sessions: delete and delete_by_subject
    assert_eq!(
        uow.login_sessions()
            .delete_by_subject(&subject("alice"))
            .await
            .unwrap(),
        1
    );
    uow.login_sessions().delete(&session.id).await.unwrap();
}

#[tokio::test]
async fn authorization_flow_records_roundtrip() {
    let db = start().await;
    seed_client(&db, "c1").await;
    let request = AuthorizationRequestRecord {
        id: AuthorizationRequestId::new(uuid::Uuid::from_u128(7)),
        client_id: cid("c1"),
        redirect_uri: uri("https://a.example/cb"),
        redirect_uri_provided: true,
        scope: scope("read write"),
        state: Some(State::try_new("xyz".to_owned()).unwrap()),
        csrf_token_hash: hash(2),
        status: AuthorizationRequestStatus::Approved,
        subject: Some(subject("alice")),
        created_at: t(0),
        updated_at: t(1),
        expires_at: t(600),
    };
    let grant = grant_record(1, "c1");
    let code = AuthorizationCodeRecord {
        id: hash(1),
        client_id: cid("c1"),
        subject: subject("alice"),
        redirect_uri: uri("https://a.example/cb"),
        redirect_uri_provided: false,
        scope: scope("read"),
        status: AuthorizationCodeStatus::Redeemed {
            grant_id: gid(1),
            redeemed_at: t(3),
        },
        issued_at: t(0),
        expires_at: t(60),
    };
    let consent = ConsentRecord {
        id: ConsentId {
            subject: subject("alice"),
            client_id: cid("c1"),
        },
        scope: scope("read"),
        created_at: t(0),
        updated_at: t(0),
    };
    let access = AccessTokenRecord {
        id: hash(3),
        grant_id: gid(1),
        client_id: cid("c1"),
        subject: None,
        scope: scope("read"),
        issued_at: t(0),
        expires_at: t(3600),
    };
    let refresh = RefreshTokenRecord {
        id: hash(4),
        grant_id: gid(1),
        client_id: cid("c1"),
        status: RefreshTokenStatus::Rotated { rotated_at: t(9) },
        issued_at: t(0),
        expires_at: t(7200),
    };
    let revoked = GrantRecord {
        id: gid(2),
        client_id: cid("c1"),
        subject: None,
        scope: ScopeSet::empty(),
        origin: GrantOrigin::ClientCredentials,
        status: GrantStatus::Revoked {
            revoked_at: t(4),
            reason: RevocationReason::RefreshTokenReplay,
        },
        created_at: t(0),
    };
    {
        let (rq, g, rv, cd, cn, at, rt) = (
            request.clone(),
            grant.clone(),
            revoked.clone(),
            code.clone(),
            consent.clone(),
            access.clone(),
            refresh.clone(),
        );
        commit_with(&db, |uow| {
            Box::pin(async move {
                uow.authorization_requests()
                    .insert(&AuthorizationRequest::from_record(rq))
                    .await
                    .unwrap();
                uow.grants().insert(&Grant::from_record(g)).await.unwrap();
                uow.grants().insert(&Grant::from_record(rv)).await.unwrap();
                uow.authorization_codes()
                    .insert(&AuthorizationCode::from_record(cd))
                    .await
                    .unwrap();
                uow.consents()
                    .upsert(&Consent::from_record(cn))
                    .await
                    .unwrap();
                uow.access_tokens()
                    .insert(&AccessToken::from_record(at))
                    .await
                    .unwrap();
                uow.refresh_tokens()
                    .insert(&RefreshToken::from_record(rt))
                    .await
                    .unwrap();
            })
        })
        .await;
    }
    let mut uow = db.factory.begin().await.unwrap();
    assert_eq!(
        uow.authorization_requests()
            .find_for_update(request.id)
            .await
            .unwrap()
            .unwrap()
            .to_record(),
        request
    );
    assert_eq!(
        uow.authorization_codes()
            .find_for_update(&code.id)
            .await
            .unwrap()
            .unwrap()
            .to_record(),
        code
    );
    assert_eq!(
        uow.consents()
            .find(&consent.id.subject, &consent.id.client_id)
            .await
            .unwrap()
            .unwrap()
            .to_record(),
        consent
    );
    assert_eq!(
        uow.grants()
            .find(gid(1))
            .await
            .unwrap()
            .unwrap()
            .to_record(),
        grant
    );
    assert_eq!(
        uow.grants()
            .find_for_update(gid(2))
            .await
            .unwrap()
            .unwrap()
            .to_record(),
        revoked
    );
    assert_eq!(
        uow.access_tokens()
            .find(&access.id)
            .await
            .unwrap()
            .unwrap()
            .to_record(),
        access
    );
    assert_eq!(
        uow.refresh_tokens()
            .find_for_update(&refresh.id)
            .await
            .unwrap()
            .unwrap()
            .to_record(),
        refresh
    );
    // active grants only
    let by_client = uow
        .grants()
        .list_active_by_client(&cid("c1"))
        .await
        .unwrap();
    assert_eq!(by_client.len(), 1);
    let by_subject = uow
        .grants()
        .list_active_by_subject(&subject("alice"))
        .await
        .unwrap();
    assert_eq!(by_subject.len(), 1);
    // upsert replaces
    let mut changed = consent.clone();
    changed.scope = scope("write");
    changed.updated_at = t(8);
    uow.consents()
        .upsert(&Consent::from_record(changed.clone()))
        .await
        .unwrap();
    let found = uow
        .consents()
        .find(&consent.id.subject, &consent.id.client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.to_record(), changed);
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
async fn dropped_uow_is_rolled_back() {
    let db = start().await;
    {
        let mut uow = db.factory.begin().await.unwrap();
        uow.users()
            .insert(&User::from_record(user_record(1, "alice")))
            .await
            .unwrap();
    }
    let mut other = db.factory.begin().await.unwrap();
    assert!(
        other
            .users()
            .find(UserId::new(uuid::Uuid::from_u128(1)))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn unique_violation_is_conflict() {
    let db = start().await;
    let mut uow = db.factory.begin().await.unwrap();
    uow.users()
        .insert(&User::from_record(user_record(1, "alice")))
        .await
        .unwrap();
    let dup = User::from_record(user_record(2, "alice"));
    assert!(matches!(
        uow.users().insert(&dup).await,
        Err(StoreError::Conflict)
    ));
}

#[tokio::test]
async fn client_duplicate_id_is_conflict() {
    let db = start().await;
    seed_client(&db, "c1").await;
    let mut uow = db.factory.begin().await.unwrap();
    assert!(matches!(
        uow.clients()
            .insert(&Client::from_record(client_record("c1")))
            .await,
        Err(StoreError::Conflict)
    ));
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

#[tokio::test]
async fn purge_expired_deletes_only_expired_rows() {
    let db = start().await;
    seed_client(&db, "c1").await;
    let cutoff = t(1000);
    let session = |n: u8, expires: i64| {
        LoginSession::from_record(LoginSessionRecord {
            id: hash(n),
            subject: subject("alice"),
            created_at: t(0),
            expires_at: t(expires),
        })
    };
    let mut kept_grant = grant_record(1, "c1");
    kept_grant.created_at = t(0);
    let mut gone_grant = grant_record(2, "c1");
    gone_grant.created_at = t(0);
    let mut new_grant = grant_record(3, "c1");
    new_grant.created_at = t(2000);
    let access = |n: u8, grant: u128, expires: i64| {
        AccessToken::from_record(AccessTokenRecord {
            id: hash(n),
            grant_id: gid(grant),
            client_id: cid("c1"),
            subject: None,
            scope: ScopeSet::empty(),
            issued_at: t(0),
            expires_at: t(expires),
        })
    };
    let mut uow = db.factory.begin().await.unwrap();
    uow.login_sessions()
        .insert(&session(1, 1000))
        .await
        .unwrap();
    uow.login_sessions()
        .insert(&session(2, 1001))
        .await
        .unwrap();
    for g in [kept_grant, gone_grant, new_grant] {
        uow.grants().insert(&Grant::from_record(g)).await.unwrap();
    }
    // Expired token on grant 2 is purged, freeing the grant; grant 1 keeps a live token.
    uow.access_tokens()
        .insert(&access(3, 2, 1000))
        .await
        .unwrap();
    uow.access_tokens()
        .insert(&access(4, 1, 5000))
        .await
        .unwrap();
    let counts = uow.purge().purge_expired(cutoff).await.unwrap();
    assert_eq!(
        counts,
        PurgeCounts {
            login_sessions: 1,
            access_tokens: 1,
            grants: 1,
            ..PurgeCounts::default()
        }
    );
    assert!(uow.grants().find(gid(1)).await.unwrap().is_some());
    assert!(uow.grants().find(gid(2)).await.unwrap().is_none());
    assert!(uow.grants().find(gid(3)).await.unwrap().is_some());
    assert!(uow.access_tokens().find(&hash(4)).await.unwrap().is_some());
    assert!(uow.login_sessions().find(&hash(2)).await.unwrap().is_some());
    assert!(uow.login_sessions().find(&hash(1)).await.unwrap().is_none());
}

#[tokio::test]
async fn purge_audit_events_deletes_old_events() {
    let db = start().await;
    let event = |n: u128, at: i64| AuditEvent {
        id: uuid::Uuid::from_u128(n),
        occurred_at: t(at),
        kind: AuditKind::ClientRegistered,
        outcome: AuditOutcome::Success,
        actor: AuditActor::System,
        request_id: "r".to_owned(),
        client_ip: None,
        client_id: None,
        subject: None,
        details: BTreeMap::new(),
    };
    let mut uow = db.factory.begin().await.unwrap();
    uow.audit_log().append(&event(1, 0)).await.unwrap();
    uow.audit_log().append(&event(2, 1)).await.unwrap();
    assert_eq!(uow.purge().purge_audit_events(t(0)).await.unwrap(), 1);
}

/// Ten transactions race to redeem one authorization code: `find_for_update` serialises
/// them, so exactly one sees it unredeemed.
#[tokio::test]
async fn concurrent_code_redemption_has_one_winner() {
    let db = start().await;
    seed_client(&db, "c1").await;
    let code = AuthorizationCodeRecord {
        id: hash(1),
        client_id: cid("c1"),
        subject: subject("alice"),
        redirect_uri: uri("https://a.example/cb"),
        redirect_uri_provided: true,
        scope: scope("read"),
        status: AuthorizationCodeStatus::Issued,
        issued_at: t(0),
        expires_at: t(600),
    };
    commit_with(&db, |uow| {
        let code = code.clone();
        Box::pin(async move {
            uow.authorization_codes()
                .insert(&AuthorizationCode::from_record(code))
                .await
                .unwrap();
        })
    })
    .await;
    let mut tasks = Vec::new();
    for n in 0..10u128 {
        let factory = db.factory.clone();
        tasks.push(tokio::spawn(async move {
            let mut uow = factory.begin().await.unwrap();
            let mut code = uow
                .authorization_codes()
                .find_for_update(&hash(1))
                .await
                .unwrap()
                .unwrap();
            let ok = code
                .redeem(
                    &cid("c1"),
                    Some(&uri("https://a.example/cb")),
                    gid(100 + n),
                    t(1),
                )
                .is_ok();
            if ok {
                let grant = Grant::from_record(grant_record(100 + n, "c1"));
                uow.grants().insert(&grant).await.unwrap();
                uow.authorization_codes().update(&code).await.unwrap();
            }
            uow.commit().await.unwrap();
            ok
        }));
    }
    let mut wins = 0;
    for task in tasks {
        if task.await.unwrap() {
            wins += 1;
        }
    }
    assert_eq!(wins, 1);
}

fn service(db: &TestDb) -> komainu_application::TokenService {
    use std::sync::Arc;
    let hasher = Arc::new(komainu_testing::PlainPasswordHasher);
    let deps = Dependencies {
        store: Arc::new(db.factory.clone()),
        clock: Arc::new(komainu_adapter_std::SystemClock),
        random: Arc::new(komainu_adapter_std::OsSecureRandom),
        password_hasher: hasher.clone(),
        authenticator: Arc::new(BuiltinAuthenticator::new(hasher)),
        config: Arc::new(ApplicationConfig::default()),
    };
    TokenService::new(deps)
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
    let config = ApplicationConfig {
        scopes: vec![ScopeDefinition {
            name: ScopeToken::try_new("read".to_owned()).unwrap(),
            description: "read".to_owned(),
        }],
        ..ApplicationConfig::default()
    };
    let deps = Dependencies {
        store: Arc::new(db.factory.clone()),
        clock: Arc::new(komainu_adapter_std::SystemClock),
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

/// Ten concurrent refreshes with one refresh token: exactly one rotation succeeds.
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
            .is_ok()
        }));
    }
    let mut ok = 0;
    for task in tasks {
        if task.await.unwrap() {
            ok += 1;
        }
    }
    assert_eq!(ok, 1);
}
