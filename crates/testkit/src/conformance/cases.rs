//! The conformance cases, ported from the PostgreSQL adapter tests.

use std::collections::BTreeMap;
use std::sync::Arc;

use komainu_application::{
    AssertionKind, AuditActor, AuditEvent, AuditKind, AuditOutcome, ListPage, PurgeCounts,
    RecordOutcome, StoreError, UnitOfWork, UnitOfWorkFactory, UsedAssertion,
};
use komainu_domain::*;

use super::fixtures::*;
use super::{CaseFailure, StoreCase};

type Store = Arc<dyn UnitOfWorkFactory>;
type CaseResult = Result<(), CaseFailure>;

macro_rules! ensure {
    ($cond:expr, $($message:tt)+) => {
        if !$cond {
            return Err(CaseFailure::new(format!($($message)+)));
        }
    };
}

macro_rules! ensure_eq {
    ($left:expr, $right:expr, $what:expr) => {{
        let (left, right) = (&$left, &$right);
        if left != right {
            return Err(CaseFailure::new(format!(
                "{}: expected {right:?}, got {left:?}",
                $what
            )));
        }
    }};
}

macro_rules! case {
    ($name:ident) => {
        StoreCase {
            name: stringify!($name),
            run: |store| Box::pin($name(store)),
        }
    };
}

pub(super) static CASES: [StoreCase; 18] = [
    case!(client_user_session_roundtrip),
    case!(authorization_flow_records_roundtrip),
    case!(grant_revoked_by_client_request_roundtrip),
    case!(audit_append_commits),
    case!(dropped_uow_is_rolled_back),
    case!(unique_violation_is_conflict),
    case!(client_duplicate_id_is_conflict),
    case!(purge_expired_deletes_only_expired_rows),
    case!(purge_audit_events_deletes_old_events),
    case!(concurrent_code_redemption_has_one_winner),
    case!(private_key_jwt_client_and_jwt_bearer_grant_roundtrip),
    case!(trusted_issuer_roundtrip),
    case!(subject_mapping_roundtrip),
    case!(used_assertion_replay),
    case!(signing_key_roundtrip_and_order),
    case!(signing_key_duplicate_kid_is_conflict),
    case!(signing_key_update_schedule_and_delete),
    case!(signing_key_uncommitted_insert_is_invisible),
];

async fn seed_client_in(uow: &mut dyn UnitOfWork, id: &str) -> CaseResult {
    uow.clients()
        .insert(&Client::from_record(client_record(id)))
        .await?;
    Ok(())
}

async fn seed_client(store: &Store, id: &str) -> CaseResult {
    let mut uow = store.begin().await?;
    uow.clients()
        .insert(&Client::from_record(client_record(id)))
        .await?;
    uow.commit().await?;
    Ok(())
}

async fn client_user_session_roundtrip(store: Store) -> CaseResult {
    let client = client_record("c1");
    let user = user_record(1, "alice");
    let session = LoginSessionRecord {
        id: hash(5),
        subject: subject("alice"),
        created_at: t(0),
        expires_at: t(60),
    };
    {
        let mut uow = store.begin().await?;
        uow.clients()
            .insert(&Client::from_record(client.clone()))
            .await?;
        uow.users().insert(&User::from_record(user.clone())).await?;
        uow.login_sessions()
            .insert(&LoginSession::from_record(session.clone()))
            .await?;
        uow.commit().await?;
    }
    let mut uow = store.begin().await?;
    ensure_eq!(
        uow.clients().find(&client.id).await?.map(|c| c.to_record()),
        Some(client.clone()),
        "clients().find"
    );
    ensure_eq!(
        uow.clients()
            .find_for_update(&client.id)
            .await?
            .map(|c| c.to_record()),
        Some(client.clone()),
        "clients().find_for_update"
    );
    ensure!(
        uow.clients().find(&cid("none")).await?.is_none(),
        "clients().find of an unknown id returned a client"
    );
    ensure_eq!(
        uow.users().find(user.id).await?.map(|u| u.to_record()),
        Some(user.clone()),
        "users().find"
    );
    ensure_eq!(
        uow.users()
            .find_by_username(&user.username)
            .await?
            .map(|u| u.to_record()),
        Some(user.clone()),
        "users().find_by_username"
    );
    ensure_eq!(
        uow.login_sessions()
            .find(&session.id)
            .await?
            .map(|s| s.to_record()),
        Some(session.clone()),
        "login_sessions().find"
    );
    // update and list
    let mut changed = client.clone();
    changed.status = ClientStatus::Disabled;
    changed.updated_at = t(5);
    uow.clients()
        .update(&Client::from_record(changed.clone()))
        .await?;
    uow.clients()
        .insert(&Client::from_record(client_record("c2")))
        .await?;
    let page = ListPage {
        after: None,
        limit: 10,
    };
    let ids: Vec<_> = uow
        .clients()
        .list(&page)
        .await?
        .iter()
        .map(|c| c.to_record().id)
        .collect();
    ensure_eq!(ids, vec![cid("c1"), cid("c2")], "clients().list ids");
    let after = ListPage {
        after: Some(cid("c1")),
        limit: 1,
    };
    ensure_eq!(
        uow.clients().list(&after).await?.len(),
        1,
        "clients().list after c1 with limit 1"
    );
    let missing = Client::from_record(client_record("zzz"));
    ensure!(
        matches!(
            uow.clients().update(&missing).await,
            Err(StoreError::Other(_))
        ),
        "clients().update of a missing client must return StoreError::Other"
    );
    // sessions: delete and delete_by_subject
    ensure_eq!(
        uow.login_sessions()
            .delete_by_subject(&subject("alice"))
            .await?,
        1,
        "login_sessions().delete_by_subject"
    );
    uow.login_sessions().delete(&session.id).await?;
    Ok(())
}

async fn authorization_flow_records_roundtrip(store: Store) -> CaseResult {
    seed_client(&store, "c1").await?;
    let request = AuthorizationRequestRecord {
        id: AuthorizationRequestId::new(uuid::Uuid::from_u128(7)),
        client_id: cid("c1"),
        redirect_uri: uri("https://a.example/cb"),
        redirect_uri_provided: true,
        scope: scope("read write"),
        state: Some(State::try_new("xyz".to_owned()).unwrap()),
        csrf_token_hash: hash(2),
        pkce: pkce(),
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
        pkce: pkce(),
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
        let mut uow = store.begin().await?;
        uow.authorization_requests()
            .insert(&AuthorizationRequest::from_record(request.clone()))
            .await?;
        uow.grants()
            .insert(&Grant::from_record(grant.clone()))
            .await?;
        uow.grants()
            .insert(&Grant::from_record(revoked.clone()))
            .await?;
        uow.authorization_codes()
            .insert(&AuthorizationCode::from_record(code.clone()))
            .await?;
        uow.consents()
            .upsert(&Consent::from_record(consent.clone()))
            .await?;
        uow.access_tokens()
            .insert(&AccessToken::from_record(access.clone()))
            .await?;
        uow.refresh_tokens()
            .insert(&RefreshToken::from_record(refresh.clone()))
            .await?;
        uow.commit().await?;
    }
    let mut uow = store.begin().await?;
    ensure_eq!(
        uow.authorization_requests()
            .find_for_update(request.id)
            .await?
            .map(|r| r.to_record()),
        Some(request.clone()),
        "authorization_requests().find_for_update"
    );
    ensure_eq!(
        uow.authorization_codes()
            .find_for_update(&code.id)
            .await?
            .map(|c| c.to_record()),
        Some(code.clone()),
        "authorization_codes().find_for_update"
    );
    ensure_eq!(
        uow.consents()
            .find(&consent.id.subject, &consent.id.client_id)
            .await?
            .map(|c| c.to_record()),
        Some(consent.clone()),
        "consents().find"
    );
    ensure_eq!(
        uow.grants().find(gid(1)).await?.map(|g| g.to_record()),
        Some(grant.clone()),
        "grants().find"
    );
    ensure_eq!(
        uow.grants()
            .find_for_update(gid(2))
            .await?
            .map(|g| g.to_record()),
        Some(revoked.clone()),
        "grants().find_for_update"
    );
    ensure_eq!(
        uow.access_tokens()
            .find(&access.id)
            .await?
            .map(|a| a.to_record()),
        Some(access.clone()),
        "access_tokens().find"
    );
    ensure_eq!(
        uow.refresh_tokens()
            .find_for_update(&refresh.id)
            .await?
            .map(|r| r.to_record()),
        Some(refresh.clone()),
        "refresh_tokens().find_for_update"
    );
    // active grants only
    ensure_eq!(
        uow.grants().list_active_by_client(&cid("c1")).await?.len(),
        1,
        "grants().list_active_by_client"
    );
    ensure_eq!(
        uow.grants()
            .list_active_by_subject(&subject("alice"))
            .await?
            .len(),
        1,
        "grants().list_active_by_subject"
    );
    // upsert replaces
    let mut changed = consent.clone();
    changed.scope = scope("write");
    changed.updated_at = t(8);
    uow.consents()
        .upsert(&Consent::from_record(changed.clone()))
        .await?;
    ensure_eq!(
        uow.consents()
            .find(&consent.id.subject, &consent.id.client_id)
            .await?
            .map(|c| c.to_record()),
        Some(changed),
        "consents().find after upsert"
    );
    Ok(())
}

async fn audit_append_commits(store: Store) -> CaseResult {
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
    let mut uow = store.begin().await?;
    uow.audit_log().append(&event).await?;
    uow.commit().await?;
    Ok(())
}

async fn grant_revoked_by_client_request_roundtrip(store: Store) -> CaseResult {
    seed_client(&store, "c1").await?;
    let record = GrantRecord {
        id: gid(1),
        client_id: cid("c1"),
        subject: None,
        scope: ScopeSet::empty(),
        origin: GrantOrigin::ClientCredentials,
        status: GrantStatus::Active,
        created_at: t(0),
    };
    {
        let mut uow = store.begin().await?;
        let mut grant = Grant::from_record(record.clone());
        uow.grants().insert(&grant).await?;
        grant.revoke(RevocationReason::ClientRequest, t(5));
        uow.grants().update(&grant).await?;
        uow.commit().await?;
    }
    let mut uow = store.begin().await?;
    ensure_eq!(
        uow.grants()
            .find(gid(1))
            .await?
            .map(|g| g.to_record().status),
        Some(GrantStatus::Revoked {
            revoked_at: t(5),
            reason: RevocationReason::ClientRequest,
        }),
        "grants().find after revoke(ClientRequest)"
    );
    Ok(())
}

async fn dropped_uow_is_rolled_back(store: Store) -> CaseResult {
    {
        let mut uow = store.begin().await?;
        uow.users()
            .insert(&User::from_record(user_record(1, "alice")))
            .await?;
    }
    let mut other = store.begin().await?;
    ensure!(
        other
            .users()
            .find(UserId::new(uuid::Uuid::from_u128(1)))
            .await?
            .is_none(),
        "a user written by a dropped unit of work is visible"
    );
    Ok(())
}

async fn unique_violation_is_conflict(store: Store) -> CaseResult {
    let mut uow = store.begin().await?;
    uow.users()
        .insert(&User::from_record(user_record(1, "alice")))
        .await?;
    let dup = User::from_record(user_record(2, "alice"));
    ensure!(
        matches!(uow.users().insert(&dup).await, Err(StoreError::Conflict)),
        "inserting a second user with the same username must return StoreError::Conflict"
    );
    Ok(())
}

async fn client_duplicate_id_is_conflict(store: Store) -> CaseResult {
    seed_client(&store, "c1").await?;
    let mut uow = store.begin().await?;
    ensure!(
        matches!(
            uow.clients()
                .insert(&Client::from_record(client_record("c1")))
                .await,
            Err(StoreError::Conflict)
        ),
        "inserting a client with an existing id must return StoreError::Conflict"
    );
    Ok(())
}

async fn purge_expired_deletes_only_expired_rows(store: Store) -> CaseResult {
    seed_client(&store, "c1").await?;
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
    let code = |n: u8, expires: i64| {
        AuthorizationCode::from_record(AuthorizationCodeRecord {
            id: hash(n),
            client_id: cid("c1"),
            subject: subject("alice"),
            redirect_uri: uri("https://a.example/cb"),
            redirect_uri_provided: true,
            scope: scope("read"),
            pkce: pkce(),
            status: AuthorizationCodeStatus::Issued,
            issued_at: t(0),
            expires_at: t(expires),
        })
    };
    let refresh = |n: u8, expires: i64| {
        RefreshToken::from_record(RefreshTokenRecord {
            id: hash(n),
            grant_id: gid(1),
            client_id: cid("c1"),
            status: RefreshTokenStatus::Active,
            issued_at: t(0),
            expires_at: t(expires),
        })
    };
    let request = |n: u128, expires: i64| {
        AuthorizationRequest::from_record(AuthorizationRequestRecord {
            id: AuthorizationRequestId::new(uuid::Uuid::from_u128(n)),
            client_id: cid("c1"),
            redirect_uri: uri("https://a.example/cb"),
            redirect_uri_provided: true,
            scope: scope("read"),
            state: None,
            csrf_token_hash: hash(9),
            pkce: pkce(),
            status: AuthorizationRequestStatus::Pending,
            subject: None,
            created_at: t(0),
            updated_at: t(0),
            expires_at: t(expires),
        })
    };
    let mut uow = store.begin().await?;
    // Each table gets one row expiring exactly at the cutoff (deleted) and one just after
    // (kept).
    uow.login_sessions().insert(&session(1, 1000)).await?;
    uow.login_sessions().insert(&session(2, 1001)).await?;
    for g in [kept_grant, gone_grant, new_grant] {
        uow.grants().insert(&Grant::from_record(g)).await?;
    }
    // Expired token on grant 2 is purged, freeing the grant; grant 1 keeps a live token.
    uow.access_tokens().insert(&access(3, 2, 1000)).await?;
    uow.access_tokens().insert(&access(4, 1, 1001)).await?;
    uow.refresh_tokens().insert(&refresh(5, 1000)).await?;
    uow.refresh_tokens().insert(&refresh(6, 1001)).await?;
    uow.authorization_codes().insert(&code(7, 1000)).await?;
    uow.authorization_codes().insert(&code(8, 1001)).await?;
    uow.authorization_requests()
        .insert(&request(1, 1000))
        .await?;
    uow.authorization_requests()
        .insert(&request(2, 1001))
        .await?;
    // Used assertions are purged only when strictly older than the cutoff.
    for (jti, expires) in [("old", 999), ("edge", 1000), ("new", 1001)] {
        uow.used_assertions()
            .record(&used_assertion(
                AssertionKind::AuthorizationGrant,
                jti,
                expires,
            ))
            .await?;
    }
    let counts = uow.purge().purge_expired(cutoff).await?;
    ensure_eq!(
        counts,
        PurgeCounts {
            authorization_requests: 1,
            authorization_codes: 1,
            access_tokens: 1,
            refresh_tokens: 1,
            login_sessions: 1,
            grants: 1,
            used_assertions: 1,
        },
        "purge_expired counts"
    );
    ensure!(
        uow.grants().find(gid(1)).await?.is_some(),
        "grant 1 (still has a live token) was purged"
    );
    ensure!(
        uow.grants().find(gid(2)).await?.is_none(),
        "grant 2 (expired token purged) was kept"
    );
    ensure!(
        uow.grants().find(gid(3)).await?.is_some(),
        "grant 3 (created after the cutoff) was purged"
    );
    ensure!(
        uow.access_tokens().find(&hash(3)).await?.is_none(),
        "access token expiring at the cutoff was kept"
    );
    ensure!(
        uow.access_tokens().find(&hash(4)).await?.is_some(),
        "access token expiring after the cutoff was purged"
    );
    ensure!(
        uow.refresh_tokens()
            .find_for_update(&hash(5))
            .await?
            .is_none(),
        "refresh token expiring at the cutoff was kept"
    );
    ensure!(
        uow.refresh_tokens()
            .find_for_update(&hash(6))
            .await?
            .is_some(),
        "refresh token expiring after the cutoff was purged"
    );
    ensure!(
        uow.authorization_codes()
            .find_for_update(&hash(7))
            .await?
            .is_none(),
        "authorization code expiring at the cutoff was kept"
    );
    ensure!(
        uow.authorization_codes()
            .find_for_update(&hash(8))
            .await?
            .is_some(),
        "authorization code expiring after the cutoff was purged"
    );
    let req_id = |n: u128| AuthorizationRequestId::new(uuid::Uuid::from_u128(n));
    ensure!(
        uow.authorization_requests()
            .find_for_update(req_id(1))
            .await?
            .is_none(),
        "authorization request expiring at the cutoff was kept"
    );
    ensure!(
        uow.authorization_requests()
            .find_for_update(req_id(2))
            .await?
            .is_some(),
        "authorization request expiring after the cutoff was purged"
    );
    for (jti, kept) in [("old", false), ("edge", true), ("new", true)] {
        let outcome = uow
            .used_assertions()
            .record(&used_assertion(
                AssertionKind::AuthorizationGrant,
                jti,
                5000,
            ))
            .await?;
        ensure_eq!(
            outcome,
            if kept {
                RecordOutcome::Replayed
            } else {
                RecordOutcome::Recorded
            },
            format!("recording used assertion {jti:?} after purge")
        );
    }
    ensure!(
        uow.login_sessions().find(&hash(2)).await?.is_some(),
        "login session expiring after the cutoff was purged"
    );
    ensure!(
        uow.login_sessions().find(&hash(1)).await?.is_none(),
        "login session expiring at the cutoff was kept"
    );
    Ok(())
}

async fn purge_audit_events_deletes_old_events(store: Store) -> CaseResult {
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
    let mut uow = store.begin().await?;
    uow.audit_log().append(&event(1, 0)).await?;
    uow.audit_log().append(&event(2, 1)).await?;
    ensure_eq!(
        uow.purge().purge_audit_events(t(0)).await?,
        1,
        "purge_audit_events"
    );
    Ok(())
}

/// Redeems the code in its own unit of work. `Ok(true)` is a win, `Ok(false)` a loss
/// (already redeemed, or an optimistic-locking conflict).
async fn try_redeem(store: &Store, n: u128) -> Result<bool, CaseFailure> {
    async fn attempt(store: &Store, n: u128) -> Result<bool, StoreError> {
        let mut uow = store.begin().await?;
        let Some(mut code) = uow.authorization_codes().find_for_update(&hash(1)).await? else {
            return Ok(false);
        };
        let won = code
            .redeem(
                &cid("c1"),
                Some(&uri("https://a.example/cb")),
                &code_verifier(),
                gid(100 + n),
                t(1),
            )
            .is_ok();
        if won {
            let grant = Grant::from_record(grant_record(100 + n, "c1"));
            uow.grants().insert(&grant).await?;
            uow.authorization_codes().update(&code).await?;
        }
        uow.commit().await?;
        Ok(won)
    }
    match attempt(store, n).await {
        Ok(won) => Ok(won),
        Err(StoreError::Conflict) => Ok(false),
        Err(other) => Err(other.into()),
    }
}

/// Two transactions race to redeem one authorization code: `find_for_update` serialises
/// them (or the loser gets `StoreError::Conflict`), so exactly one wins.
async fn concurrent_code_redemption_has_one_winner(store: Store) -> CaseResult {
    seed_client(&store, "c1").await?;
    let code = AuthorizationCodeRecord {
        id: hash(1),
        client_id: cid("c1"),
        subject: subject("alice"),
        redirect_uri: uri("https://a.example/cb"),
        redirect_uri_provided: true,
        scope: scope("read"),
        pkce: pkce(),
        status: AuthorizationCodeStatus::Issued,
        issued_at: t(0),
        expires_at: t(600),
    };
    {
        let mut uow = store.begin().await?;
        uow.authorization_codes()
            .insert(&AuthorizationCode::from_record(code))
            .await?;
        uow.commit().await?;
    }
    let (first, second) = tokio::join!(try_redeem(&store, 0), try_redeem(&store, 1));
    let wins = u32::from(first?) + u32::from(second?);
    ensure_eq!(wins, 1, "number of transactions that redeemed the code");
    Ok(())
}

fn used_assertion(kind: AssertionKind, jti: &str, expires: i64) -> UsedAssertion {
    UsedAssertion {
        kind,
        issuer: "https://idp.example.com".to_owned(),
        jti: jti.to_owned(),
        expires_at: t(expires),
    }
}

async fn private_key_jwt_client_and_jwt_bearer_grant_roundtrip(store: Store) -> CaseResult {
    let mut with_jwks = client_record("c1");
    with_jwks.auth_method = TokenEndpointAuthMethod::PrivateKeyJwt;
    with_jwks.secret_hash = None;
    with_jwks.keys = Some(ClientKeys::Jwks(jwks_document()));
    let mut with_uri = client_record("c2");
    with_uri.auth_method = TokenEndpointAuthMethod::PrivateKeyJwt;
    with_uri.secret_hash = None;
    with_uri.keys = Some(ClientKeys::JwksUri(
        JwksUri::try_new("https://idp.example.com/jwks".to_owned()).unwrap(),
    ));
    let mut grant = grant_record(1, "c1");
    grant.origin = GrantOrigin::JwtBearer;
    {
        let mut uow = store.begin().await?;
        for record in [&with_jwks, &with_uri] {
            uow.clients()
                .insert(&Client::from_record(record.clone()))
                .await?;
        }
        uow.grants()
            .insert(&Grant::from_record(grant.clone()))
            .await?;
        uow.commit().await?;
    }
    let mut uow = store.begin().await?;
    for record in [with_jwks, with_uri] {
        ensure_eq!(
            uow.clients().find(&record.id).await?.map(|c| c.to_record()),
            Some(record),
            "clients().find of a private_key_jwt client"
        );
    }
    ensure_eq!(
        uow.grants().find(gid(1)).await?.map(|g| g.to_record()),
        Some(grant),
        "grants().find of a jwt_bearer grant"
    );
    Ok(())
}

async fn trusted_issuer_roundtrip(store: Store) -> CaseResult {
    for client in ["a", "b", "c"] {
        seed_client(&store, client).await?;
    }
    let first = issuer_record("https://a.example.com", &["a", "b"]);
    {
        let mut uow = store.begin().await?;
        uow.trusted_issuers()
            .insert(&TrustedIssuer::from_record(first.clone()))
            .await?;
        uow.commit().await?;
    }
    let mut uow = store.begin().await?;
    ensure_eq!(
        uow.trusted_issuers()
            .find(&first.id)
            .await?
            .map(|i| i.to_record()),
        Some(first.clone()),
        "trusted_issuers().find"
    );
    ensure_eq!(
        uow.trusted_issuers()
            .find_for_update(&first.id)
            .await?
            .map(|i| i.to_record()),
        Some(first.clone()),
        "trusted_issuers().find_for_update"
    );
    ensure!(
        uow.trusted_issuers()
            .find(&issuer_id("none"))
            .await?
            .is_none(),
        "trusted_issuers().find of an unknown id returned an issuer"
    );
    ensure!(
        matches!(
            uow.trusted_issuers()
                .insert(&TrustedIssuer::from_record(first.clone()))
                .await,
            Err(StoreError::Conflict)
        ),
        "inserting an issuer with an existing id must return StoreError::Conflict"
    );
    drop(uow);

    // update replaces the allowed clients: {a, b} -> {b, c}
    let mut changed = first.clone();
    changed.allowed_clients = ["b", "c"].iter().map(|c| cid(c)).collect();
    changed.status = IssuerStatus::Disabled;
    changed.updated_at = t(5);
    let mut uow = store.begin().await?;
    uow.trusted_issuers()
        .insert(&TrustedIssuer::from_record(issuer_record(
            "https://b.example.com",
            &["a"],
        )))
        .await?;
    uow.trusted_issuers()
        .update(&TrustedIssuer::from_record(changed.clone()))
        .await?;
    ensure_eq!(
        uow.trusted_issuers()
            .find(&first.id)
            .await?
            .map(|i| i.to_record()),
        Some(changed.clone()),
        "trusted_issuers().find after update"
    );
    let page = ListPage {
        after: None,
        limit: 1,
    };
    let ids: Vec<_> = uow
        .trusted_issuers()
        .list(&page)
        .await?
        .iter()
        .map(|i| i.to_record().id)
        .collect();
    ensure_eq!(
        ids,
        vec![first.id.clone()],
        "trusted_issuers().list limit 1"
    );
    let page = ListPage {
        after: Some(first.id.clone()),
        limit: 10,
    };
    let ids: Vec<_> = uow
        .trusted_issuers()
        .list(&page)
        .await?
        .iter()
        .map(|i| i.to_record().id)
        .collect();
    ensure_eq!(
        ids,
        vec![issuer_id("https://b.example.com")],
        "trusted_issuers().list after the first id"
    );
    Ok(())
}

async fn subject_mapping_roundtrip(store: Store) -> CaseResult {
    let issuer = issuer_id("https://a.example.com");
    {
        let mut uow = store.begin().await?;
        seed_client_in(&mut *uow, "c1").await?;
        for (n, name) in [(1, "alice"), (2, "bob")] {
            uow.users()
                .insert(&User::from_record(user_record(n, name)))
                .await?;
        }
        uow.trusted_issuers()
            .insert(&TrustedIssuer::from_record(issuer_record(
                "https://a.example.com",
                &["c1"],
            )))
            .await?;
        uow.commit().await?;
    }
    let mut uow = store.begin().await?;
    let first = mapping("https://a.example.com", "sub-1", 1, 0);
    uow.subject_mappings().upsert(&first).await?;
    ensure_eq!(
        uow.subject_mappings()
            .find(&issuer, &external_subject("sub-1"))
            .await?,
        Some(first),
        "subject_mappings().find"
    );
    ensure!(
        uow.subject_mappings()
            .find(&issuer, &external_subject("other"))
            .await?
            .is_none(),
        "subject_mappings().find of an unknown subject returned a mapping"
    );
    let overwritten = mapping("https://a.example.com", "sub-1", 2, 7);
    uow.subject_mappings().upsert(&overwritten).await?;
    ensure_eq!(
        uow.subject_mappings()
            .find(&issuer, &external_subject("sub-1"))
            .await?,
        Some(overwritten.clone()),
        "subject_mappings().find after overwriting upsert"
    );
    let second = mapping("https://a.example.com", "sub-0", 1, 1);
    uow.subject_mappings().upsert(&second).await?;
    let page = ListPage {
        after: None,
        limit: 10,
    };
    ensure_eq!(
        uow.subject_mappings()
            .list_by_issuer(&issuer, &page)
            .await?,
        vec![second.clone(), overwritten.clone()],
        "subject_mappings().list_by_issuer"
    );
    let page = ListPage {
        after: Some(external_subject("sub-0")),
        limit: 10,
    };
    ensure_eq!(
        uow.subject_mappings()
            .list_by_issuer(&issuer, &page)
            .await?,
        vec![overwritten],
        "subject_mappings().list_by_issuer after sub-0"
    );
    ensure!(
        uow.subject_mappings()
            .delete(&issuer, &external_subject("sub-1"))
            .await?,
        "subject_mappings().delete of an existing mapping returned false"
    );
    ensure!(
        !uow.subject_mappings()
            .delete(&issuer, &external_subject("sub-1"))
            .await?,
        "subject_mappings().delete of a missing mapping returned true"
    );
    Ok(())
}

async fn used_assertion_replay(store: Store) -> CaseResult {
    let grant = used_assertion(AssertionKind::AuthorizationGrant, "j1", 100);
    let client_auth = used_assertion(AssertionKind::ClientAuthentication, "j1", 100);
    {
        let mut uow = store.begin().await?;
        ensure_eq!(
            uow.used_assertions().record(&grant).await?,
            RecordOutcome::Recorded,
            "first record"
        );
        ensure_eq!(
            uow.used_assertions().record(&grant).await?,
            RecordOutcome::Replayed,
            "second record of the same key"
        );
        ensure_eq!(
            uow.used_assertions().record(&client_auth).await?,
            RecordOutcome::Recorded,
            "record of the same issuer and jti with another kind"
        );
        // Dropped without commit.
    }
    let mut uow = store.begin().await?;
    ensure_eq!(
        uow.used_assertions().record(&grant).await?,
        RecordOutcome::Recorded,
        "record after the first unit of work was dropped"
    );
    uow.commit().await?;
    let mut uow = store.begin().await?;
    ensure_eq!(
        uow.used_assertions().record(&grant).await?,
        RecordOutcome::Replayed,
        "record after the key was committed"
    );
    Ok(())
}

async fn signing_key_roundtrip_and_order(store: Store) -> CaseResult {
    // Inserted out of order; `B`, `b` and `a` share `activates_at`; `kid` breaks the
    // tie in byte order (`B` < `a` < `b`), independent of the DB collation.
    let keys = [
        signing_key_with(SigningAlgorithm::Rs256, "c", 20, 30, 40),
        signing_key("b", 10, 30, 40),
        signing_key("a", 10, 30, 40),
        signing_key("B", 10, 30, 40),
    ];
    let mut uow = store.begin().await?;
    for key in &keys {
        uow.signing_keys().insert(key).await?;
    }
    uow.commit().await?;
    let mut uow = store.begin().await?;
    let listed = uow.signing_keys().list().await?;
    let expected = vec![
        keys[3].clone(),
        keys[2].clone(),
        keys[1].clone(),
        keys[0].clone(),
    ];
    ensure_eq!(listed, expected, "signing_keys().list");
    Ok(())
}

async fn signing_key_duplicate_kid_is_conflict(store: Store) -> CaseResult {
    let mut uow = store.begin().await?;
    uow.signing_keys()
        .insert(&signing_key("a", 1, 2, 3))
        .await?;
    uow.commit().await?;
    let mut uow = store.begin().await?;
    let result = uow.signing_keys().insert(&signing_key("a", 5, 6, 7)).await;
    ensure!(
        matches!(result, Err(StoreError::Conflict)),
        "duplicate kid: expected Conflict, got {result:?}"
    );
    Ok(())
}

async fn signing_key_update_schedule_and_delete(store: Store) -> CaseResult {
    let original = signing_key("a", 1, 2, 3);
    let mut uow = store.begin().await?;
    uow.signing_keys().insert(&original).await?;
    uow.commit().await?;

    // Only the three times may change, even when other fields differ.
    let mut record = original.to_record();
    record.activates_at = t(10);
    record.retires_at = t(20);
    record.deletes_at = t(30);
    let expected = ServerSigningKey::from_record(record.clone());
    record.sealed_private_key = SealedPrivateKey::new(vec![9, 9]).unwrap();
    record.public_jwk = PublicJwk::try_new(r#"{"kid":"other"}"#.to_owned()).unwrap();
    let mut uow = store.begin().await?;
    uow.signing_keys()
        .update_schedule(&ServerSigningKey::from_record(record))
        .await?;
    uow.commit().await?;
    let mut uow = store.begin().await?;
    ensure_eq!(
        uow.signing_keys().list().await?,
        vec![expected],
        "list after update_schedule"
    );

    let result = uow
        .signing_keys()
        .update_schedule(&signing_key("missing", 1, 2, 3))
        .await;
    ensure!(
        matches!(&result, Err(StoreError::Other(m)) if m == "signing key not found"),
        "update_schedule of a missing key: expected Other(\"signing key not found\"), got {result:?}"
    );

    ensure!(
        uow.signing_keys().delete(&signing_key_id("a")).await?,
        "delete of an existing key returned false"
    );
    ensure!(
        !uow.signing_keys().delete(&signing_key_id("a")).await?,
        "second delete returned true"
    );
    ensure!(
        uow.signing_keys().list().await?.is_empty(),
        "list after delete is not empty"
    );
    Ok(())
}

async fn signing_key_uncommitted_insert_is_invisible(store: Store) -> CaseResult {
    let mut writer = store.begin().await?;
    writer
        .signing_keys()
        .insert(&signing_key("a", 1, 2, 3))
        .await?;
    let mut reader = store.begin().await?;
    ensure!(
        reader.signing_keys().list().await?.is_empty(),
        "an uncommitted insert is visible to another unit of work"
    );
    drop(writer);
    let mut reader = store.begin().await?;
    ensure!(
        reader.signing_keys().list().await?.is_empty(),
        "a dropped insert is visible"
    );
    Ok(())
}
