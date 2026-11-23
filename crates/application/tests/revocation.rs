//! TokenService::revoke acceptance tests (token-revocation design §5.2).

mod common;

use common::*;
use komainu_application::{
    AuditKind, ClientAuthentication, RevocationError, RevocationRequest, TokenResponse,
};
use komainu_domain::{GrantType, Secret};
use time::Duration;

fn request(token: &str, hint: Option<&str>) -> RevocationRequest {
    RevocationRequest {
        token: Some(token.to_owned()),
        token_type_hint: hint.map(str::to_owned),
        ..RevocationRequest::default()
    }
}

fn revoke(
    fx: &Fixture,
    auth: ClientAuthentication,
    request: RevocationRequest,
) -> Result<(), RevocationError> {
    block_on(fx.token.revoke(&ctx(), auth, request))
}

fn kinds(fx: &Fixture, kind: AuditKind) -> Vec<komainu_application::AuditEvent> {
    fx.env
        .store
        .audit_events()
        .into_iter()
        .filter(|e| e.kind == kind)
        .collect()
}

fn alive(fx: &Fixture, token: &str) -> bool {
    block_on(fx.token.verify_access_token(token))
        .unwrap()
        .is_some()
}

/// A client, a user and the tokens of one authorization code exchange.
fn setup() -> (Fixture, Registered, TokenResponse) {
    let fx = Fixture::new();
    let client = register(&fx, confidential(&ALL_GRANTS));
    create_user(&fx, "alice");
    let code = obtain_code(&fx, &client.id, "alice", &[("scope", "read")]);
    let tokens = exchange(&fx, client.basic(), code_request(&code)).unwrap();
    (fx, client, tokens)
}

fn refresh_of(tokens: &TokenResponse) -> String {
    tokens.refresh_token.as_ref().unwrap().expose().to_string()
}

fn access_of(tokens: &TokenResponse) -> String {
    tokens.access_token.expose().to_string()
}

#[test]
fn revoking_the_access_token_revokes_the_grant() {
    let (fx, client, tokens) = setup();
    revoke(&fx, client.basic(), request(&access_of(&tokens), None)).unwrap();
    assert!(!alive(&fx, &access_of(&tokens)));
    // The refresh token of the same grant stops working too.
    let err = exchange(
        &fx,
        client.basic(),
        refresh_request(&refresh_of(&tokens), None),
    )
    .unwrap_err();
    assert_eq!(err.code(), "invalid_grant");
    let events = kinds(&fx, AuditKind::GrantRevoked);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].details["reason"], "client_request");
    assert_eq!(events[0].actor.as_str(), "client");
    assert_eq!(events[0].outcome.as_str(), "success");
    assert!(events[0].details.contains_key("grant_id"));
    assert_eq!(events[0].client_id.as_ref(), Some(&client.id));
}

#[test]
fn revoking_the_refresh_token_revokes_the_grant() {
    let (fx, client, tokens) = setup();
    revoke(
        &fx,
        client.basic(),
        request(&refresh_of(&tokens), Some("refresh_token")),
    )
    .unwrap();
    assert!(!alive(&fx, &access_of(&tokens)));
    assert_eq!(kinds(&fx, AuditKind::GrantRevoked).len(), 1);
    // The revoked refresh token itself can no longer be exchanged.
    let err = exchange(
        &fx,
        client.basic(),
        refresh_request(&refresh_of(&tokens), None),
    )
    .unwrap_err();
    assert_eq!(err.code(), "invalid_grant");
}

#[test]
fn a_wrong_or_unknown_hint_does_not_matter() {
    let (fx, client, tokens) = setup();
    // The hint says access_token but a refresh token is presented.
    revoke(
        &fx,
        client.basic(),
        request(&refresh_of(&tokens), Some("access_token")),
    )
    .unwrap();
    assert!(!alive(&fx, &access_of(&tokens)));

    let (fx, client, tokens) = setup();
    // The hint says refresh_token but an access token is presented.
    revoke(
        &fx,
        client.basic(),
        request(&access_of(&tokens), Some("refresh_token")),
    )
    .unwrap();
    assert!(!alive(&fx, &access_of(&tokens)));

    let (fx, client, tokens) = setup();
    revoke(
        &fx,
        client.basic(),
        request(&access_of(&tokens), Some("bogus")),
    )
    .unwrap();
    assert!(!alive(&fx, &access_of(&tokens)));
}

#[test]
fn a_rotated_refresh_token_still_revokes_without_replay_detection() {
    let (fx, client, tokens) = setup();
    let rotated = exchange(
        &fx,
        client.basic(),
        refresh_request(&refresh_of(&tokens), None),
    )
    .unwrap();
    revoke(&fx, client.basic(), request(&refresh_of(&tokens), None)).unwrap();
    assert!(!alive(&fx, &access_of(&rotated)));
    assert!(kinds(&fx, AuditKind::RefreshTokenReplayDetected).is_empty());
    // The newest refresh token is dead too.
    let err = exchange(
        &fx,
        client.basic(),
        refresh_request(&refresh_of(&rotated), None),
    )
    .unwrap_err();
    assert_eq!(err.code(), "invalid_grant");
    let events = kinds(&fx, AuditKind::GrantRevoked);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].details["reason"], "client_request");
}

#[test]
fn expired_tokens_still_revoke_the_grant() {
    let (fx, client, tokens) = setup();
    fx.env.clock.advance(Duration::days(365));
    revoke(&fx, client.basic(), request(&access_of(&tokens), None)).unwrap();
    assert_eq!(kinds(&fx, AuditKind::GrantRevoked).len(), 1);
}

#[test]
fn an_expired_refresh_token_still_revokes_the_grant() {
    let (fx, client, tokens) = setup();
    fx.env.clock.advance(Duration::days(365));
    revoke(
        &fx,
        client.basic(),
        request(&refresh_of(&tokens), Some("refresh_token")),
    )
    .unwrap();
    assert_eq!(kinds(&fx, AuditKind::GrantRevoked).len(), 1);
}

#[test]
fn a_purged_token_succeeds_without_changes() {
    let (fx, client, tokens) = setup();
    fx.env.clock.advance(Duration::days(3650));
    block_on(fx.maintenance.purge_expired(&ctx())).unwrap();
    assert!(fx.env.store.state().refresh_tokens.is_empty());
    assert!(fx.env.store.state().access_tokens.is_empty());
    let before = fx.env.store.audit_events().len();
    revoke(&fx, client.basic(), request(&refresh_of(&tokens), None)).unwrap();
    revoke(&fx, client.basic(), request(&access_of(&tokens), None)).unwrap();
    assert_eq!(fx.env.store.audit_events().len(), before);
    assert!(kinds(&fx, AuditKind::GrantRevoked).is_empty());
}

#[test]
fn revoking_the_same_token_twice_audits_once() {
    for refresh in [false, true] {
        let (fx, client, tokens) = setup();
        let token = if refresh {
            refresh_of(&tokens)
        } else {
            access_of(&tokens)
        };
        revoke(&fx, client.basic(), request(&token, None)).unwrap();
        revoke(&fx, client.basic(), request(&token, None)).unwrap();
        assert_eq!(kinds(&fx, AuditKind::GrantRevoked).len(), 1);
    }
}

#[test]
fn revoking_both_tokens_of_a_grant_audits_once() {
    let (fx, client, tokens) = setup();
    revoke(&fx, client.basic(), request(&access_of(&tokens), None)).unwrap();
    revoke(&fx, client.basic(), request(&refresh_of(&tokens), None)).unwrap();
    assert_eq!(kinds(&fx, AuditKind::GrantRevoked).len(), 1);
}

#[test]
fn unknown_and_malformed_tokens_succeed_silently() {
    let (fx, client, tokens) = setup();
    let unissued = "a".repeat(512);
    for raw in [
        "nope",
        "ünicode-トークン",
        "bad\x01token",
        "line\nbreak",
        &"a".repeat(513),
        &unissued,
    ] {
        revoke(&fx, client.basic(), request(raw, None)).unwrap();
    }
    assert!(alive(&fx, &access_of(&tokens)));
    assert!(kinds(&fx, AuditKind::GrantRevoked).is_empty());
    assert!(kinds(&fx, AuditKind::TokenRevocationClientMismatch).is_empty());
}

#[test]
fn another_clients_token_is_refused_and_audited() {
    let (fx, client, tokens) = setup();
    let other = register(&fx, confidential(&ALL_GRANTS));
    for token in [access_of(&tokens), refresh_of(&tokens)] {
        let err = revoke(&fx, other.basic(), request(&token, None)).unwrap_err();
        assert!(matches!(err, RevocationError::InvalidGrant));
    }
    assert!(alive(&fx, &access_of(&tokens)));
    assert!(kinds(&fx, AuditKind::GrantRevoked).is_empty());
    let events = kinds(&fx, AuditKind::TokenRevocationClientMismatch);
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].outcome.as_str(), "failure");
    assert_eq!(events[0].client_id.as_ref(), Some(&other.id));
    assert_eq!(events[0].details["token_type"], "access_token");
    assert_eq!(events[1].details["token_type"], "refresh_token");
    let secret = tokens.access_token.expose();
    assert!(
        events
            .iter()
            .all(|e| e.details.values().all(|v| !v.contains(secret)))
    );

    // Also refused after the grant was revoked.
    revoke(&fx, client.basic(), request(&access_of(&tokens), None)).unwrap();
    let err = revoke(&fx, other.basic(), request(&access_of(&tokens), None)).unwrap_err();
    assert!(matches!(err, RevocationError::InvalidGrant));
    assert_eq!(
        kinds(&fx, AuditKind::TokenRevocationClientMismatch).len(),
        3
    );
}

#[test]
fn client_authentication_failure_revokes_nothing() {
    let (fx, client, tokens) = setup();
    let bad = ClientAuthentication::Basic {
        client_id: client.id.as_inner().to_string(),
        secret: Secret::new("wrong".to_owned()),
    };
    let err = revoke(&fx, bad, request(&access_of(&tokens), None)).unwrap_err();
    assert!(matches!(
        err,
        RevocationError::InvalidClient {
            basic_attempted: true
        }
    ));
    let err = revoke(
        &fx,
        ClientAuthentication::None,
        request(&access_of(&tokens), None),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        RevocationError::InvalidClient {
            basic_attempted: false
        }
    ));
    assert!(alive(&fx, &access_of(&tokens)));
    assert_eq!(kinds(&fx, AuditKind::ClientAuthenticationFailed).len(), 2);
}

#[test]
fn other_client_authentication_failures_revoke_nothing() {
    let failed = |fx: &Fixture, auth, token: &str| {
        let err = revoke(fx, auth, request(token, None)).unwrap_err();
        assert!(matches!(
            err,
            RevocationError::InvalidClient {
                basic_attempted: false
            }
        ));
    };
    // Wrong client_secret_post secret.
    let fx = Fixture::new();
    let mut input = confidential(&ALL_GRANTS);
    input.auth_method = komainu_domain::TokenEndpointAuthMethod::ClientSecretPost;
    let client = register(&fx, input);
    let tokens = exchange(
        &fx,
        client.post(),
        grant_request("client_credentials", None),
    )
    .unwrap();
    let bad = ClientAuthentication::Post {
        client_id: client.id.as_inner().to_string(),
        secret: Secret::new("wrong".to_owned()),
    };
    failed(&fx, bad, &access_of(&tokens));
    assert_eq!(kinds(&fx, AuditKind::ClientAuthenticationFailed).len(), 1);
    assert!(alive(&fx, &access_of(&tokens)));

    // Disabled client. disable_client itself revokes the grant (ClientDisabled), so "nothing
    // was revoked by the request" is judged by the grant.revoked count staying the same.
    block_on(fx.admin.disable_client(&ctx(), &client.id)).unwrap();
    let before = kinds(&fx, AuditKind::GrantRevoked).len();
    failed(&fx, client.post(), &access_of(&tokens));
    assert_eq!(kinds(&fx, AuditKind::ClientAuthenticationFailed).len(), 2);
    assert_eq!(kinds(&fx, AuditKind::GrantRevoked).len(), before);

    // A public client registered while allowed, then used with allow_public_clients = false.
    let mut cfg = config();
    cfg.allow_public_clients = true;
    let fx = Fixture::with_config(cfg);
    let mut input = confidential(&[GrantType::AuthorizationCode]);
    input.client_type = komainu_domain::ClientType::Public;
    input.auth_method = komainu_domain::TokenEndpointAuthMethod::None;
    let public = block_on(fx.admin.register_client(&ctx(), input)).unwrap();
    // Positive control: with public clients allowed the same call is accepted.
    let allowed = ClientAuthentication::PublicId {
        client_id: public.client.id.as_inner().to_string(),
    };
    revoke(&fx, allowed, request("some-token", None)).unwrap();
    assert!(kinds(&fx, AuditKind::ClientAuthenticationFailed).is_empty());
    let mut deps = fx.env.deps.clone();
    deps.config = std::sync::Arc::new(config());
    let strict = komainu_application::TokenService::new(deps);
    let auth = ClientAuthentication::PublicId {
        client_id: public.client.id.as_inner().to_string(),
    };
    let err = block_on(strict.revoke(&ctx(), auth, request("some-token", None))).unwrap_err();
    assert!(matches!(
        err,
        RevocationError::InvalidClient {
            basic_attempted: false
        }
    ));
    assert_eq!(kinds(&fx, AuditKind::ClientAuthenticationFailed).len(), 1);
    assert!(kinds(&fx, AuditKind::GrantRevoked).is_empty());
}

#[test]
fn missing_token_or_duplicates_are_invalid_requests() {
    let (fx, client, tokens) = setup();
    let missing = RevocationRequest::default();
    let err = revoke(&fx, client.basic(), missing).unwrap_err();
    assert!(matches!(err, RevocationError::InvalidRequest));
    let empty = RevocationRequest::from_pairs([("token".to_owned(), String::new())]);
    assert!(matches!(
        revoke(&fx, client.basic(), empty).unwrap_err(),
        RevocationError::InvalidRequest
    ));
    let t = access_of(&tokens);
    let dup = RevocationRequest::from_pairs([
        ("token".to_owned(), t.clone()),
        ("token".to_owned(), t.clone()),
    ]);
    assert!(matches!(
        revoke(&fx, client.basic(), dup).unwrap_err(),
        RevocationError::InvalidRequest
    ));
    let dup_hint = RevocationRequest::from_pairs([
        ("token".to_owned(), t.clone()),
        ("token_type_hint".to_owned(), "access_token".to_owned()),
        ("token_type_hint".to_owned(), "access_token".to_owned()),
    ]);
    assert!(matches!(
        revoke(&fx, client.basic(), dup_hint).unwrap_err(),
        RevocationError::InvalidRequest
    ));
    assert!(alive(&fx, &t));
}

#[test]
fn client_credentials_grant_can_be_revoked() {
    let fx = Fixture::new();
    let client = register(&fx, confidential(&ALL_GRANTS));
    let tokens = exchange(
        &fx,
        client.basic(),
        grant_request("client_credentials", None),
    )
    .unwrap();
    revoke(&fx, client.basic(), request(&access_of(&tokens), None)).unwrap();
    assert!(!alive(&fx, &access_of(&tokens)));
    assert_eq!(kinds(&fx, AuditKind::GrantRevoked).len(), 1);
}

#[test]
fn revocation_request_debug_redacts_the_token() {
    let debug = format!("{:?}", request("secret-token-value", Some("access_token")));
    assert!(!debug.contains("secret-token-value"));
    assert!(debug.contains("[REDACTED]"));
    assert!(debug.contains("access_token"));
}
