//! TokenService acceptance tests (application.md).

mod common;

use common::*;
use komainu_application::{AuditKind, TokenError, TokenRequest};
use komainu_domain::{ClientKeys, GrantType, ScopeSet};
use time::Duration;

/// Registers a client with all grants, a user, and returns an authorization code.
fn setup() -> (Fixture, Registered, String) {
    let fx = Fixture::new();
    let client = register(&fx, confidential(&ALL_GRANTS));
    create_user(&fx, "alice");
    let code = obtain_code(&fx, &client.id, "alice", &[("scope", "read write")]);
    (fx, client, code)
}

fn audit_kinds(fx: &Fixture) -> Vec<AuditKind> {
    fx.env.store.audit_events().iter().map(|e| e.kind).collect()
}

#[test]
fn token_request_debug_redacts_secrets() {
    let req = TokenRequest {
        grant_type: Some("authorization_code".to_owned()),
        code: Some("abc123".to_owned()),
        refresh_token: Some("rt-xyz".to_owned()),
        code_verifier: Some("v".repeat(43)),
        ..TokenRequest::default()
    };
    let text = format!("{req:?}");
    assert_eq!(
        text,
        "TokenRequest { grant_type: Some(\"authorization_code\"), code: Some([REDACTED]), \
         redirect_uri: None, scope: None, refresh_token: Some([REDACTED]), code_verifier: Some([REDACTED]), \
         assertion: None, \
         duplicated: [] }"
    );
    assert!(
        !text.contains("abc123") && !text.contains("rt-xyz") && !text.contains(&"v".repeat(43))
    );
}

#[test]
fn authorization_code_exchange_returns_tokens() {
    let (fx, client, code) = setup();
    let res = exchange(&fx, client.basic(), code_request(&code)).unwrap();
    assert_eq!(res.token_type, "Bearer");
    assert_eq!(res.expires_in, 3600);
    assert_eq!(res.scope.to_string(), "read write");
    assert!(res.refresh_token.is_some());
    let info = block_on(fx.token.verify_access_token(res.access_token.expose()))
        .unwrap()
        .expect("access token is valid");
    assert_eq!(info.client_id, client.id);
    assert!(info.subject.is_some());
    assert_no_verifier_in_audit(&fx);
}

fn assert_no_verifier_in_audit(fx: &Fixture) {
    for event in fx.env.store.audit_events() {
        for value in event.details.values() {
            assert!(!value.contains(CODE_VERIFIER) && !value.contains(&"b".repeat(43)));
        }
    }
}

#[test]
fn missing_code_verifier_is_invalid_request_and_keeps_the_code() {
    let (fx, client, code) = setup();
    let mut req = code_request(&code);
    req.code_verifier = None;
    assert!(matches!(
        exchange(&fx, client.basic(), req),
        Err(TokenError::InvalidRequest)
    ));
    assert!(exchange(&fx, client.basic(), code_request(&code)).is_ok());
    assert_no_verifier_in_audit(&fx);
}

#[test]
fn malformed_code_verifier_is_invalid_grant_and_keeps_the_code() {
    let (fx, client, code) = setup();
    for bad in [
        "a".repeat(42),
        "a".repeat(129),
        format!("{}!", "a".repeat(42)),
    ] {
        let mut req = code_request(&code);
        req.code_verifier = Some(bad);
        assert!(matches!(
            exchange(&fx, client.basic(), req),
            Err(TokenError::InvalidGrant)
        ));
    }
    assert!(exchange(&fx, client.basic(), code_request(&code)).is_ok());
}

#[test]
fn mismatched_code_verifier_is_invalid_grant_and_keeps_the_code() {
    let (fx, client, code) = setup();
    let mut req = code_request(&code);
    req.code_verifier = Some("b".repeat(43));
    assert!(matches!(
        exchange(&fx, client.basic(), req),
        Err(TokenError::InvalidGrant)
    ));
    let state = fx.env.store.state();
    assert!(state.grants.is_empty());
    assert!(state.access_tokens.is_empty() && state.refresh_tokens.is_empty());
    assert!(exchange(&fx, client.basic(), code_request(&code)).is_ok());
    assert_no_verifier_in_audit(&fx);
}

#[test]
fn replay_is_detected_before_the_pkce_check() {
    for verifier in [CODE_VERIFIER.to_owned(), "b".repeat(43)] {
        let (fx, client, code) = setup();
        let first = exchange(&fx, client.basic(), code_request(&code)).unwrap();
        let mut req = code_request(&code);
        req.code_verifier = Some(verifier);
        assert!(matches!(
            exchange(&fx, client.basic(), req),
            Err(TokenError::InvalidGrant)
        ));
        assert!(
            block_on(fx.token.verify_access_token(first.access_token.expose()))
                .unwrap()
                .is_none()
        );
        let kinds = audit_kinds(&fx);
        assert!(kinds.contains(&AuditKind::AuthorizationCodeReplayDetected));
        assert!(kinds.contains(&AuditKind::GrantRevoked));
        let revoked = fx
            .env
            .store
            .audit_events()
            .into_iter()
            .find(|e| e.kind == AuditKind::GrantRevoked)
            .unwrap();
        assert_eq!(revoked.details["reason"], "code_replay");
        assert_no_verifier_in_audit(&fx);
    }
}

#[test]
fn replay_without_a_valid_code_verifier_does_not_revoke() {
    let (fx, client, code) = setup();
    let first = exchange(&fx, client.basic(), code_request(&code)).unwrap();
    let events = fx.env.store.audit_events().len();
    let mut missing = code_request(&code);
    missing.code_verifier = None;
    assert!(matches!(
        exchange(&fx, client.basic(), missing),
        Err(TokenError::InvalidRequest)
    ));
    let mut malformed = code_request(&code);
    malformed.code_verifier = Some("short".to_owned());
    assert!(matches!(
        exchange(&fx, client.basic(), malformed),
        Err(TokenError::InvalidGrant)
    ));
    assert!(
        block_on(fx.token.verify_access_token(first.access_token.expose()))
            .unwrap()
            .is_some()
    );
    assert_eq!(fx.env.store.audit_events().len(), events);
}

#[test]
fn authorization_code_exchange_ignores_request_scope() {
    let (fx, client, code) = setup();
    let mut req = code_request(&code);
    req.scope = Some("write".to_owned());
    let res = exchange(&fx, client.basic(), req).unwrap();
    assert_eq!(res.scope.to_string(), "read write");
}

#[test]
fn code_replay_is_invalid_grant_and_revokes_grant() {
    let (fx, client, code) = setup();
    let first = exchange(&fx, client.basic(), code_request(&code)).unwrap();
    let err = exchange(&fx, client.basic(), code_request(&code)).unwrap_err();
    assert!(matches!(err, TokenError::InvalidGrant));
    assert!(
        block_on(fx.token.verify_access_token(first.access_token.expose()))
            .unwrap()
            .is_none()
    );
    let kinds = audit_kinds(&fx);
    assert!(kinds.contains(&AuditKind::AuthorizationCodeReplayDetected));
    assert!(kinds.contains(&AuditKind::GrantRevoked));
    let revoked = fx
        .env
        .store
        .audit_events()
        .into_iter()
        .find(|e| e.kind == AuditKind::GrantRevoked)
        .unwrap();
    assert_eq!(revoked.details["reason"], "code_replay");
}

#[test]
fn code_with_other_client_is_invalid_grant_and_stays_redeemable() {
    let (fx, client, code) = setup();
    let other = register(&fx, confidential(&ALL_GRANTS));
    let err = exchange(&fx, other.basic(), code_request(&code)).unwrap_err();
    assert!(matches!(err, TokenError::InvalidGrant));
    assert!(exchange(&fx, client.basic(), code_request(&code)).is_ok());
}

#[test]
fn code_errors_are_invalid_grant_or_invalid_request() {
    let (fx, client, code) = setup();
    let mut no_code = code_request(&code);
    no_code.code = None;
    assert!(matches!(
        exchange(&fx, client.basic(), no_code),
        Err(TokenError::InvalidRequest)
    ));
    let mut unknown = code_request(&code);
    unknown.code = Some("unknown".to_owned());
    assert!(matches!(
        exchange(&fx, client.basic(), unknown),
        Err(TokenError::InvalidGrant)
    ));
    let mut wrong_uri = code_request(&code);
    wrong_uri.redirect_uri = Some("https://evil.example/cb".to_owned());
    assert!(matches!(
        exchange(&fx, client.basic(), wrong_uri),
        Err(TokenError::InvalidGrant)
    ));
    fx.env.clock.advance(Duration::seconds(60));
    assert!(matches!(
        exchange(&fx, client.basic(), code_request(&code)),
        Err(TokenError::InvalidGrant)
    ));
}

#[test]
fn unknown_client_with_basic_is_invalid_client_basic_attempted() {
    let (fx, _client, code) = setup();
    let auth = komainu_application::ClientAuthentication::Basic {
        client_id: "no-such-client".to_owned(),
        secret: komainu_domain::Secret::new("x".to_owned()),
    };
    let err = exchange(&fx, auth, code_request(&code)).unwrap_err();
    assert!(matches!(
        err,
        TokenError::InvalidClient {
            basic_attempted: true
        }
    ));
    let err = exchange(
        &fx,
        komainu_application::ClientAuthentication::None,
        code_request(&code),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        TokenError::InvalidClient {
            basic_attempted: false
        }
    ));
    // The failures are audited with the presented method and id, but no secret.
    let events: Vec<_> = fx
        .env
        .store
        .audit_events()
        .into_iter()
        .filter(|e| e.kind == AuditKind::ClientAuthenticationFailed)
        .collect();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].details["method"], "client_secret_basic");
    assert_eq!(events[0].details["client_id_presented"], "no-such-client");
    assert_eq!(events[1].details["method"], "missing");
    assert_eq!(events[1].details["client_id_presented"], "null");
}

#[test]
fn wrong_auth_method_is_invalid_client() {
    let (fx, client, code) = setup();
    let err = exchange(&fx, client.post(), code_request(&code)).unwrap_err();
    assert!(matches!(
        err,
        TokenError::InvalidClient {
            basic_attempted: false
        }
    ));
}

#[test]
fn wrong_secret_and_disabled_client_are_invalid_client() {
    let (fx, client, code) = setup();
    let bad = komainu_application::ClientAuthentication::Basic {
        client_id: client.id.as_inner().to_string(),
        secret: komainu_domain::Secret::new("wrong".to_owned()),
    };
    assert!(matches!(
        exchange(&fx, bad, code_request(&code)),
        Err(TokenError::InvalidClient {
            basic_attempted: true
        })
    ));
    block_on(fx.admin.disable_client(&ctx(), &client.id)).unwrap();
    assert!(matches!(
        exchange(&fx, client.basic(), code_request(&code)),
        Err(TokenError::InvalidClient { .. })
    ));
}

#[test]
fn public_client_auth_requires_public_client_and_config() {
    let mut cfg = config();
    cfg.allow_public_clients = true;
    let fx = Fixture::with_config(cfg);
    let mut input = confidential(&[GrantType::AuthorizationCode]);
    input.client_type = komainu_domain::ClientType::Public;
    input.auth_method = komainu_domain::TokenEndpointAuthMethod::None;
    let public = block_on(fx.admin.register_client(&ctx(), input)).unwrap();
    assert!(public.secret.is_none());
    create_user(&fx, "alice");
    let code = obtain_code(&fx, &public.client.id, "alice", &[]);
    let id = public.client.id.as_inner().to_string();
    let ok = exchange(
        &fx,
        komainu_application::ClientAuthentication::PublicId { client_id: id },
        code_request(&code),
    );
    assert!(ok.is_ok());
    // A confidential client cannot authenticate with only its id.
    let conf = register(&fx, confidential(&ALL_GRANTS));
    let err = exchange(
        &fx,
        komainu_application::ClientAuthentication::PublicId {
            client_id: conf.id.as_inner().to_string(),
        },
        grant_request("client_credentials", None),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        TokenError::InvalidClient {
            basic_attempted: false
        }
    ));
}

#[test]
fn client_credentials_without_scope_and_default_is_invalid_scope() {
    let fx = Fixture::new();
    let mut input = confidential(&[GrantType::ClientCredentials]);
    input.redirect_uris.clear();
    input.default_scopes = ScopeSet::empty();
    let client = register(&fx, input);
    let err = exchange(
        &fx,
        client.basic(),
        grant_request("client_credentials", None),
    )
    .unwrap_err();
    assert!(matches!(err, TokenError::InvalidScope));
    let err = exchange(
        &fx,
        client.basic(),
        grant_request("client_credentials", Some("admin")),
    )
    .unwrap_err();
    assert!(matches!(err, TokenError::InvalidScope));
}

#[test]
fn client_credentials_has_no_refresh_token() {
    let fx = Fixture::new();
    let client = register(&fx, confidential(&ALL_GRANTS));
    let res = exchange(
        &fx,
        client.basic(),
        grant_request("client_credentials", Some("write")),
    )
    .unwrap();
    assert!(res.refresh_token.is_none());
    assert_eq!(res.scope.to_string(), "write");
    let info = block_on(fx.token.verify_access_token(res.access_token.expose()))
        .unwrap()
        .unwrap();
    assert!(info.subject.is_none());
}

#[test]
fn refresh_rotation_and_replay_detection() {
    let (fx, client, code) = setup();
    let first = exchange(&fx, client.basic(), code_request(&code)).unwrap();
    let old = first.refresh_token.unwrap();
    let second = exchange(&fx, client.basic(), refresh_request(old.expose(), None)).unwrap();
    assert!(second.refresh_token.is_some());
    assert!(
        block_on(fx.token.verify_access_token(second.access_token.expose()))
            .unwrap()
            .is_some()
    );
    let err = exchange(&fx, client.basic(), refresh_request(old.expose(), None)).unwrap_err();
    assert!(matches!(err, TokenError::InvalidGrant));
    assert!(
        block_on(fx.token.verify_access_token(second.access_token.expose()))
            .unwrap()
            .is_none()
    );
    let kinds = audit_kinds(&fx);
    assert!(kinds.contains(&AuditKind::RefreshTokenReplayDetected));
    assert!(kinds.contains(&AuditKind::GrantRevoked));
    // The new refresh token no longer works either.
    let new = second.refresh_token.unwrap();
    assert!(matches!(
        exchange(&fx, client.basic(), refresh_request(new.expose(), None)),
        Err(TokenError::InvalidGrant)
    ));
}

#[test]
fn refresh_scope_can_only_narrow_the_grant_scope() {
    let (fx, client, code) = setup();
    let first = exchange(&fx, client.basic(), code_request(&code)).unwrap();
    let rt = first.refresh_token.unwrap();
    let narrowed = exchange(
        &fx,
        client.basic(),
        refresh_request(rt.expose(), Some("read")),
    )
    .unwrap();
    assert_eq!(narrowed.scope.to_string(), "read");
    let rt2 = narrowed.refresh_token.unwrap();
    let widened = exchange(
        &fx,
        client.basic(),
        refresh_request(rt2.expose(), Some("write")),
    )
    .unwrap();
    assert_eq!(widened.scope.to_string(), "write");
    let rt3 = widened.refresh_token.unwrap();
    let err = exchange(
        &fx,
        client.basic(),
        refresh_request(rt3.expose(), Some("admin")),
    )
    .unwrap_err();
    assert!(matches!(err, TokenError::InvalidScope));
}

#[test]
fn refresh_token_of_other_client_is_invalid_grant() {
    let (fx, client, code) = setup();
    let other = register(&fx, confidential(&ALL_GRANTS));
    let first = exchange(&fx, client.basic(), code_request(&code)).unwrap();
    let rt = first.refresh_token.unwrap();
    assert!(matches!(
        exchange(&fx, other.basic(), refresh_request(rt.expose(), None)),
        Err(TokenError::InvalidGrant)
    ));
}

#[test]
fn unsupported_and_unauthorized_grant_types() {
    let fx = Fixture::new();
    let client = register(&fx, confidential(&[GrantType::AuthorizationCode]));
    assert!(matches!(
        exchange(&fx, client.basic(), grant_request("password", None)),
        Err(TokenError::UnsupportedGrantType)
    ));
    assert!(matches!(
        exchange(
            &fx,
            client.basic(),
            grant_request("client_credentials", None)
        ),
        Err(TokenError::UnauthorizedClient)
    ));
    assert!(matches!(
        exchange(&fx, client.basic(), TokenRequest::default()),
        Err(TokenError::InvalidRequest)
    ));
    let mut dup = grant_request("client_credentials", None);
    dup.duplicated.push("scope");
    assert!(matches!(
        exchange(&fx, client.basic(), dup),
        Err(TokenError::InvalidRequest)
    ));
}

#[test]
fn token_error_codes() {
    assert_eq!(TokenError::InvalidRequest.code(), "invalid_request");
    assert_eq!(
        TokenError::InvalidClient {
            basic_attempted: true
        }
        .code(),
        "invalid_client"
    );
    assert_eq!(TokenError::InvalidGrant.code(), "invalid_grant");
    assert_eq!(TokenError::UnauthorizedClient.code(), "unauthorized_client");
    assert_eq!(
        TokenError::UnsupportedGrantType.code(),
        "unsupported_grant_type"
    );
    assert_eq!(TokenError::InvalidScope.code(), "invalid_scope");
    assert_eq!(
        TokenError::Server(komainu_application::StoreError::Conflict).code(),
        "server_error"
    );
}

#[test]
fn access_token_expires_exactly_at_ttl() {
    let fx = Fixture::new();
    let client = register(&fx, confidential(&ALL_GRANTS));
    let res = exchange(
        &fx,
        client.basic(),
        grant_request("client_credentials", None),
    )
    .unwrap();
    let token = res.access_token.expose().to_owned();
    fx.env.clock.advance(Duration::seconds(3599));
    assert!(
        block_on(fx.token.verify_access_token(&token))
            .unwrap()
            .is_some()
    );
    fx.env.clock.advance(Duration::seconds(1));
    assert!(
        block_on(fx.token.verify_access_token(&token))
            .unwrap()
            .is_none()
    );
    assert!(
        block_on(fx.token.verify_access_token("garbage token"))
            .unwrap()
            .is_none()
    );
}

/// Checks that the latest `token.issued` event is the only new one, carries the design's
/// details, and holds neither the plaintext nor the hash of any issued token or credential.
fn assert_token_issued(
    fx: &Fixture,
    expected_count: usize,
    res: &komainu_application::TokenResponse,
    grant_type: &str,
    scope: &str,
    refresh_issued: bool,
    extra_secrets: &[&str],
) {
    let issued: Vec<_> = fx
        .env
        .store
        .audit_events()
        .into_iter()
        .filter(|e| e.kind == AuditKind::TokenIssued)
        .collect();
    assert_eq!(issued.len(), expected_count);
    let event = issued.last().unwrap();
    assert_eq!(event.details["grant_type"], grant_type);
    assert_eq!(event.details["scope"], scope);
    assert_eq!(
        event.details["refresh_token_issued"],
        if refresh_issued { "true" } else { "false" }
    );
    assert!(event.details.contains_key("grant_id"));
    assert_eq!(res.refresh_token.is_some(), refresh_issued);
    let dump = format!("{event:?}");
    let mut secrets = vec![res.access_token.expose()];
    secrets.extend(res.refresh_token.as_ref().map(|t| t.expose()));
    secrets.extend_from_slice(extra_secrets);
    for secret in secrets {
        assert!(!dump.contains(secret));
    }
    let hex = |hash: komainu_domain::TokenHash| {
        hash.as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    assert!(!dump.contains(&hex(res.access_token.hash())));
    if let Some(refresh) = &res.refresh_token {
        assert!(!dump.contains(&hex(refresh.hash())));
    }
}

#[test]
fn token_issued_audit_has_no_secret_values() {
    let (fx, client, code) = setup();
    let res = exchange(&fx, client.basic(), code_request(&code)).unwrap();
    assert_token_issued(
        &fx,
        1,
        &res,
        "authorization_code",
        "read write",
        true,
        &[code.as_str(), client.secret.expose()],
    );
}

#[test]
fn token_issued_audit_for_refresh_and_client_credentials() {
    let (fx, client, code) = setup();
    let first = exchange(&fx, client.basic(), code_request(&code)).unwrap();
    let refresh = first.refresh_token.as_ref().unwrap().expose().to_owned();
    let second = exchange(&fx, client.basic(), refresh_request(&refresh, None)).unwrap();
    assert_token_issued(
        &fx,
        2,
        &second,
        "refresh_token",
        "read write",
        true,
        &[refresh.as_str(), client.secret.expose()],
    );
    let third = exchange(
        &fx,
        client.basic(),
        grant_request("client_credentials", Some("read")),
    )
    .unwrap();
    assert_token_issued(
        &fx,
        3,
        &third,
        "client_credentials",
        "read",
        false,
        &[client.secret.expose()],
    );
}

#[test]
fn exchange_futures_are_send() {
    let fx = Fixture::new();
    let client = register(&fx, confidential(&ALL_GRANTS));
    assert_send(
        &fx.token
            .exchange(&ctx(), client.basic(), TokenRequest::default()),
    );
    assert_send(&fx.token.verify_access_token("x"));
}

// ---- private_key_jwt (F-2, F-3) ----

fn cc_request() -> TokenRequest {
    grant_request("client_credentials", Some("read"))
}

fn token_with(
    fx: &Fixture,
    auth: komainu_application::ClientAuthentication,
) -> Result<komainu_application::TokenResponse, TokenError> {
    exchange(fx, auth, cc_request())
}

#[test]
fn private_key_jwt_authenticates_and_replay_is_rejected() {
    let (fx, _) = assertion_fixture();
    let key = key_with_kid("k1");
    let id = register_private_key_jwt(&fx, jwks_keys(&[&key]));
    let jwt = assertion(&fx, &key, &id, "jti-1");
    let res = token_with(&fx, assertion_auth(Some(&id), jwt.clone())).unwrap();
    assert_eq!(res.token_type, "Bearer");
    // The same assertion a second time is a replay.
    let err = token_with(&fx, assertion_auth(None, jwt)).unwrap_err();
    assert!(matches!(
        err,
        TokenError::InvalidClient {
            basic_attempted: false
        }
    ));
    assert_eq!(failure_reasons(&fx), ["replay"]);
    let event = &fx.env.store.audit_events().into_iter().last().unwrap();
    assert_eq!(
        event.details.get("method").map(String::as_str),
        Some("private_key_jwt")
    );
}

#[test]
fn a_failed_request_keeps_the_client_assertion_jti() {
    let (fx, _) = assertion_fixture();
    let key = key_with_kid("k1");
    let id = register_private_key_jwt(&fx, jwks_keys(&[&key]));
    let jwt = assertion(&fx, &key, &id, "jti-1");
    let err = exchange(
        &fx,
        assertion_auth(Some(&id), jwt.clone()),
        grant_request("client_credentials", Some("unknown-scope")),
    )
    .unwrap_err();
    assert!(matches!(err, TokenError::InvalidScope));
    // The jti was committed when the client was authenticated (D-3).
    let err = token_with(&fx, assertion_auth(Some(&id), jwt)).unwrap_err();
    assert!(matches!(err, TokenError::InvalidClient { .. }));
    assert_eq!(failure_reasons(&fx), ["replay"]);
}

#[test]
fn private_key_jwt_failures_are_audited_with_a_reason() {
    let (fx, fetcher) = assertion_fixture();
    let key = key_with_kid("k1");
    let other = key_with_kid("k1");
    let id = register_private_key_jwt(&fx, jwks_keys(&[&key]));
    let secret_client = register(&fx, confidential(&ALL_GRANTS));
    let invalid = |r: Result<_, TokenError>| {
        assert!(matches!(r, Err(TokenError::InvalidClient { .. })), "{r:?}")
    };
    let cid = id.as_inner();
    // Signature by another key.
    invalid(token_with(
        &fx,
        assertion_auth(None, assertion_with(&fx, &other, cid, cid, "a", ISSUER, 60)),
    ));
    // iss != sub.
    invalid(token_with(
        &fx,
        assertion_auth(None, assertion_with(&fx, &key, cid, "x", "b", ISSUER, 60)),
    ));
    // Unknown client.
    invalid(token_with(
        &fx,
        assertion_auth(
            None,
            assertion_with(&fx, &key, "nobody", "nobody", "c", ISSUER, 60),
        ),
    ));
    // Wrong audience.
    invalid(token_with(
        &fx,
        assertion_auth(
            None,
            assertion_with(&fx, &key, cid, cid, "d", "https://x", 60),
        ),
    ));
    // Not a JWT.
    invalid(token_with(&fx, assertion_auth(None, "garbage".to_owned())));
    // A client using another method.
    let sid = secret_client.id.as_inner();
    invalid(token_with(
        &fx,
        assertion_auth(None, assertion_with(&fx, &key, sid, sid, "e", ISSUER, 60)),
    ));
    assert_eq!(
        failure_reasons(&fx),
        [
            "signature",
            "subject_mismatch",
            "unknown_client",
            "audience",
            "malformed",
            "method_not_allowed"
        ]
    );
    // Disabled client.
    block_on(fx.admin.disable_client(&ctx(), &id)).unwrap();
    invalid(token_with(
        &fx,
        assertion_auth(None, assertion_with(&fx, &key, cid, cid, "f", ISSUER, 60)),
    ));
    assert_eq!(failure_reasons(&fx).last().unwrap(), "client_disabled");
    // No fetch happened for a jwks client.
    assert_eq!(fetcher.calls(&jwks_uri()), 0);
}

#[test]
fn private_key_jwt_client_id_mismatch_is_invalid_request() {
    let (fx, _) = assertion_fixture();
    let key = key_with_kid("k1");
    let id = register_private_key_jwt(&fx, jwks_keys(&[&key]));
    let other = register(&fx, confidential(&ALL_GRANTS));
    let jwt = assertion(&fx, &key, &id, "j");
    let err = token_with(&fx, assertion_auth(Some(&other.id), jwt)).unwrap_err();
    assert!(matches!(err, TokenError::InvalidRequest));
    assert!(failure_reasons(&fx).is_empty());
}

#[test]
fn private_key_jwt_without_issuer_is_not_configured() {
    let fx = Fixture::new();
    let key = key_with_kid("k1");
    let id = register_private_key_jwt(&fx, jwks_keys(&[&key]));
    let jwt = assertion(&fx, &key, &id, "j");
    assert!(token_with(&fx, assertion_auth(None, jwt)).is_err());
    assert_eq!(failure_reasons(&fx), ["not_configured"]);
}

#[test]
fn jwks_uri_client_fetches_and_refreshes_on_unknown_kid() {
    let (fx, fetcher) = assertion_fixture();
    let old = key_with_kid("old");
    let new = key_with_kid("new");
    let uri = jwks_uri();
    fetcher.set(&uri, Ok(jwks_json(&[&old])));
    let id = register_private_key_jwt(&fx, ClientKeys::JwksUri(uri.clone()));
    token_with(&fx, assertion_auth(None, assertion(&fx, &old, &id, "1"))).unwrap();
    assert_eq!(fetcher.calls(&uri), 1);
    // The key is rotated; within a minute of the last fetch no refetch is allowed.
    fetcher.set(&uri, Ok(jwks_json(&[&new])));
    let r = token_with(&fx, assertion_auth(None, assertion(&fx, &new, &id, "2")));
    assert!(r.is_err());
    assert_eq!(fetcher.calls(&uri), 1);
    // After 60 seconds the unknown kid triggers one refetch.
    fx.env.clock.advance(Duration::seconds(61));
    token_with(&fx, assertion_auth(None, assertion(&fx, &new, &id, "3"))).unwrap();
    assert_eq!(fetcher.calls(&uri), 2);
}

#[test]
fn jwks_uri_fetch_failure_is_key_fetch_failed() {
    let (fx, _) = assertion_fixture();
    let key = key_with_kid("k");
    let id = register_private_key_jwt(&fx, ClientKeys::JwksUri(jwks_uri()));
    // The URI has no configured response (404).
    assert!(token_with(&fx, assertion_auth(None, assertion(&fx, &key, &id, "1"))).is_err());
    assert_eq!(failure_reasons(&fx), ["key_fetch_failed"]);
    // Without a fetcher such a client cannot be registered (tests/admin.rs).
}

#[test]
fn issuer_with_a_trailing_slash_accepts_the_advertised_audiences() {
    let (fx, _) = assertion_fixture_with_issuer(&format!("{ISSUER}/"));
    let key = key_with_kid("k1");
    let id = register_private_key_jwt(&fx, jwks_keys(&[&key]));
    let cid = id.as_inner();
    for (jti, aud) in [("a", ISSUER.to_owned()), ("b", format!("{ISSUER}/token"))] {
        let jwt = assertion_with(&fx, &key, cid, cid, jti, &aud, 60);
        token_with(&fx, assertion_auth(None, jwt)).unwrap();
    }
}

#[test]
fn assertion_with_token_endpoint_audience_is_accepted() {
    let (fx, _) = assertion_fixture();
    let key = key_with_kid("k1");
    let id = register_private_key_jwt(&fx, jwks_keys(&[&key]));
    let cid = id.as_inner();
    let aud = format!("{ISSUER}/token");
    let jwt = assertion_with(&fx, &key, cid, cid, "aud-token", &aud, 60);
    token_with(&fx, assertion_auth(None, jwt)).unwrap();
    assert!(failure_reasons(&fx).is_empty());
}

#[test]
fn revocation_endpoint_audience_is_accepted_only_at_revoke() {
    let (fx, _) = assertion_fixture();
    let key = key_with_kid("k1");
    let id = register_private_key_jwt(&fx, jwks_keys(&[&key]));
    let cid = id.as_inner();
    let aud = format!("{ISSUER}/revoke");
    let jwt = assertion_with(&fx, &key, cid, cid, "aud-revoke-1", &aud, 60);
    assert!(token_with(&fx, assertion_auth(None, jwt)).is_err());
    assert_eq!(failure_reasons(&fx), ["audience"]);
    let jwt = assertion_with(&fx, &key, cid, cid, "aud-revoke-2", &aud, 60);
    let request = komainu_application::RevocationRequest {
        token: Some("unknown-token".to_owned()),
        ..komainu_application::RevocationRequest::default()
    };
    block_on(fx.token.revoke(&ctx(), assertion_auth(None, jwt), request)).unwrap();
    assert_eq!(failure_reasons(&fx), ["audience"]);
}

#[test]
fn assertion_debug_never_shows_the_body() {
    let body = "eyJhbGciOiJFUzI1NiJ9.SECRET-BODY.sig";
    let req = TokenRequest {
        assertion: Some(body.to_owned()),
        ..TokenRequest::default()
    };
    let text = format!("{req:?}");
    assert!(!text.contains("SECRET-BODY"), "{text}");
    assert!(text.contains("assertion: Some([REDACTED])"), "{text}");
    let auth = komainu_application::ClientAuthentication::Assertion {
        client_id: Some("c".to_owned()),
        assertion: komainu_domain::Secret::new(body.to_owned()),
    };
    assert!(!format!("{auth:?}").contains("SECRET-BODY"));
}

#[test]
fn unsigned_and_expired_assertions_are_rejected_with_reasons() {
    use base64::Engine;
    use komainu_application::Clock;
    let (fx, _) = assertion_fixture();
    let key = key_with_kid("k1");
    let id = register_private_key_jwt(&fx, jwks_keys(&[&key]));
    let cid = id.as_inner();
    // alg=none with every claim valid: only the missing signature can reject it.
    let exp = fx.env.clock.now().unix_timestamp() + 60;
    let payload =
        format!(r#"{{"iss":"{cid}","sub":"{cid}","aud":"{ISSUER}","exp":{exp},"jti":"none-1"}}"#);
    let none = format!(
        "{}.{}.",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload),
    );
    assert!(matches!(
        token_with(&fx, assertion_auth(Some(&id), none)),
        Err(TokenError::InvalidClient { .. })
    ));
    // Expired beyond the leeway.
    let expired = assertion_with(&fx, &key, cid, cid, "old", ISSUER, -300);
    assert!(matches!(
        token_with(&fx, assertion_auth(None, expired)),
        Err(TokenError::InvalidClient { .. })
    ));
    let reasons = failure_reasons(&fx);
    assert_eq!(reasons.len(), 2);
    assert_eq!(reasons[1], "expired");
    assert!(
        ["malformed", "signature"].contains(&reasons[0].as_str()),
        "{reasons:?}"
    );
}

// ---- jwt-bearer grant (F-10, F-11) ----

mod jwt_bearer {
    use super::*;
    use komainu_application::{ClientAuthentication, RegisterClient, RegisterIssuer};
    use komainu_domain::{
        ClientId, ExternalSubject, IssuerId, Subject, TrustedIssuerUpdate, UserId, Username,
    };
    use komainu_jose::SigningKey;

    const IDP: &str = "https://idp.example.com";
    const GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

    /// A confidential client without redirect URIs (no authorization_code grant).
    fn bearer(grant_types: &[GrantType]) -> RegisterClient {
        RegisterClient {
            redirect_uris: vec![],
            ..confidential(grant_types)
        }
    }

    struct Env {
        fx: Fixture,
        client: Registered,
        key: SigningKey,
        user_id: UserId,
    }

    fn setup() -> Env {
        let (fx, _) = assertion_fixture();
        let grants = [GrantType::JwtBearer, GrantType::ClientCredentials];
        let client = register(&fx, bearer(&grants));
        let key = key_with_kid("idp-1");
        block_on(fx.admin.register_issuer(
            &ctx(),
            RegisterIssuer {
                id: IssuerId::try_new(IDP.to_owned()).unwrap(),
                jwks: jwks_document(&key),
                allowed_clients: [client.id.clone()].into(),
            },
        ))
        .unwrap();
        create_user(&fx, "alice");
        let mapping = map(&fx, "u-1", "alice");
        Env {
            fx,
            client,
            key,
            user_id: mapping,
        }
    }

    fn jwks_document(key: &SigningKey) -> komainu_domain::JwksDocument {
        komainu_domain::JwksDocument::try_new(jwks_json(&[key])).unwrap()
    }

    fn map(fx: &Fixture, subject: &str, username: &str) -> UserId {
        block_on(fx.admin.map_subject(
            &ctx(),
            &IssuerId::try_new(IDP.to_owned()).unwrap(),
            ExternalSubject::try_new(subject.to_owned()).unwrap(),
            &Username::try_new(username.to_owned()).unwrap(),
        ))
        .unwrap()
        .user_id
    }

    fn request(assertion: String) -> TokenRequest {
        TokenRequest {
            assertion: Some(assertion),
            ..grant_request(GRANT, None)
        }
    }

    fn good(env: &Env, jti: &str) -> String {
        assertion_with(&env.fx, &env.key, IDP, "u-1", jti, ISSUER, 60)
    }

    fn rejected(fx: &Fixture) -> Vec<(String, String)> {
        fx.env
            .store
            .audit_events()
            .into_iter()
            .filter(|e| e.kind == AuditKind::AssertionRejected)
            .map(|e| {
                (
                    e.details
                        .get("issuer_presented")
                        .cloned()
                        .unwrap_or_default(),
                    e.details.get("reason").cloned().unwrap_or_default(),
                )
            })
            .collect()
    }

    /// Resolves every subject to the user `alice`, ignoring the mapping table.
    struct AliceResolver;

    impl komainu_application::AssertionSubjectResolver for AliceResolver {
        fn resolve<'a>(
            &'a self,
            uow: &'a mut dyn komainu_application::UnitOfWork,
            _issuer: &'a komainu_domain::TrustedIssuer,
            _subject: &'a ExternalSubject,
        ) -> komainu_application::BoxFuture<
            'a,
            Result<Option<UserId>, komainu_application::StoreError>,
        > {
            Box::pin(async move {
                let name = Username::try_new("alice".to_owned()).unwrap();
                Ok(uow.users().find_by_username(&name).await?.map(|u| *u.id()))
            })
        }
    }

    #[test]
    fn a_fake_subject_resolver_works_without_a_mapping_table() {
        let test_env = komainu_testkit::TestEnv::new(config().with_issuer(ISSUER))
            .with_subject_resolver(std::sync::Arc::new(AliceResolver));
        let deps = test_env.deps.clone();
        let fx = Fixture {
            admin: komainu_application::AdminService::new(deps.clone()),
            authz: komainu_application::AuthorizationService::new(deps.clone()),
            token: komainu_application::TokenService::new(deps.clone()),
            maintenance: komainu_application::MaintenanceService::new(deps),
            env: test_env,
        };
        let client = register(&fx, bearer(&[GrantType::JwtBearer]));
        let key = key_with_kid("idp-1");
        block_on(fx.admin.register_issuer(
            &ctx(),
            RegisterIssuer {
                id: IssuerId::try_new(IDP.to_owned()).unwrap(),
                jwks: jwks_document(&key),
                allowed_clients: [client.id.clone()].into(),
            },
        ))
        .unwrap();
        create_user(&fx, "alice");
        let jwt = assertion_with(&fx, &key, IDP, "anyone", "j1", ISSUER, 60);
        let res = exchange(&fx, client.basic(), request(jwt)).unwrap();
        assert!(res.refresh_token.is_none());
    }

    #[test]
    fn issues_an_access_token_for_the_mapped_user() {
        let env = setup();
        let res = exchange(&env.fx, env.client.basic(), request(good(&env, "j1"))).unwrap();
        assert!(res.refresh_token.is_none());
        assert_eq!(res.scope, scopes("read"));
        let info = block_on(env.fx.token.verify_access_token(res.access_token.expose()))
            .unwrap()
            .unwrap();
        assert_eq!(info.subject, Some(Subject::from(env.user_id)));
        assert_eq!(info.client_id, env.client.id);
        let issued = env
            .fx
            .env
            .store
            .audit_events()
            .into_iter()
            .find(|e| e.kind == AuditKind::TokenIssued)
            .unwrap();
        assert_eq!(issued.details.get("issuer").map(String::as_str), Some(IDP));
        assert_eq!(
            issued.details.get("grant_type").map(String::as_str),
            Some(GRANT)
        );
        // An explicit scope is honoured; one the client may not use is invalid_scope.
        let mut write = request(good(&env, "j2"));
        write.scope = Some("write".to_owned());
        let res = exchange(&env.fx, env.client.basic(), write).unwrap();
        assert_eq!(res.scope, scopes("write"));
        let mut admin = request(good(&env, "j3"));
        admin.scope = Some("admin".to_owned());
        let err = exchange(&env.fx, env.client.basic(), admin).unwrap_err();
        assert!(matches!(err, TokenError::InvalidScope));
        assert!(rejected(&env.fx).is_empty());
    }

    #[test]
    fn rejections_are_invalid_grant_with_a_reason() {
        let env = setup();
        let fx = &env.fx;
        let other = key_with_kid("idp-1");
        let cases: Vec<(String, &str)> = vec![
            (
                assertion_with(fx, &other, IDP, "u-1", "a", ISSUER, 60),
                "signature",
            ),
            (
                assertion_with(fx, &env.key, IDP, "u-1", "b", "https://x", 60),
                "audience",
            ),
            (
                assertion_with(fx, &env.key, IDP, "u-1", "c", ISSUER, -300),
                "expired",
            ),
            (
                assertion_with(fx, &env.key, IDP, "nobody", "d", ISSUER, 60),
                "unknown_subject",
            ),
            (
                assertion_with(
                    fx,
                    &env.key,
                    "https://other.example.com",
                    "u-1",
                    "e",
                    ISSUER,
                    60,
                ),
                "unknown_issuer",
            ),
            ("garbage".to_owned(), "malformed"),
        ];
        let mut expected = Vec::new();
        for (jwt, reason) in cases {
            let err = exchange(fx, env.client.basic(), request(jwt.clone())).unwrap_err();
            assert!(matches!(err, TokenError::InvalidGrant), "{reason}: {err:?}");
            let presented = match reason {
                "unknown_issuer" => "https://other.example.com",
                "malformed" => "",
                _ => IDP,
            };
            expected.push((presented.to_owned(), reason.to_owned()));
        }
        // A "malformed" assertion presents no issuer: it is recorded as "null".
        expected[5].0 = "null".to_owned();
        assert_eq!(rejected(fx), expected);
        // Nothing was issued and no jti of a rejected assertion was consumed.
        assert!(!audit_kinds(fx).contains(&AuditKind::TokenIssued));
    }

    #[test]
    fn replay_issuer_state_and_user_state_are_rejected() {
        let env = setup();
        let fx = &env.fx;
        let jwt = good(&env, "r1");
        exchange(fx, env.client.basic(), request(jwt.clone())).unwrap();
        let err = exchange(fx, env.client.basic(), request(jwt)).unwrap_err();
        assert!(matches!(err, TokenError::InvalidGrant));
        // Disabled issuer.
        let id = IssuerId::try_new(IDP.to_owned()).unwrap();
        block_on(fx.admin.disable_issuer(&ctx(), &id)).unwrap();
        let err = exchange(fx, env.client.basic(), request(good(&env, "r2"))).unwrap_err();
        assert!(matches!(err, TokenError::InvalidGrant));
        block_on(fx.admin.enable_issuer(&ctx(), &id)).unwrap();
        // The issuer no longer allows the client.
        let other = register(fx, bearer(&[GrantType::JwtBearer]));
        block_on(fx.admin.update_issuer(
            &ctx(),
            &id,
            TrustedIssuerUpdate {
                allowed_clients: Some([other.id.clone()].into()),
                ..Default::default()
            },
        ))
        .unwrap();
        let err = exchange(fx, env.client.basic(), request(good(&env, "r3"))).unwrap_err();
        assert!(matches!(err, TokenError::InvalidGrant));
        // Disabled user.
        block_on(
            fx.admin
                .disable_user(&ctx(), &Username::try_new("alice".to_owned()).unwrap()),
        )
        .unwrap();
        let err = exchange(fx, other.basic(), request(good(&env, "r4"))).unwrap_err();
        assert!(matches!(err, TokenError::InvalidGrant));
        let reasons: Vec<_> = rejected(fx).into_iter().map(|r| r.1).collect();
        assert_eq!(
            reasons,
            [
                "replay",
                "issuer_disabled",
                "client_not_allowed",
                "user_disabled"
            ]
        );
    }

    #[test]
    fn missing_assertion_and_missing_grant_are_not_audited_as_rejections() {
        let env = setup();
        let fx = &env.fx;
        let err = exchange(fx, env.client.basic(), grant_request(GRANT, None)).unwrap_err();
        assert!(matches!(err, TokenError::InvalidRequest));
        let secret_only = register(fx, bearer(&[GrantType::ClientCredentials]));
        let err = exchange(fx, secret_only.basic(), request(good(&env, "m1"))).unwrap_err();
        assert!(matches!(err, TokenError::UnauthorizedClient));
        assert!(rejected(fx).is_empty());
    }

    #[test]
    fn unsupported_without_an_issuer() {
        let fx = Fixture::new();
        let client = register(&fx, bearer(&[GrantType::ClientCredentials]));
        let err = exchange(&fx, client.basic(), request("x".to_owned())).unwrap_err();
        assert!(matches!(err, TokenError::UnsupportedGrantType));
    }

    #[test]
    fn a_rejected_grant_keeps_the_client_assertion_jti() {
        let (fx, _) = assertion_fixture();
        let client_key = key_with_kid("c1");
        let idp_key = key_with_kid("idp-1");
        let client_id: ClientId = block_on(fx.admin.register_client(
            &ctx(),
            RegisterClient {
                grant_types: grants(&[GrantType::JwtBearer]),
                redirect_uris: vec![],
                ..private_key_jwt(jwks_keys(&[&client_key]))
            },
        ))
        .unwrap()
        .client
        .id;
        block_on(fx.admin.register_issuer(
            &ctx(),
            RegisterIssuer {
                id: IssuerId::try_new(IDP.to_owned()).unwrap(),
                jwks: jwks_document(&idp_key),
                allowed_clients: [client_id.clone()].into(),
            },
        ))
        .unwrap();
        create_user(&fx, "alice");
        map(&fx, "u-1", "alice");
        let auth = |jti: &str| -> ClientAuthentication {
            assertion_auth(
                Some(&client_id),
                assertion(&fx, &client_key, &client_id, jti),
            )
        };
        let bad = assertion_with(&fx, &idp_key, IDP, "nobody", "g1", ISSUER, 60);
        let err = exchange(&fx, auth("same-client-jti"), request(bad)).unwrap_err();
        assert!(matches!(err, TokenError::InvalidGrant));
        // The client assertion stays used although the request failed (D-3).
        let ok = assertion_with(&fx, &idp_key, IDP, "u-1", "g2", ISSUER, 60);
        let err = exchange(&fx, auth("same-client-jti"), request(ok.clone())).unwrap_err();
        assert!(matches!(err, TokenError::InvalidClient { .. }));
        assert_eq!(failure_reasons(&fx), ["replay"]);
        // A scope error is found before the grant assertion's jti is recorded.
        let mut bad_scope = request(ok.clone());
        bad_scope.scope = Some("unknown-scope".to_owned());
        let err = exchange(&fx, auth("client-jti-2"), bad_scope).unwrap_err();
        assert!(matches!(err, TokenError::InvalidScope));
        exchange(&fx, auth("client-jti-3"), request(ok)).unwrap();
        assert_eq!(rejected(&fx).len(), 1);
    }

    #[test]
    fn disabling_the_user_revokes_jwt_bearer_grants() {
        let env = setup();
        let res = exchange(&env.fx, env.client.basic(), request(good(&env, "d1"))).unwrap();
        block_on(
            env.fx
                .admin
                .disable_user(&ctx(), &Username::try_new("alice".to_owned()).unwrap()),
        )
        .unwrap();
        assert!(
            block_on(env.fx.token.verify_access_token(res.access_token.expose()))
                .unwrap()
                .is_none()
        );
    }
}
