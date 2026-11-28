//! Acceptance tests of `disabled_grant_types` / `disabled_auth_methods`
//! (extension-points.md §無効化).

mod common;

use std::sync::Arc;

use common::*;
use komainu_application::{
    AdminError, AdminService, ApplicationConfig, ApplicationConfigError, AuditKind,
    ClientAuthentication, RevocationError, RevocationRequest, ServerCapabilities, TokenError,
    TokenService,
};
use komainu_domain::{GrantType, TokenEndpointAuthMethod};

/// Services over the fixture's store but with a different configuration. Clients are
/// registered through the fixture first, so that disabling does not affect them.
fn with_config(fx: &Fixture, config: ApplicationConfig) -> (TokenService, AdminService) {
    let mut deps = fx.env.deps.clone();
    deps.config = Arc::new(config);
    (TokenService::new(deps.clone()), AdminService::new(deps))
}

fn exchange_with(
    token: &TokenService,
    auth: ClientAuthentication,
    request: komainu_application::TokenRequest,
) -> Result<komainu_application::TokenResponse, TokenError> {
    block_on(token.exchange(&ctx(), auth, request))
}

#[test]
fn disabled_client_credentials() {
    let cfg = config().with_disabled_grant_types(grants(&[GrantType::ClientCredentials]));
    let caps = ServerCapabilities::from_config(&cfg);
    assert_eq!(
        caps.grant_types,
        [GrantType::AuthorizationCode, GrantType::RefreshToken]
    );

    let fx = Fixture::new();
    let client = register(&fx, confidential(&ALL_GRANTS));
    let (token, admin) = with_config(&fx, cfg);
    let err = exchange_with(
        &token,
        client.basic(),
        grant_request("client_credentials", None),
    )
    .unwrap_err();
    assert!(matches!(err, TokenError::UnsupportedGrantType));

    let err = block_on(admin.register_client(&ctx(), confidential(&ALL_GRANTS))).unwrap_err();
    assert!(matches!(
        err,
        AdminError::GrantTypeDisabled(GrantType::ClientCredentials)
    ));
}

#[test]
fn disabled_grant_is_refused_before_client_authentication() {
    let fx = Fixture::new();
    let (token, _) = with_config(
        &fx,
        config().with_disabled_grant_types(grants(&[GrantType::ClientCredentials])),
    );
    let bad = ClientAuthentication::None;
    let err = exchange_with(&token, bad, grant_request("client_credentials", None)).unwrap_err();
    assert!(matches!(err, TokenError::UnsupportedGrantType));
    assert!(fx.env.store.audit_events().is_empty());
}

#[test]
fn updating_a_client_checks_disabled_settings() {
    let fx = Fixture::new();
    let client = register(&fx, confidential(&[GrantType::AuthorizationCode]));
    let (_, admin) = with_config(
        &fx,
        config()
            .with_disabled_grant_types(grants(&[GrantType::ClientCredentials]))
            .with_disabled_auth_methods([TokenEndpointAuthMethod::ClientSecretPost].into()),
    );
    let update = |f: &dyn Fn(&mut komainu_domain::ClientUpdate)| {
        let mut u = komainu_domain::ClientUpdate::default();
        f(&mut u);
        block_on(admin.update_client(&ctx(), &client.id, u)).unwrap_err()
    };
    let err = update(&|u| u.grant_types = Some(grants(&[GrantType::ClientCredentials])));
    assert!(matches!(
        err,
        AdminError::GrantTypeDisabled(GrantType::ClientCredentials)
    ));
    let err = update(&|u| u.auth_method = Some(TokenEndpointAuthMethod::ClientSecretPost));
    assert!(matches!(
        err,
        AdminError::AuthMethodDisabled(TokenEndpointAuthMethod::ClientSecretPost)
    ));
}

#[test]
fn disabled_refresh_token_is_not_issued_and_not_accepted() {
    let fx = Fixture::new();
    let client = register(&fx, confidential(&ALL_GRANTS));
    create_user(&fx, "alice");
    let code = obtain_code(&fx, &client.id, "alice", &[("scope", "read")]);
    let (token, _) = with_config(
        &fx,
        config().with_disabled_grant_types(grants(&[GrantType::RefreshToken])),
    );
    let response = exchange_with(&token, client.basic(), code_request(&code)).unwrap();
    assert!(response.refresh_token.is_none());

    let err = exchange_with(&token, client.basic(), refresh_request("whatever", None)).unwrap_err();
    assert!(matches!(err, TokenError::UnsupportedGrantType));
    assert_eq!(
        ServerCapabilities::from_config(
            &config().with_disabled_grant_types(grants(&[GrantType::RefreshToken]))
        )
        .grant_types,
        [GrantType::AuthorizationCode, GrantType::ClientCredentials]
    );
}

#[test]
fn disabled_client_secret_post() {
    let cfg =
        config().with_disabled_auth_methods([TokenEndpointAuthMethod::ClientSecretPost].into());
    let caps = ServerCapabilities::from_config(&cfg);
    let expected = [TokenEndpointAuthMethod::ClientSecretBasic];
    assert_eq!(caps.token_endpoint_auth_methods, expected);
    assert_eq!(caps.revocation_endpoint_auth_methods, expected);

    let fx = Fixture::new();
    let mut input = confidential(&ALL_GRANTS);
    input.auth_method = TokenEndpointAuthMethod::ClientSecretPost;
    let client = register(&fx, input);
    let (token, admin) = with_config(&fx, cfg);

    let err = exchange_with(
        &token,
        client.post(),
        grant_request("client_credentials", None),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        TokenError::InvalidClient {
            basic_attempted: false
        }
    ));
    let event = fx
        .env
        .store
        .audit_events()
        .into_iter()
        .find(|e| e.kind == AuditKind::ClientAuthenticationFailed)
        .unwrap();
    assert_eq!(event.details["method"], "client_secret_post");
    assert_eq!(event.details["reason"], "method_disabled");
    assert_eq!(
        event.details["client_id_presented"],
        client.id.as_inner().as_str()
    );

    // /revoke uses the same authentication.
    let err = block_on(token.revoke(
        &ctx(),
        client.post(),
        RevocationRequest {
            token: Some("t".to_owned()),
            ..RevocationRequest::default()
        },
    ))
    .unwrap_err();
    assert!(matches!(
        err,
        RevocationError::InvalidClient {
            basic_attempted: false
        }
    ));

    let mut input = confidential(&ALL_GRANTS);
    input.auth_method = TokenEndpointAuthMethod::ClientSecretPost;
    let err = block_on(admin.register_client(&ctx(), input)).unwrap_err();
    assert!(matches!(
        err,
        AdminError::AuthMethodDisabled(TokenEndpointAuthMethod::ClientSecretPost)
    ));
}

#[test]
fn disabled_client_secret_basic_reports_basic_attempted() {
    let fx = Fixture::new();
    let client = register(&fx, confidential(&ALL_GRANTS));
    let (token, _) = with_config(
        &fx,
        config().with_disabled_auth_methods([TokenEndpointAuthMethod::ClientSecretBasic].into()),
    );
    let err = exchange_with(
        &token,
        client.basic(),
        grant_request("client_credentials", None),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        TokenError::InvalidClient {
            basic_attempted: true
        }
    ));
}

#[test]
fn validate_rules() {
    assert_eq!(config().validate(), Ok(()));
    let cfg = config().with_disabled_grant_types(grants(&[GrantType::AuthorizationCode]));
    assert_eq!(
        cfg.validate(),
        Err(ApplicationConfigError::AuthorizationCodeDisabled)
    );
    let both = [
        TokenEndpointAuthMethod::ClientSecretBasic,
        TokenEndpointAuthMethod::ClientSecretPost,
    ];
    let cfg = config().with_disabled_auth_methods(both.into());
    assert_eq!(cfg.validate(), Err(ApplicationConfigError::NoAuthMethod));
    // Another method keeps the server usable.
    assert_eq!(
        cfg.clone().with_allow_public_clients(true).validate(),
        Ok(())
    );
    assert_eq!(cfg.with_issuer(ISSUER).validate(), Ok(()));
    // The first violation wins.
    let cfg = config()
        .with_disabled_grant_types(grants(&[GrantType::AuthorizationCode]))
        .with_disabled_auth_methods(both.into());
    assert_eq!(
        cfg.validate(),
        Err(ApplicationConfigError::AuthorizationCodeDisabled)
    );
}

#[test]
fn admin_reports_the_first_disabled_grant_in_set_order() {
    let fx = Fixture::new();
    let disabled = grants(&[GrantType::ClientCredentials, GrantType::RefreshToken]);
    let first = *disabled.iter().next().unwrap();
    let (_, admin) = with_config(&fx, config().with_disabled_grant_types(disabled));
    let err = block_on(admin.register_client(&ctx(), confidential(&ALL_GRANTS))).unwrap_err();
    assert!(matches!(err, AdminError::GrantTypeDisabled(g) if g == first));
}

#[test]
fn disabled_method_is_reported_before_public_clients_disabled() {
    let fx = Fixture::new();
    let (_, admin) = with_config(
        &fx,
        config().with_disabled_auth_methods([TokenEndpointAuthMethod::None].into()),
    );
    let mut input = confidential(&[GrantType::AuthorizationCode]);
    input.client_type = komainu_domain::ClientType::Public;
    input.auth_method = TokenEndpointAuthMethod::None;
    let err = block_on(admin.register_client(&ctx(), input)).unwrap_err();
    assert!(matches!(
        err,
        AdminError::AuthMethodDisabled(TokenEndpointAuthMethod::None)
    ));
}
