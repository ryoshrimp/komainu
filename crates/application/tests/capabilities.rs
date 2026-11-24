//! Acceptance tests of `ServerCapabilities`.

mod common;

use common::{Fixture, config};
use komainu_application::{ApplicationConfig, ResponseMode, ResponseType, ServerCapabilities};
use komainu_domain::{CodeChallengeMethod, GrantType, TokenEndpointAuthMethod};

#[test]
fn private_clients_only_by_default() {
    let caps = ServerCapabilities::from_config(&config());
    let expected = vec![
        TokenEndpointAuthMethod::ClientSecretBasic,
        TokenEndpointAuthMethod::ClientSecretPost,
    ];
    assert_eq!(caps.token_endpoint_auth_methods, expected);
    assert_eq!(caps.revocation_endpoint_auth_methods, expected);
}

#[test]
fn public_clients_add_none_last() {
    let caps = ServerCapabilities::from_config(&config().with_allow_public_clients(true));
    let expected = vec![
        TokenEndpointAuthMethod::ClientSecretBasic,
        TokenEndpointAuthMethod::ClientSecretPost,
        TokenEndpointAuthMethod::None,
    ];
    assert_eq!(caps.token_endpoint_auth_methods, expected);
    assert_eq!(caps.revocation_endpoint_auth_methods, expected);
}

#[test]
fn scopes_follow_configuration_order() {
    let caps = ServerCapabilities::from_config(&config());
    let names: Vec<&str> = caps.scopes.iter().map(|s| s.as_str()).collect();
    assert_eq!(names, ["read", "write"]);
    assert!(
        ServerCapabilities::from_config(&ApplicationConfig::default())
            .scopes
            .is_empty()
    );
}

#[test]
fn fixed_lists() {
    let caps = ServerCapabilities::from_config(&config());
    assert_eq!(caps.response_types, [ResponseType::Code]);
    assert_eq!(caps.response_modes, [ResponseMode::Query]);
    assert_eq!(
        caps.grant_types,
        [
            GrantType::AuthorizationCode,
            GrantType::ClientCredentials,
            GrantType::RefreshToken
        ]
    );
    assert_eq!(caps.code_challenge_methods, [CodeChallengeMethod::S256]);
    assert_eq!(ResponseType::Code.as_str(), "code");
    assert_eq!(ResponseMode::Query.as_str(), "query");
}

#[test]
fn token_service_reports_the_same_capabilities() {
    let cfg = config().with_allow_public_clients(true);
    let fx = Fixture::with_config(cfg.clone());
    assert_eq!(
        fx.token.server_capabilities(),
        ServerCapabilities::from_config(&cfg)
    );
}
