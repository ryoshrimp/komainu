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

#[test]
fn issuer_adds_private_key_jwt_and_algs() {
    use komainu_jose::Algorithm;
    let caps = ServerCapabilities::from_config(&config().with_issuer("https://as.example.com"));
    let expected = vec![
        TokenEndpointAuthMethod::ClientSecretBasic,
        TokenEndpointAuthMethod::ClientSecretPost,
        TokenEndpointAuthMethod::PrivateKeyJwt,
    ];
    assert_eq!(caps.token_endpoint_auth_methods, expected);
    assert_eq!(caps.revocation_endpoint_auth_methods, expected);
    assert_eq!(
        caps.token_endpoint_auth_signing_algs,
        [Algorithm::Rs256, Algorithm::Es256]
    );
    assert_eq!(
        caps.revocation_endpoint_auth_signing_algs,
        [Algorithm::Rs256, Algorithm::Es256]
    );
    let with_public = ServerCapabilities::from_config(
        &config()
            .with_issuer("https://as.example.com")
            .with_allow_public_clients(true),
    );
    assert_eq!(
        with_public.token_endpoint_auth_methods.last(),
        Some(&TokenEndpointAuthMethod::None)
    );
    // Without an issuer nothing about assertions is advertised.
    let plain = ServerCapabilities::from_config(&config());
    assert!(plain.token_endpoint_auth_signing_algs.is_empty());
    assert!(!plain.grant_types.contains(&GrantType::JwtBearer));
}
