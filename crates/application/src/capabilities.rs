//! What the authorization server supports, independent of URLs.

use komainu_domain::{CodeChallengeMethod, GrantType, ScopeToken, TokenEndpointAuthMethod};
use komainu_jose::Algorithm;

use crate::config::ApplicationConfig;
use crate::token::{AuthMethodRegistry, GrantRegistry};

/// What this authorization server supports, independent of URLs.
///
/// Every list is in a fixed order and has no duplicates. The grant type and client
/// authentication lists are built from the registered handlers (not from all variants of the
/// domain enums), so that a new variant is only advertised once it is implemented.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ServerCapabilities {
    /// Always `[ResponseType::Code]` today.
    pub response_types: Vec<ResponseType>,
    /// Always `[ResponseMode::Query]` today.
    pub response_modes: Vec<ResponseMode>,
    /// `[AuthorizationCode, ClientCredentials, RefreshToken]`, plus `JwtBearer` when `issuer`
    /// is set.
    pub grant_types: Vec<GrantType>,
    /// `[ClientSecretBasic, ClientSecretPost]`, then `PrivateKeyJwt` when `issuer` is set,
    /// plus `None` last when `allow_public_clients` is true.
    pub token_endpoint_auth_methods: Vec<TokenEndpointAuthMethod>,
    /// Same as `token_endpoint_auth_methods`.
    pub revocation_endpoint_auth_methods: Vec<TokenEndpointAuthMethod>,
    /// `[CodeChallengeMethod::S256]`.
    pub code_challenge_methods: Vec<CodeChallengeMethod>,
    /// `[Rs256, Es256]` when `issuer` is set (`private_key_jwt` is advertised), else empty.
    pub token_endpoint_auth_signing_algs: Vec<Algorithm>,
    /// Same as `token_endpoint_auth_signing_algs`.
    pub revocation_endpoint_auth_signing_algs: Vec<Algorithm>,
    /// `ApplicationConfig::scopes` names, in configuration order. May be empty.
    pub scopes: Vec<ScopeToken>,
}

impl ServerCapabilities {
    /// Derives the capabilities from the configuration.
    pub fn from_config(config: &ApplicationConfig) -> Self {
        let grants = GrantRegistry::builtin(config);
        let auth_methods = AuthMethodRegistry::builtin(config);
        let methods = auth_methods.available(config);
        let algs = auth_methods.signing_algs(config);
        Self {
            response_types: vec![ResponseType::Code],
            response_modes: vec![ResponseMode::Query],
            grant_types: grants.available(config),
            token_endpoint_auth_methods: methods.clone(),
            revocation_endpoint_auth_methods: methods,
            code_challenge_methods: vec![CodeChallengeMethod::S256],
            token_endpoint_auth_signing_algs: algs.clone(),
            revocation_endpoint_auth_signing_algs: algs,
            scopes: config.scopes.iter().map(|s| s.name.clone()).collect(),
        }
    }
}

/// `response_type` values. Only `code` is supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResponseType {
    Code,
}

impl ResponseType {
    /// `"code"`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Code => "code",
        }
    }
}

/// `response_mode` values. Only `query` is supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResponseMode {
    Query,
}

impl ResponseMode {
    /// `"query"`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Query => "query",
        }
    }
}
