//! What the authorization server supports, independent of URLs.

use komainu_domain::{CodeChallengeMethod, GrantType, ScopeToken, TokenEndpointAuthMethod};

use crate::config::ApplicationConfig;

/// What this authorization server supports, independent of URLs.
///
/// Every list is in a fixed order and has no duplicates. The lists are written out
/// explicitly (not derived from all variants of the domain enums) so that a new variant is
/// only advertised once it is implemented.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ServerCapabilities {
    /// Always `[ResponseType::Code]` today.
    pub response_types: Vec<ResponseType>,
    /// Always `[ResponseMode::Query]` today.
    pub response_modes: Vec<ResponseMode>,
    /// `[AuthorizationCode, ClientCredentials, RefreshToken]`.
    pub grant_types: Vec<GrantType>,
    /// `[ClientSecretBasic, ClientSecretPost]`, plus `None` last when
    /// `allow_public_clients` is true.
    pub token_endpoint_auth_methods: Vec<TokenEndpointAuthMethod>,
    /// Same as `token_endpoint_auth_methods`.
    pub revocation_endpoint_auth_methods: Vec<TokenEndpointAuthMethod>,
    /// `[CodeChallengeMethod::S256]`.
    pub code_challenge_methods: Vec<CodeChallengeMethod>,
    /// `ApplicationConfig::scopes` names, in configuration order. May be empty.
    pub scopes: Vec<ScopeToken>,
}

impl ServerCapabilities {
    /// Derives the capabilities from the configuration.
    pub fn from_config(config: &ApplicationConfig) -> Self {
        let mut auth_methods = vec![
            TokenEndpointAuthMethod::ClientSecretBasic,
            TokenEndpointAuthMethod::ClientSecretPost,
        ];
        if config.allow_public_clients {
            auth_methods.push(TokenEndpointAuthMethod::None);
        }
        Self {
            response_types: vec![ResponseType::Code],
            response_modes: vec![ResponseMode::Query],
            grant_types: vec![
                GrantType::AuthorizationCode,
                GrantType::ClientCredentials,
                GrantType::RefreshToken,
            ],
            token_endpoint_auth_methods: auth_methods.clone(),
            revocation_endpoint_auth_methods: auth_methods,
            code_challenge_methods: vec![CodeChallengeMethod::S256],
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
