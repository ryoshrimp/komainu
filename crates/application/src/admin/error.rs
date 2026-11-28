use komainu_domain::{ClientId, DomainError, GrantType, TokenEndpointAuthMethod};

use crate::port::{PasswordHashError, StoreError};

/// Failure of an [`AdminService`](super::AdminService) operation.
#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    /// Domain validation or client invariant violation.
    #[error("invalid input: {0}")]
    Invalid(DomainError),
    /// `allowed_scopes` contains a scope not defined in `ApplicationConfig::scopes`.
    #[error("scope is not defined in the configuration: {0}")]
    UnknownScope(String),
    /// `client_type=public` while `allow_public_clients=false`.
    #[error("public clients are disabled")]
    PublicClientsDisabled,
    /// The client's `auth_method` is in `ApplicationConfig::disabled_auth_methods`.
    #[error("client authentication method is disabled: {}", .0.as_str())]
    AuthMethodDisabled(TokenEndpointAuthMethod),
    /// The client's `grant_types` has one in `ApplicationConfig::disabled_grant_types`.
    #[error("grant type is disabled: {}", .0.as_str())]
    GrantTypeDisabled(GrantType),
    /// `jwks` is not a usable JWK Set (parse failure, private key, or not 1 to 10 keys).
    #[error("invalid jwks: {0}")]
    InvalidJwks(String),
    /// `allowed_clients` of an issuer names a client that does not exist.
    #[error("unknown client: {}", .0.as_inner())]
    UnknownClient(ClientId),
    #[error("not found")]
    NotFound,
    /// Duplicate username.
    #[error("already exists")]
    Conflict,
    #[error("password hashing failed: {0}")]
    PasswordHash(PasswordHashError),
    #[error("store error: {0}")]
    Store(StoreError),
}

impl From<StoreError> for AdminError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::Conflict => Self::Conflict,
            other => Self::Store(other),
        }
    }
}

impl From<DomainError> for AdminError {
    fn from(error: DomainError) -> Self {
        Self::Invalid(error)
    }
}
