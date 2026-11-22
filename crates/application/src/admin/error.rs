use komainu_domain::DomainError;

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
