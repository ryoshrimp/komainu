use komainu_domain::{DomainError, SigningAlgorithm};

use crate::port::{SealError, StoreError};

/// Errors of [`SigningKeyService`](super::SigningKeyService).
#[derive(Debug, thiserror::Error)]
pub enum SigningKeyError {
    /// The algorithm is not in the signing configuration.
    #[error("signing algorithm is not enabled: {}", .0.as_str())]
    AlgorithmNotEnabled(SigningAlgorithm),
    /// There is no active key for the algorithm.
    #[error("no active signing key for {}", .0.as_str())]
    NoActiveKey(SigningAlgorithm),
    /// No key has that kid.
    #[error("signing key not found")]
    NotFound,
    /// A sealing, key or signing operation failed. Holds only the source error's `Display`.
    #[error("key operation failed: {0}")]
    Crypto(String),
    /// The store failed.
    #[error("store error: {0}")]
    Store(StoreError),
}

impl From<StoreError> for SigningKeyError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<SealError> for SigningKeyError {
    fn from(e: SealError) -> Self {
        Self::Crypto(e.to_string())
    }
}

impl From<komainu_jose::JoseError> for SigningKeyError {
    fn from(e: komainu_jose::JoseError) -> Self {
        Self::Crypto(e.to_string())
    }
}

impl From<DomainError> for SigningKeyError {
    fn from(e: DomainError) -> Self {
        Self::Crypto(e.to_string())
    }
}
