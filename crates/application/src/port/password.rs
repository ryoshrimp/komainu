use komainu_domain::{Password, PasswordHash};

use super::BoxFuture;

#[derive(Debug, Clone, thiserror::Error)]
#[error("password hashing failed: {0}")]
pub struct PasswordHashError(pub String);

pub trait PasswordHasher: Send + Sync + 'static {
    fn hash<'a>(
        &'a self,
        password: &'a Password,
    ) -> BoxFuture<'a, Result<PasswordHash, PasswordHashError>>;
    /// false on mismatch or on an unparsable hash.
    fn verify<'a>(&'a self, password: &'a Password, hash: &'a PasswordHash) -> BoxFuture<'a, bool>;
    /// Burns roughly the same time as verify. Used when the user does not exist.
    fn verify_dummy<'a>(&'a self, password: &'a Password) -> BoxFuture<'a, ()>;
}
