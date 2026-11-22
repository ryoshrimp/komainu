use argon2::{Argon2, PasswordHasher as _, PasswordVerifier as _};
use komainu_application::BoxFuture;
use komainu_application::{PasswordHashError, PasswordHasher, SecureRandom};
use komainu_domain::{Password, PasswordHash, Secret};

use crate::OsSecureRandom;

const SALT_LEN: usize = 16;
const DUMMY_PASSWORD: &str = "komainu-dummy-password";

/// Argon2id v0x13 password hasher using the `argon2` crate defaults.
///
/// Hashing and verification run on tokio's blocking pool.
pub struct Argon2PasswordHasher {
    dummy_hash: String,
}

impl std::fmt::Debug for Argon2PasswordHasher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Argon2PasswordHasher")
            .finish_non_exhaustive()
    }
}

fn argon2() -> Argon2<'static> {
    Argon2::default()
}

/// Hashes with a fresh 16-byte salt from the OS random source and returns a PHC string.
fn hash_phc(password: &str) -> Result<String, PasswordHashError> {
    let mut salt = [0u8; SALT_LEN];
    OsSecureRandom.fill_bytes(&mut salt);
    argon2()
        .hash_password_with_salt(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| PasswordHashError(e.to_string()))
}

fn verify_phc(password: &str, hash: &str) -> bool {
    argon2().verify_password(password.as_bytes(), hash).is_ok()
}

impl Argon2PasswordHasher {
    /// Argon2id v0x13 with argon2 crate defaults. Computes a dummy hash for `verify_dummy`.
    pub fn new() -> Result<Self, PasswordHashError> {
        Ok(Self {
            dummy_hash: hash_phc(DUMMY_PASSWORD)?,
        })
    }
}

fn clone_secret(password: &Password) -> Secret<String> {
    Secret::new(password.expose().to_owned())
}

impl PasswordHasher for Argon2PasswordHasher {
    fn hash<'a>(
        &'a self,
        password: &'a Password,
    ) -> BoxFuture<'a, Result<PasswordHash, PasswordHashError>> {
        let secret = clone_secret(password);
        Box::pin(async move {
            let phc = tokio::task::spawn_blocking(move || hash_phc(secret.expose_secret_ref()))
                .await
                .map_err(|e| PasswordHashError(e.to_string()))??;
            PasswordHash::try_new(phc).map_err(|e| PasswordHashError(e.to_string()))
        })
    }

    fn verify<'a>(&'a self, password: &'a Password, hash: &'a PasswordHash) -> BoxFuture<'a, bool> {
        let secret = clone_secret(password);
        let hash = hash.as_inner().clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || verify_phc(secret.expose_secret_ref(), &hash))
                .await
                .unwrap_or(false)
        })
    }

    fn verify_dummy<'a>(&'a self, password: &'a Password) -> BoxFuture<'a, ()> {
        let secret = clone_secret(password);
        let hash = self.dummy_hash.clone();
        Box::pin(async move {
            let _ =
                tokio::task::spawn_blocking(move || verify_phc(secret.expose_secret_ref(), &hash))
                    .await;
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    fn pw(s: &str) -> Password {
        Password::try_new(Secret::new(s.to_owned())).unwrap()
    }

    #[tokio::test]
    async fn hash_is_phc_argon2id_and_verifies() {
        let hasher = Argon2PasswordHasher::new().unwrap();
        let hash = hasher.hash(&pw("correct horse")).await.unwrap();
        assert!(hash.as_inner().starts_with("$argon2id$v=19$"));
        assert!(hasher.verify(&pw("correct horse"), &hash).await);
        assert!(!hasher.verify(&pw("wrong horse"), &hash).await);
    }

    #[tokio::test]
    async fn same_password_hashes_to_different_strings() {
        let hasher = Argon2PasswordHasher::new().unwrap();
        let a = hasher.hash(&pw("same")).await.unwrap();
        let b = hasher.hash(&pw("same")).await.unwrap();
        assert_ne!(a.as_inner(), b.as_inner());
    }

    #[tokio::test]
    async fn verify_returns_false_for_non_phc_hash() {
        let hasher = Argon2PasswordHasher::new().unwrap();
        for bad in [
            "not a hash",
            "plain$pw",
            "$argon2id$",
            "$argon2id$v=19$garbage",
        ] {
            let hash = PasswordHash::try_new(bad.to_owned()).unwrap();
            assert!(!hasher.verify(&pw("x"), &hash).await, "{bad}");
        }
    }

    #[tokio::test]
    async fn verify_dummy_costs_about_as_much_as_verify() {
        let hasher = Argon2PasswordHasher::new().unwrap();
        let hash = hasher.hash(&pw("timing")).await.unwrap();
        let t = Instant::now();
        hasher.verify(&pw("timing"), &hash).await;
        let real = t.elapsed();
        let t = Instant::now();
        hasher.verify_dummy(&pw("timing")).await;
        let dummy = t.elapsed();
        // Loose bounds: only guards against the dummy being skipped or far cheaper.
        assert!(dummy * 4 > real, "dummy {dummy:?} vs real {real:?}");
        assert!(dummy < real * 4, "dummy {dummy:?} vs real {real:?}");
    }

    #[test]
    fn debug_does_not_leak_hash_material() {
        let hasher = Argon2PasswordHasher::new().unwrap();
        let s = format!("{hasher:?}");
        assert!(!s.contains("argon2id"));
    }
}
