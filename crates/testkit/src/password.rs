use komainu_application::{BoxFuture, PasswordHashError, PasswordHasher};
use komainu_domain::{Password, PasswordHash};

/// hash = "plain$" + password; verify compares strings. verify_dummy does nothing.
pub struct PlainPasswordHasher;

impl PasswordHasher for PlainPasswordHasher {
    fn hash<'a>(
        &'a self,
        password: &'a Password,
    ) -> BoxFuture<'a, Result<PasswordHash, PasswordHashError>> {
        let result = PasswordHash::try_new(format!("plain${}", password.expose()))
            .map_err(|e| PasswordHashError(e.to_string()));
        Box::pin(std::future::ready(result))
    }

    fn verify<'a>(&'a self, password: &'a Password, hash: &'a PasswordHash) -> BoxFuture<'a, bool> {
        let ok = hash.as_inner().strip_prefix("plain$") == Some(password.expose());
        Box::pin(std::future::ready(ok))
    }

    fn verify_dummy<'a>(&'a self, _password: &'a Password) -> BoxFuture<'a, ()> {
        Box::pin(std::future::ready(()))
    }
}

#[cfg(test)]
mod tests {
    use komainu_domain::Secret;

    use super::*;
    use crate::test_util::block_on;

    fn password(s: &str) -> Password {
        Password::try_new(Secret::new(s.to_owned())).unwrap()
    }

    #[test]
    fn hash_and_verify() {
        let hasher = PlainPasswordHasher;
        let hash = block_on(hasher.hash(&password("pw"))).unwrap();
        assert_eq!(hash.as_inner(), "plain$pw");
        assert!(block_on(hasher.verify(&password("pw"), &hash)));
        assert!(!block_on(hasher.verify(&password("other"), &hash)));
        let unparsable = PasswordHash::try_new("$argon2id$x".to_owned()).unwrap();
        assert!(!block_on(hasher.verify(&password("pw"), &unparsable)));
    }
}
