use std::fmt;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::Secret;
use crate::error::DomainError;

/// A plaintext token, authorization code, client secret, CSRF token or session
/// token (1-512 bytes of VSCHAR). It never prints its value.
pub struct OpaqueToken(Secret<String>);

impl OpaqueToken {
    pub fn try_new(value: Secret<String>) -> Result<OpaqueToken, DomainError> {
        let s = value.expose_secret_ref();
        if s.is_empty() || s.len() > 512 {
            return Err(DomainError::invalid(
                "opaque_token",
                "length must be 1 to 512 bytes",
            ));
        }
        if !s.bytes().all(|b| matches!(b, 0x20..=0x7e)) {
            return Err(DomainError::invalid("opaque_token", "invalid character"));
        }
        Ok(OpaqueToken(value))
    }

    pub fn expose(&self) -> &str {
        self.0.expose_secret_ref()
    }

    /// SHA-256 of the UTF-8 bytes.
    pub fn hash(&self) -> TokenHash {
        TokenHash(Sha256::digest(self.expose().as_bytes()).into())
    }
}

impl fmt::Debug for OpaqueToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("OpaqueToken").field(&self.0).finish()
    }
}

/// SHA-256 of an [`OpaqueToken`]; the identifier under which tokens are stored.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TokenHash([u8; 32]);

impl TokenHash {
    pub const fn from_bytes(bytes: [u8; 32]) -> TokenHash {
        TokenHash(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Constant-time comparison.
    pub fn ct_eq(&self, other: &TokenHash) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl fmt::Debug for TokenHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TokenHash({:02x}{:02x}{:02x}{:02x}…)",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(s: &str) -> OpaqueToken {
        OpaqueToken::try_new(Secret::new(s.to_owned())).unwrap()
    }

    #[test]
    fn debug_never_prints_secrets() {
        assert_eq!(format!("{:?}", token("abc")), "OpaqueToken([REDACTED])");
        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&[0x01, 0x23, 0xab, 0xcd]);
        assert_eq!(
            format!("{:?}", TokenHash::from_bytes(b)),
            "TokenHash(0123abcd…)"
        );
    }

    #[test]
    fn validation() {
        assert!(OpaqueToken::try_new(Secret::new(String::new())).is_err());
        assert!(OpaqueToken::try_new(Secret::new("a".repeat(513))).is_err());
        assert!(OpaqueToken::try_new(Secret::new("a".repeat(512))).is_ok());
        assert!(OpaqueToken::try_new(Secret::new("a\u{7f}".to_owned())).is_err());
        assert!(OpaqueToken::try_new(Secret::new("é".to_owned())).is_err());
    }

    #[test]
    fn hash_is_sha256() {
        // SHA-256("abc")
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        let hash = token("abc").hash();
        assert_eq!(hash.as_bytes(), &expected);
        assert!(hash.ct_eq(&TokenHash::from_bytes(expected)));
        assert!(!hash.ct_eq(&token("abd").hash()));
    }
}
