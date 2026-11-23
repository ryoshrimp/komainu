use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use komainu_domain::{OpaqueToken, Secret};

use crate::port::{Clock, SecureRandom};

/// UUIDv7 from clock.now() (unix millis) and 10 random bytes.
pub fn new_uuid_v7(clock: &dyn Clock, random: &dyn SecureRandom) -> uuid::Uuid {
    // A clock before the epoch cannot be represented; clamp to 0.
    let millis = u64::try_from(clock.now().unix_timestamp_nanos() / 1_000_000).unwrap_or(0);
    let mut bytes = [0u8; 10];
    random.fill_bytes(&mut bytes);
    uuid::Builder::from_unix_timestamp_millis(millis, &bytes).into_uuid()
}

/// 32 random bytes, base64url without padding (43 chars). N-1.
pub fn new_opaque_token(random: &dyn SecureRandom) -> OpaqueToken {
    let mut bytes = [0u8; 32];
    random.fill_bytes(&mut bytes);
    OpaqueToken::try_new(Secret::new(URL_SAFE_NO_PAD.encode(bytes)))
        .expect("43 base64url characters are a valid opaque token")
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// Fills every buffer with bytes derived from a running counter, so that
    /// across many tokens every 6-bit value (every base64url character) occurs.
    struct CounterRandom(AtomicUsize);

    impl SecureRandom for CounterRandom {
        fn fill_bytes(&self, dest: &mut [u8]) {
            let start = self.0.fetch_add(1, Ordering::Relaxed);
            for (i, byte) in dest.iter_mut().enumerate() {
                *byte = start.wrapping_mul(7).wrapping_add(i.wrapping_mul(13)) as u8;
            }
        }
    }

    /// Mirrors `is_b64token` in `crates/http/tests/token.rs`; keep the two in sync.
    /// RFC 6750 §2.1: `b64token = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="`
    fn is_b64token(s: &str) -> bool {
        let body = s.trim_end_matches('=');
        !body.is_empty()
            && body
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~+/".contains(&b))
    }

    #[test]
    fn is_b64token_discriminates() {
        for valid in ["a", "Az09-._~+/", "abc==", "a/b+c"] {
            assert!(is_b64token(valid), "{valid:?} should be a b64token");
        }
        for invalid in ["", "=", "a b", "a@b", "a!b", "a=b"] {
            assert!(!is_b64token(invalid), "{invalid:?} should be rejected");
        }
    }

    #[test]
    fn opaque_tokens_are_rfc6750_b64tokens() {
        let random = CounterRandom(AtomicUsize::new(0));
        let mut seen = std::collections::HashSet::new();
        for _ in 0..512 {
            let token = new_opaque_token(&random);
            let value = token.expose();
            assert!(is_b64token(value), "not a b64token: {value}");
            seen.extend(value.chars());
        }
        // Every base64url character was exercised, not just a lucky subset.
        assert_eq!(seen.len(), 64, "alphabet coverage: {seen:?}");
    }
}
