use komainu_application::SecureRandom;
use rand::TryRng;
use rand::rngs::SysRng;

/// CSPRNG backed by the operating system's random source.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsSecureRandom;

impl SecureRandom for OsSecureRandom {
    /// # Panics
    ///
    /// Panics if the OS random source fails, because token generation cannot continue safely.
    fn fill_bytes(&self, dest: &mut [u8]) {
        SysRng
            .try_fill_bytes(dest)
            .expect("the OS random source must be available");
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use komainu_application::new_opaque_token;

    use super::*;

    #[test]
    fn opaque_token_is_43_url_safe_chars_and_unique() {
        let random = OsSecureRandom;
        let mut seen = HashSet::new();
        for _ in 0..1000 {
            let token = new_opaque_token(&random);
            let s = token.expose();
            assert_eq!(s.len(), 43);
            assert!(
                s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            );
            assert!(seen.insert(s.to_owned()), "duplicate token");
        }
    }

    #[test]
    fn fill_bytes_fills_the_whole_buffer() {
        let mut buf = [0u8; 64];
        OsSecureRandom.fill_bytes(&mut buf);
        // An unfilled tail would stay zero; a random 8-byte chunk is all zero with
        // probability 2^-64.
        for chunk in buf.chunks(8) {
            assert!(chunk.iter().any(|b| *b != 0), "{chunk:?}");
        }
    }
}
