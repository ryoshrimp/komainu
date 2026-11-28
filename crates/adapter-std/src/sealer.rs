use std::fmt;
use std::sync::Arc;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use komainu_application::{KeySealer, SealError, SecureRandom};
use komainu_domain::{SealedPrivateKey, Secret};

const VERSION: u8 = 0x01;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;

/// AES-256-GCM. Format: 0x01 || nonce (12 bytes) || ciphertext || tag (16 bytes).
pub struct AesGcmKeySealer {
    cipher: Aes256Gcm,
    random: Arc<dyn SecureRandom>,
}

/// The key encryption key was not 32 bytes in standard base64.
#[derive(Debug, thiserror::Error)]
#[error("the key encryption key must be 32 bytes in standard base64")]
pub struct InvalidSealerKey;

impl AesGcmKeySealer {
    pub fn new(key: Secret<[u8; KEY_LEN]>, random: Arc<dyn SecureRandom>) -> Self {
        let cipher = Aes256Gcm::new(key.expose_secret_ref().into());
        Self { cipher, random }
    }

    // Zeroizing the intermediate buffers is best effort: optimizations and copies (`[u8; 32]`
    // is `Copy`; the inner `Vec` on a decode failure is dropped by the decoder) mean complete
    // erasure is not guaranteed.
    /// Reads a 32-byte key from standard base64 (padded; surrounding whitespace is ignored).
    pub fn from_base64(
        key: &Secret<String>,
        random: Arc<dyn SecureRandom>,
    ) -> Result<Self, InvalidSealerKey> {
        let bytes = Secret::new(
            STANDARD
                .decode(key.expose_secret_ref().trim())
                .map_err(|_| InvalidSealerKey)?,
        );
        let array: [u8; KEY_LEN] = bytes
            .expose_secret_ref()
            .as_slice()
            .try_into()
            .map_err(|_| InvalidSealerKey)?;
        Ok(Self::new(Secret::new(array), random))
    }

    // Best effort only: `key.fill(0)` may be optimized away or leave other copies behind.
    /// Generates a new key encryption key (32 random bytes) in standard base64.
    pub fn generate_key_base64(random: &dyn SecureRandom) -> Secret<String> {
        let mut key = [0u8; KEY_LEN];
        random.fill_bytes(&mut key);
        let encoded = STANDARD.encode(key);
        key.fill(0);
        Secret::new(encoded)
    }
}

impl fmt::Debug for AesGcmKeySealer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AesGcmKeySealer { .. }")
    }
}

impl KeySealer for AesGcmKeySealer {
    fn seal(&self, plaintext: &Secret<Vec<u8>>, aad: &[u8]) -> Result<SealedPrivateKey, SealError> {
        let mut nonce = [0u8; NONCE_LEN];
        self.random.fill_bytes(&mut nonce);
        let ciphertext = self
            .cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: plaintext.expose_secret_ref(),
                    aad,
                },
            )
            .map_err(|_| SealError::Seal)?;
        let mut out = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
        out.push(VERSION);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        SealedPrivateKey::new(out).map_err(|_| SealError::Seal)
    }

    fn open(&self, sealed: &SealedPrivateKey, aad: &[u8]) -> Result<Secret<Vec<u8>>, SealError> {
        let bytes = sealed.as_bytes();
        if bytes.len() < 1 + NONCE_LEN + TAG_LEN || bytes[0] != VERSION {
            return Err(SealError::Open);
        }
        let (nonce, ciphertext) = bytes[1..].split_at(NONCE_LEN);
        let nonce = Nonce::try_from(nonce).map_err(|_| SealError::Open)?;
        self.cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map(Secret::new)
            .map_err(|_| SealError::Open)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OsSecureRandom;

    fn sealer(key: u8) -> AesGcmKeySealer {
        AesGcmKeySealer::new(Secret::new([key; KEY_LEN]), Arc::new(OsSecureRandom))
    }

    fn pt(bytes: &[u8]) -> Secret<Vec<u8>> {
        Secret::new(bytes.to_vec())
    }

    fn sealed(bytes: Vec<u8>) -> SealedPrivateKey {
        SealedPrivateKey::new(bytes).unwrap()
    }

    #[test]
    fn round_trip_with_format() {
        let s = sealer(7);
        let out = s.seal(&pt(b"private key"), b"kid-1").unwrap();
        assert_eq!(out.as_bytes()[0], 0x01);
        assert_eq!(out.as_bytes().len(), b"private key".len() + 29);
        let opened = s.open(&out, b"kid-1").unwrap();
        assert_eq!(opened.expose_secret_ref(), b"private key");
    }

    #[test]
    fn same_plaintext_seals_differently() {
        let s = sealer(7);
        let a = s.seal(&pt(b"x"), b"a").unwrap();
        let b = s.seal(&pt(b"x"), b"a").unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn open_rejects_bad_input() {
        let s = sealer(7);
        let out = s.seal(&pt(b"secret"), b"aad").unwrap();
        assert!(matches!(s.open(&out, b"other"), Err(SealError::Open)));
        assert!(matches!(sealer(8).open(&out, b"aad"), Err(SealError::Open)));

        for i in 0..out.as_bytes().len() {
            let mut tampered = out.as_bytes().to_vec();
            tampered[i] ^= 1;
            assert!(
                matches!(s.open(&sealed(tampered), b"aad"), Err(SealError::Open)),
                "{i}"
            );
        }

        let mut v2 = out.as_bytes().to_vec();
        v2[0] = 0x02;
        assert!(matches!(s.open(&sealed(v2), b"aad"), Err(SealError::Open)));
        assert!(matches!(
            s.open(&sealed(vec![0x01; 28]), b"aad"),
            Err(SealError::Open)
        ));
    }

    #[test]
    fn from_base64_checks_length_and_format() {
        let random: Arc<dyn SecureRandom> = Arc::new(OsSecureRandom);
        let enc = |n: usize| Secret::new(STANDARD.encode(vec![1u8; n]));
        assert!(AesGcmKeySealer::from_base64(&enc(32), random.clone()).is_ok());
        let padded = Secret::new(format!(" {}\n", enc(32).expose_secret_ref()));
        assert!(AesGcmKeySealer::from_base64(&padded, random.clone()).is_ok());
        for bad in [enc(31), enc(33), Secret::new("not base64!!".to_owned())] {
            assert!(AesGcmKeySealer::from_base64(&bad, random.clone()).is_err());
        }
    }

    #[test]
    fn generated_key_is_readable() {
        let a = AesGcmKeySealer::generate_key_base64(&OsSecureRandom);
        let b = AesGcmKeySealer::generate_key_base64(&OsSecureRandom);
        assert_ne!(a.expose_secret_ref(), b.expose_secret_ref());
        assert!(AesGcmKeySealer::from_base64(&a, Arc::new(OsSecureRandom)).is_ok());
    }

    #[test]
    fn debug_does_not_leak_key() {
        let s = sealer(0xAB);
        assert_eq!(format!("{s:?}"), "AesGcmKeySealer { .. }");
    }
}
