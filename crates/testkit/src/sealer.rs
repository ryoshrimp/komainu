use komainu_application::{KeySealer, SealError};
use komainu_domain::{SealedPrivateKey, Secret};

const MAGIC: &[u8] = b"TEST";

/// A [`KeySealer`] that does not encrypt: it only prefixes the plaintext with a tag and the
/// AAD, and checks them on open. **Not for production.**
#[derive(Debug, Clone, Copy, Default)]
pub struct TestKeySealer;

impl KeySealer for TestKeySealer {
    fn seal(&self, plaintext: &Secret<Vec<u8>>, aad: &[u8]) -> Result<SealedPrivateKey, SealError> {
        let aad_len = u32::try_from(aad.len()).map_err(|_| SealError::Seal)?;
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&aad_len.to_be_bytes());
        out.extend_from_slice(aad);
        out.extend_from_slice(plaintext.expose_secret_ref());
        SealedPrivateKey::new(out).map_err(|_| SealError::Seal)
    }

    fn open(&self, sealed: &SealedPrivateKey, aad: &[u8]) -> Result<Secret<Vec<u8>>, SealError> {
        let mut header = MAGIC.to_vec();
        header.extend_from_slice(
            &u32::try_from(aad.len())
                .map_err(|_| SealError::Open)?
                .to_be_bytes(),
        );
        header.extend_from_slice(aad);
        sealed
            .as_bytes()
            .strip_prefix(header.as_slice())
            .map(|rest| Secret::new(rest.to_vec()))
            .ok_or(SealError::Open)
    }
}
