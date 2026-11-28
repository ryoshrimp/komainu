use komainu_domain::{SealedPrivateKey, Secret};

#[derive(Debug, thiserror::Error)]
pub enum SealError {
    #[error("failed to seal the private key")]
    Seal,
    #[error("failed to open the sealed private key")]
    Open,
}

/// Encrypts AS private keys at rest. Implementations must be authenticated encryption
/// bound to `aad`.
pub trait KeySealer: Send + Sync + 'static {
    fn seal(&self, plaintext: &Secret<Vec<u8>>, aad: &[u8]) -> Result<SealedPrivateKey, SealError>;
    /// Fails with `SealError::Open` if `aad` differs from the one used at seal time, the key
    /// is wrong, or the data was tampered with.
    fn open(&self, sealed: &SealedPrivateKey, aad: &[u8]) -> Result<Secret<Vec<u8>>, SealError>;
}
