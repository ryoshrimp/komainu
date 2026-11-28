//! Settings of the AS signing keys.

use komainu_domain::{SigningAlgorithm, SigningPolicy};

/// Which algorithms the AS signs with and how long its keys live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningConfig {
    algorithms: Vec<SigningAlgorithm>,
    policy: SigningPolicy,
}

impl SigningConfig {
    /// Fails with [`SigningConfigError::Algorithms`] if `algorithms` is empty or has duplicates.
    pub fn new(
        algorithms: Vec<SigningAlgorithm>,
        policy: SigningPolicy,
    ) -> Result<Self, SigningConfigError> {
        let unique = algorithms
            .iter()
            .enumerate()
            .all(|(i, a)| !algorithms[..i].contains(a));
        if algorithms.is_empty() || !unique {
            return Err(SigningConfigError::Algorithms);
        }
        Ok(Self { algorithms, policy })
    }

    /// The algorithms to keep an active key for, in order.
    pub fn algorithms(&self) -> &[SigningAlgorithm] {
        &self.algorithms
    }

    /// Key lifetimes.
    pub fn policy(&self) -> &SigningPolicy {
        &self.policy
    }
}

impl Default for SigningConfig {
    fn default() -> Self {
        Self {
            algorithms: vec![SigningAlgorithm::Es256],
            policy: SigningPolicy::default(),
        }
    }
}

/// An invalid [`SigningConfig`].
#[derive(Debug, thiserror::Error)]
pub enum SigningConfigError {
    /// `algorithms` is empty or has duplicates.
    #[error("signing algorithms must be non-empty and unique")]
    Algorithms,
}
