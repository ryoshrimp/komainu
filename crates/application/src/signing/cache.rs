//! Decrypted keys and the JWKS, cached for [`CACHE_TTL`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use komainu_domain::{ServerSigningKey, SigningKeyId};
use komainu_jose::SigningKey;
use time::{Duration, OffsetDateTime};

/// How long a loaded set of keys is used before it is read again.
pub(crate) const CACHE_TTL: Duration = Duration::seconds(60);

pub(crate) struct Cached {
    pub(crate) loaded_at: OffsetDateTime,
    /// Every stored key.
    pub(crate) keys: Vec<ServerSigningKey>,
    /// Decrypted keys that were pending or active at `loaded_at`, by kid.
    pub(crate) signers: HashMap<SigningKeyId, Arc<SigningKey>>,
    pub(crate) jwks: Arc<str>,
}

/// The lock is never held across an await.
#[derive(Default)]
pub(crate) struct KeyCache(Mutex<Option<Arc<Cached>>>);

impl KeyCache {
    pub(crate) fn fresh(&self, now: OffsetDateTime) -> Option<Arc<Cached>> {
        let guard = self.0.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .as_ref()
            .filter(|c| now - c.loaded_at < CACHE_TTL)
            .cloned()
    }

    pub(crate) fn store(&self, cached: Arc<Cached>) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = Some(cached);
    }

    pub(crate) fn clear(&self) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}
