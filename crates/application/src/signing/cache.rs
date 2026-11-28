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

#[derive(Default)]
struct Slot {
    cached: Option<Arc<Cached>>,
    /// Bumped by [`KeyCache::clear`], so a load that started before a clear does not
    /// store what it read.
    generation: u64,
}

/// The lock is never held across an await.
#[derive(Default)]
pub(crate) struct KeyCache(Mutex<Slot>);

impl KeyCache {
    /// The cached keys if they were loaded less than [`CACHE_TTL`] ago (a clock that went
    /// back counts as stale), or else the generation to pass to [`Self::store`].
    pub(crate) fn fresh(&self, now: OffsetDateTime) -> Result<Arc<Cached>, u64> {
        let slot = self.0.lock().unwrap_or_else(|e| e.into_inner());
        slot.cached
            .as_ref()
            .filter(|c| {
                let age = now - c.loaded_at;
                !age.is_negative() && age < CACHE_TTL
            })
            .cloned()
            .ok_or(slot.generation)
    }

    /// Stores `cached` unless the cache was cleared since `generation` was read.
    pub(crate) fn store(&self, cached: Arc<Cached>, generation: u64) {
        let mut slot = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if slot.generation == generation {
            slot.cached = Some(cached);
        }
    }

    pub(crate) fn clear(&self) {
        let mut slot = self.0.lock().unwrap_or_else(|e| e.into_inner());
        slot.cached = None;
        slot.generation = slot.generation.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cached(loaded_at: OffsetDateTime) -> Arc<Cached> {
        Arc::new(Cached {
            loaded_at,
            keys: Vec::new(),
            signers: HashMap::new(),
            jwks: "{}".into(),
        })
    }

    #[test]
    fn a_load_that_started_before_a_clear_is_not_stored() {
        let cache = KeyCache::default();
        let now = OffsetDateTime::UNIX_EPOCH;
        let Err(generation) = cache.fresh(now) else {
            panic!("fresh")
        };
        cache.clear();
        cache.store(cached(now), generation);
        assert!(cache.fresh(now).is_err());

        let Err(generation) = cache.fresh(now) else {
            panic!("fresh")
        };
        cache.store(cached(now), generation);
        assert!(cache.fresh(now).is_ok());
    }

    #[test]
    fn a_clock_that_went_back_makes_the_cache_stale() {
        let cache = KeyCache::default();
        let now = OffsetDateTime::UNIX_EPOCH + Duration::hours(1);
        let Err(generation) = cache.fresh(now) else {
            panic!("fresh")
        };
        cache.store(cached(now), generation);
        assert!(cache.fresh(now + Duration::seconds(59)).is_ok());
        assert!(cache.fresh(now - Duration::seconds(1)).is_err());
        assert!(cache.fresh(now + CACHE_TTL).is_err());
    }
}
