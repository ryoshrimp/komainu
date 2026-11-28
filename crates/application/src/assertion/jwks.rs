//! Cache of the keys behind a client's `jwks_uri`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use komainu_domain::JwksUri;
use komainu_jose::JwkSet;
use time::OffsetDateTime;

use super::{JWKS_CACHE_TTL, JWKS_MIN_REFETCH_INTERVAL};
use crate::port::{Clock, JwksFetchError, JwksFetcher};

/// Fetches and caches JWKS documents by URI.
///
/// Share one instance (`Arc<JwksResolver>`) so that the cache is one.
pub struct JwksResolver {
    fetcher: Option<Arc<dyn JwksFetcher>>,
    clock: Arc<dyn Clock>,
    cache: Mutex<HashMap<JwksUri, CacheEntry>>,
}

#[derive(Default)]
struct CacheEntry {
    keys: Option<(Arc<JwkSet>, OffsetDateTime)>,
    /// When the last finished fetch (successful or not) started.
    last_attempt: Option<OffsetDateTime>,
    /// Fetches of this URI that are running now.
    fetching: usize,
}

impl CacheEntry {
    fn valid_keys(&self, now: OffsetDateTime) -> Option<Arc<JwkSet>> {
        let (keys, fetched_at) = self.keys.as_ref()?;
        (now - *fetched_at < JWKS_CACHE_TTL).then(|| Arc::clone(keys))
    }
}

pub(crate) enum Freshness {
    /// Use the cache while it is valid (`now - fetched_at < JWKS_CACHE_TTL`). Otherwise fetch,
    /// unless the last attempt (successful or not) was less than `JWKS_MIN_REFETCH_INTERVAL` ago.
    Cached,
    /// Fetch again if the last attempt was at least `JWKS_MIN_REFETCH_INTERVAL` ago. Otherwise
    /// return the valid cache, or `RefetchTooSoon` if there is none (an expired cache is never
    /// returned).
    Refresh,
}

pub(crate) enum KeyResolveError {
    // The cause is not reported yet (audit reasons are coarse); only tests read it.
    Fetch(#[cfg_attr(not(test), expect(dead_code))] JwksFetchError),
    /// The body is not a JWKS, or has no keys.
    InvalidJwks,
    RefetchTooSoon,
}

impl JwksResolver {
    /// Without a `fetcher`, every `jwks_uri` fails with `Transport("no fetcher configured")`.
    pub fn new(fetcher: Option<Arc<dyn JwksFetcher>>, clock: Arc<dyn Clock>) -> Self {
        Self {
            fetcher,
            clock,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Whether a fetcher was given, so that a `jwks_uri` can be used at all.
    pub(crate) fn has_fetcher(&self) -> bool {
        self.fetcher.is_some()
    }

    pub(crate) async fn keys(
        &self,
        uri: &JwksUri,
        freshness: Freshness,
    ) -> Result<Arc<JwkSet>, KeyResolveError> {
        let Some(fetcher) = &self.fetcher else {
            return Err(KeyResolveError::Fetch(JwksFetchError::Transport(
                "no fetcher configured".to_owned(),
            )));
        };
        let now = self.clock.now();
        {
            let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = cache.get(uri) {
                let valid = entry.valid_keys(now);
                let too_soon = entry
                    .last_attempt
                    .is_some_and(|at| now - at < JWKS_MIN_REFETCH_INTERVAL);
                match freshness {
                    Freshness::Cached => {
                        if let Some(keys) = valid {
                            return Ok(keys);
                        }
                        if too_soon {
                            return Err(KeyResolveError::RefetchTooSoon);
                        }
                    }
                    // A running fetch counts as too soon too, so that requests with an unknown
                    // `kid` do not pile up fetches. Requests without valid keys still fetch.
                    Freshness::Refresh if too_soon || entry.fetching > 0 => {
                        return valid.ok_or(KeyResolveError::RefetchTooSoon);
                    }
                    Freshness::Refresh => {}
                }
            }
            cache.entry(uri.clone()).or_default().fetching += 1;
        }

        // The lock is not held across the fetch. The guard also ends the fetch if this future
        // is dropped before it finishes.
        let mut guard = Fetching {
            cache: &self.cache,
            uri,
            started: now,
            keys: None,
        };
        let result = fetcher.fetch(uri).await;
        let parsed = match result {
            Ok(body) => match JwkSet::from_json(&body) {
                Ok(set) if !set.keys().is_empty() => Ok(Arc::new(set)),
                _ => Err(KeyResolveError::InvalidJwks),
            },
            Err(e) => Err(KeyResolveError::Fetch(e)),
        };

        if let Ok(keys) = &parsed {
            guard.keys = Some(Arc::clone(keys));
        }
        parsed
    }
}

/// Records the end of a fetch in the cache when dropped.
struct Fetching<'a> {
    cache: &'a Mutex<HashMap<JwksUri, CacheEntry>>,
    uri: &'a JwksUri,
    started: OffsetDateTime,
    keys: Option<Arc<JwkSet>>,
}

impl Drop for Fetching<'_> {
    fn drop(&mut self) {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        let entry = cache.entry(self.uri.clone()).or_default();
        entry.fetching = entry.fetching.saturating_sub(1);
        entry.last_attempt = Some(
            entry
                .last_attempt
                .map_or(self.started, |at| at.max(self.started)),
        );
        // Keep the keys of the newest fetch when fetches overlap.
        if let Some(keys) = self.keys.take()
            && entry
                .keys
                .as_ref()
                .is_none_or(|(_, at)| *at <= self.started)
        {
            entry.keys = Some((keys, self.started));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Waker};

    use komainu_jose::SigningKey;
    use time::Duration;

    use super::*;
    use crate::port::BoxFuture;

    fn block_on<F: Future>(future: F) -> F::Output {
        let mut cx = Context::from_waker(Waker::noop());
        match pin!(future).as_mut().poll(&mut cx) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("future suspended"),
        }
    }

    struct TestClock(Mutex<OffsetDateTime>);

    impl Clock for TestClock {
        fn now(&self) -> OffsetDateTime {
            *self.0.lock().unwrap()
        }
    }

    /// Returns `body` (or a timeout when `fail` is set) and counts calls.
    struct Fetcher {
        calls: AtomicUsize,
        fail: Mutex<bool>,
        body: Mutex<String>,
    }

    impl JwksFetcher for Fetcher {
        fn fetch<'a>(&'a self, _uri: &'a JwksUri) -> BoxFuture<'a, Result<String, JwksFetchError>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let out = if *self.fail.lock().unwrap() {
                Err(JwksFetchError::Timeout)
            } else {
                Ok(self.body.lock().unwrap().clone())
            };
            Box::pin(std::future::ready(out))
        }
    }

    struct Fixture {
        clock: Arc<TestClock>,
        fetcher: Arc<Fetcher>,
        resolver: JwksResolver,
        uri: JwksUri,
    }

    impl Fixture {
        fn new() -> Self {
            let key = SigningKey::generate_es256().unwrap().verifying_key();
            let body = JwkSet::new(vec![key]).unwrap().to_json();
            let clock = Arc::new(TestClock(Mutex::new(
                OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(),
            )));
            let fetcher = Arc::new(Fetcher {
                calls: AtomicUsize::new(0),
                fail: Mutex::new(false),
                body: Mutex::new(body),
            });
            let resolver = JwksResolver::new(Some(fetcher.clone()), clock.clone());
            let uri = JwksUri::try_new("https://c.example.com/jwks".to_owned()).unwrap();
            Self {
                clock,
                fetcher,
                resolver,
                uri,
            }
        }

        fn advance(&self, secs: i64) {
            *self.clock.0.lock().unwrap() += Duration::seconds(secs);
        }

        fn calls(&self) -> usize {
            self.fetcher.calls.load(Ordering::SeqCst)
        }

        fn fail(&self, fail: bool) {
            *self.fetcher.fail.lock().unwrap() = fail;
        }

        fn get(&self, freshness: Freshness) -> Result<Arc<JwkSet>, KeyResolveError> {
            block_on(self.resolver.keys(&self.uri, freshness))
        }
    }

    #[test]
    fn cached_uses_cache_until_ttl() {
        let f = Fixture::new();
        assert!(f.get(Freshness::Cached).is_ok());
        assert!(f.get(Freshness::Cached).is_ok());
        assert_eq!(f.calls(), 1);
        f.advance(3599);
        assert!(f.get(Freshness::Cached).is_ok());
        assert_eq!(f.calls(), 1);
        f.advance(1);
        assert!(f.get(Freshness::Cached).is_ok());
        assert_eq!(f.calls(), 2);
    }

    #[test]
    fn refresh_waits_for_min_interval() {
        let f = Fixture::new();
        assert!(f.get(Freshness::Cached).is_ok());
        f.advance(59);
        assert!(f.get(Freshness::Refresh).is_ok());
        assert_eq!(f.calls(), 1);
        f.advance(1);
        assert!(f.get(Freshness::Refresh).is_ok());
        assert_eq!(f.calls(), 2);
    }

    #[test]
    fn fetch_failure_without_cache() {
        let f = Fixture::new();
        f.fail(true);
        assert!(matches!(
            f.get(Freshness::Cached),
            Err(KeyResolveError::Fetch(JwksFetchError::Timeout))
        ));
    }

    #[test]
    fn failed_refresh_keeps_valid_cache() {
        let f = Fixture::new();
        assert!(f.get(Freshness::Cached).is_ok());
        f.advance(60);
        f.fail(true);
        assert!(matches!(
            f.get(Freshness::Refresh),
            Err(KeyResolveError::Fetch(JwksFetchError::Timeout))
        ));
        assert!(f.get(Freshness::Cached).is_ok());
        assert_eq!(f.calls(), 2);
    }

    #[test]
    fn expired_cache_is_not_served_after_failure() {
        let f = Fixture::new();
        assert!(f.get(Freshness::Cached).is_ok());
        f.advance(3600);
        f.fail(true);
        assert!(matches!(
            f.get(Freshness::Cached),
            Err(KeyResolveError::Fetch(JwksFetchError::Timeout))
        ));
        assert_eq!(f.calls(), 2);
        f.advance(59);
        assert!(matches!(
            f.get(Freshness::Cached),
            Err(KeyResolveError::RefetchTooSoon)
        ));
        assert_eq!(f.calls(), 2);
        f.advance(1);
        assert!(f.get(Freshness::Cached).is_err());
        assert_eq!(f.calls(), 3);
    }

    #[test]
    fn refresh_with_only_expired_cache_is_too_soon() {
        let f = Fixture::new();
        assert!(f.get(Freshness::Cached).is_ok());
        f.advance(3600);
        f.fail(true);
        assert!(f.get(Freshness::Cached).is_err());
        f.advance(30);
        assert!(matches!(
            f.get(Freshness::Refresh),
            Err(KeyResolveError::RefetchTooSoon)
        ));
        assert_eq!(f.calls(), 2);
    }

    #[test]
    fn invalid_jwks_is_not_cached() {
        let f = Fixture::new();
        for body in ["not json", r#"{"keys":[]}"#] {
            *f.fetcher.body.lock().unwrap() = body.to_owned();
            assert!(matches!(
                f.get(Freshness::Refresh),
                Err(KeyResolveError::InvalidJwks)
            ));
            f.advance(60);
        }
    }

    #[test]
    fn invalid_body_keeps_old_cache_and_counts_as_attempt() {
        let f = Fixture::new();
        assert!(f.get(Freshness::Cached).is_ok());
        f.advance(60);
        *f.fetcher.body.lock().unwrap() = "not json".to_owned();
        assert!(matches!(
            f.get(Freshness::Refresh),
            Err(KeyResolveError::InvalidJwks)
        ));
        assert_eq!(f.calls(), 2);
        assert!(f.get(Freshness::Cached).is_ok());
        f.advance(59);
        assert!(f.get(Freshness::Refresh).is_ok());
        assert_eq!(f.calls(), 2);
    }

    /// Stays pending until `open` is set.
    struct GateFetcher {
        calls: AtomicUsize,
        open: std::sync::atomic::AtomicBool,
        body: String,
    }

    impl JwksFetcher for GateFetcher {
        fn fetch<'a>(&'a self, _uri: &'a JwksUri) -> BoxFuture<'a, Result<String, JwksFetchError>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(std::future::poll_fn(move |_| {
                if self.open.load(Ordering::SeqCst) {
                    Poll::Ready(Ok(self.body.clone()))
                } else {
                    Poll::Pending
                }
            }))
        }
    }

    #[test]
    fn refresh_during_a_fetch_does_not_fetch_again() {
        let f = Fixture::new();
        let fetcher = Arc::new(GateFetcher {
            calls: AtomicUsize::new(0),
            open: std::sync::atomic::AtomicBool::new(false),
            body: f.fetcher.body.lock().unwrap().clone(),
        });
        let resolver = JwksResolver::new(Some(fetcher.clone()), f.clock.clone());
        let mut cx = Context::from_waker(Waker::noop());
        let calls = || fetcher.calls.load(Ordering::SeqCst);
        {
            // No keys yet: an unknown kid is refused, a plain request fetches too.
            let mut first = pin!(resolver.keys(&f.uri, Freshness::Cached));
            assert!(first.as_mut().poll(&mut cx).is_pending());
            let mut refresh = pin!(resolver.keys(&f.uri, Freshness::Refresh));
            assert!(matches!(
                refresh.as_mut().poll(&mut cx),
                Poll::Ready(Err(KeyResolveError::RefetchTooSoon))
            ));
            let mut cached = pin!(resolver.keys(&f.uri, Freshness::Cached));
            assert!(cached.as_mut().poll(&mut cx).is_pending());
            assert_eq!(calls(), 2);
            fetcher.open.store(true, Ordering::SeqCst);
            assert!(matches!(first.as_mut().poll(&mut cx), Poll::Ready(Ok(_))));
            assert!(matches!(cached.as_mut().poll(&mut cx), Poll::Ready(Ok(_))));
        }
        // With valid keys: a refresh during a running refresh gets the cached keys.
        f.advance(60);
        fetcher.open.store(false, Ordering::SeqCst);
        let mut running = pin!(resolver.keys(&f.uri, Freshness::Refresh));
        assert!(running.as_mut().poll(&mut cx).is_pending());
        let mut other = pin!(resolver.keys(&f.uri, Freshness::Refresh));
        assert!(matches!(other.as_mut().poll(&mut cx), Poll::Ready(Ok(_))));
        assert_eq!(calls(), 3);
        fetcher.open.store(true, Ordering::SeqCst);
        assert!(matches!(running.as_mut().poll(&mut cx), Poll::Ready(Ok(_))));
        // The finished fetch counts as the last attempt.
        let mut soon = pin!(resolver.keys(&f.uri, Freshness::Refresh));
        assert!(matches!(soon.as_mut().poll(&mut cx), Poll::Ready(Ok(_))));
        assert_eq!(calls(), 3);
    }

    #[test]
    fn a_dropped_fetch_does_not_block_refresh() {
        let f = Fixture::new();
        let fetcher = Arc::new(GateFetcher {
            calls: AtomicUsize::new(0),
            open: std::sync::atomic::AtomicBool::new(false),
            body: f.fetcher.body.lock().unwrap().clone(),
        });
        let resolver = JwksResolver::new(Some(fetcher.clone()), f.clock.clone());
        let mut cx = Context::from_waker(Waker::noop());
        {
            let mut first = pin!(resolver.keys(&f.uri, Freshness::Cached));
            assert!(first.as_mut().poll(&mut cx).is_pending());
        }
        f.advance(60);
        fetcher.open.store(true, Ordering::SeqCst);
        let mut refresh = pin!(resolver.keys(&f.uri, Freshness::Refresh));
        assert!(matches!(refresh.as_mut().poll(&mut cx), Poll::Ready(Ok(_))));
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn no_fetcher_configured() {
        let f = Fixture::new();
        let resolver = JwksResolver::new(None, f.clock.clone());
        let got = block_on(resolver.keys(&f.uri, Freshness::Cached));
        assert!(matches!(
            got,
            Err(KeyResolveError::Fetch(JwksFetchError::Transport(m))) if m == "no fetcher configured"
        ));
    }
}
