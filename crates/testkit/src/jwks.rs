use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use komainu_application::port::BoxFuture;
use komainu_application::{JwksFetchError, JwksFetcher};
use komainu_domain::JwksUri;

/// A fake that answers per URI and counts the calls.
///
/// A URI without a configured response gets `Err(JwksFetchError::Status(404))`.
#[derive(Debug, Default, Clone)]
pub struct StaticJwksFetcher {
    state: Arc<Mutex<State>>,
}

#[derive(Debug, Default)]
struct State {
    responses: HashMap<JwksUri, Result<String, JwksFetchError>>,
    calls: HashMap<JwksUri, usize>,
}

impl StaticJwksFetcher {
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets (overwrites) the response for `uri`.
    pub fn set(&self, uri: &JwksUri, response: Result<String, JwksFetchError>) {
        self.lock().responses.insert(uri.clone(), response);
    }

    /// How many times `uri` was fetched.
    pub fn calls(&self, uri: &JwksUri) -> usize {
        self.lock().calls.get(uri).copied().unwrap_or(0)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// `JwksFetchError` is not `Clone`: rebuild it from its kind.
fn rebuild(error: &JwksFetchError) -> JwksFetchError {
    match error {
        JwksFetchError::Forbidden => JwksFetchError::Forbidden,
        JwksFetchError::Timeout => JwksFetchError::Timeout,
        JwksFetchError::Status(s) => JwksFetchError::Status(*s),
        JwksFetchError::TooLarge => JwksFetchError::TooLarge,
        JwksFetchError::Transport(m) => JwksFetchError::Transport(m.clone()),
        other => JwksFetchError::Transport(other.to_string()),
    }
}

impl JwksFetcher for StaticJwksFetcher {
    fn fetch<'a>(&'a self, uri: &'a JwksUri) -> BoxFuture<'a, Result<String, JwksFetchError>> {
        let mut state = self.lock();
        *state.calls.entry(uri.clone()).or_insert(0) += 1;
        let out = match state.responses.get(uri) {
            Some(Ok(body)) => Ok(body.clone()),
            Some(Err(e)) => Err(rebuild(e)),
            None => Err(JwksFetchError::Status(404)),
        };
        Box::pin(std::future::ready(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::block_on;

    fn uri(path: &str) -> JwksUri {
        JwksUri::try_new(format!("https://c.example.com/{path}")).unwrap()
    }

    #[test]
    fn unset_uri_is_404_and_set_body_is_returned() {
        let fetcher = StaticJwksFetcher::new();
        let (a, b) = (uri("a"), uri("b"));
        assert!(matches!(
            block_on(fetcher.fetch(&a)),
            Err(JwksFetchError::Status(404))
        ));
        fetcher.set(&a, Ok("{}".to_owned()));
        assert_eq!(block_on(fetcher.fetch(&a)).unwrap(), "{}");
        fetcher.set(&b, Err(JwksFetchError::Timeout));
        for _ in 0..2 {
            assert!(matches!(
                block_on(fetcher.fetch(&b)),
                Err(JwksFetchError::Timeout)
            ));
        }
        assert_eq!(fetcher.calls(&a), 2);
        assert_eq!(fetcher.calls(&b), 2);
        assert_eq!(fetcher.calls(&uri("c")), 0);
    }
}
