use komainu_domain::JwksUri;

use super::BoxFuture;

/// Fetches a `jwks_uri`.
pub trait JwksFetcher: Send + Sync + 'static {
    /// Fetches the JSON body of the JWKS at `uri`. Does not parse it.
    fn fetch<'a>(&'a self, uri: &'a JwksUri) -> BoxFuture<'a, Result<String, JwksFetchError>>;
}

/// Why a JWKS could not be fetched.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JwksFetchError {
    /// The destination address or scheme is not allowed (SSRF protection).
    #[error("destination not allowed")]
    Forbidden,
    #[error("timed out")]
    Timeout,
    /// A status other than 200 (3xx included).
    #[error("unexpected status {0}")]
    Status(u16),
    #[error("response too large")]
    TooLarge,
    #[error("transport error: {0}")]
    Transport(String),
}
