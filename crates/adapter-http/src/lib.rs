//! SSRF-safe `jwks_uri` fetcher built on reqwest.

mod ip;

use std::error::Error as _;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use komainu_application::{BoxFuture, JwksFetchError, JwksFetcher};
use komainu_domain::JwksUri;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::redirect::Policy;

use ip::is_global;

/// Settings of [`ReqwestJwksFetcher`].
#[derive(Debug, Clone)]
pub struct JwksFetcherConfig {
    /// Limit for the whole exchange, from connecting to reading the body. Defaults to 5 seconds.
    pub timeout: Duration,
    /// Maximum body size in bytes. Defaults to 65536.
    pub max_body_bytes: usize,
    /// Allows non-global addresses and the http scheme. For tests only. Defaults to `false`.
    pub allow_non_global_for_testing: bool,
}

impl Default for JwksFetcherConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            max_body_bytes: 65536,
            allow_non_global_for_testing: false,
        }
    }
}

/// Failure to build the HTTP client.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("failed to build HTTP client: {0}")]
    Client(String),
}

/// Every resolved address was non-global.
#[derive(Debug, thiserror::Error)]
#[error("destination resolves only to non-global addresses")]
struct ForbiddenAddress;

struct GlobalOnlyResolver {
    allow_non_global: bool,
}

impl Resolve for GlobalOnlyResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let allow_non_global = self.allow_non_global;
        Box::pin(async move {
            let found = tokio::net::lookup_host((name.as_str(), 0)).await?;
            let addrs: Vec<SocketAddr> = found
                .filter(|a| allow_non_global || is_global(a.ip()))
                .collect();
            if addrs.is_empty() {
                return Err(Box::new(ForbiddenAddress) as Box<dyn std::error::Error + Send + Sync>);
            }
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

/// [`JwksFetcher`] that refuses non-global destinations, redirects, proxies and oversized bodies.
pub struct ReqwestJwksFetcher {
    client: reqwest::Client,
    config: JwksFetcherConfig,
}

impl ReqwestJwksFetcher {
    pub fn new(config: JwksFetcherConfig) -> Result<Self, BuildError> {
        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .no_proxy()
            .timeout(config.timeout)
            .user_agent(concat!("komainu/", env!("CARGO_PKG_VERSION")))
            .https_only(!config.allow_non_global_for_testing)
            .dns_resolver(Arc::new(GlobalOnlyResolver {
                allow_non_global: config.allow_non_global_for_testing,
            }))
            .build()
            .map_err(|e| BuildError::Client(e.to_string()))?;
        Ok(Self { client, config })
    }

    async fn do_fetch(&self, uri: &JwksUri) -> Result<String, JwksFetchError> {
        let url = reqwest::Url::parse(uri.as_str())
            .map_err(|e| JwksFetchError::Transport(e.to_string()))?;
        if !self.config.allow_non_global_for_testing {
            if url.scheme() != "https" {
                return Err(JwksFetchError::Forbidden);
            }
            // IP literals bypass the DNS resolver, so check them here.
            let literal = url
                .host_str()
                .map(|h| h.trim_start_matches('[').trim_end_matches(']'))
                .and_then(|h| h.parse::<IpAddr>().ok());
            if literal.is_some_and(|ip| !is_global(ip)) {
                return Err(JwksFetchError::Forbidden);
            }
        }

        let mut response = self
            .client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(map_error)?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(JwksFetchError::Status(response.status().as_u16()));
        }
        let max = self.config.max_body_bytes;
        if response.content_length().is_some_and(|n| n > max as u64) {
            return Err(JwksFetchError::TooLarge);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(map_error)? {
            if body.len() + chunk.len() > max {
                return Err(JwksFetchError::TooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        String::from_utf8(body).map_err(|_| JwksFetchError::Transport("invalid utf-8".to_owned()))
    }
}

fn map_error(e: reqwest::Error) -> JwksFetchError {
    if e.is_timeout() {
        return JwksFetchError::Timeout;
    }
    let mut source = e.source();
    while let Some(s) = source {
        if s.is::<ForbiddenAddress>() {
            return JwksFetchError::Forbidden;
        }
        source = s.source();
    }
    JwksFetchError::Transport(e.to_string())
}

impl JwksFetcher for ReqwestJwksFetcher {
    fn fetch<'a>(&'a self, uri: &'a JwksUri) -> BoxFuture<'a, Result<String, JwksFetchError>> {
        Box::pin(async move {
            let result = self.do_fetch(uri).await;
            if let Err(e) = &result {
                tracing::warn!(uri = uri.as_str(), error = %e, "jwks fetch failed");
            }
            result
        })
    }
}
