use std::sync::Arc;

use komainu_application::{AuthorizationService, SigningKeyService, TokenService};

use crate::csp::ContentSecurityPolicy;
use crate::metadata::AuthorizationServerMetadata;
use crate::screens::{DefaultScreens, ScreenRenderer};

/// Settings of the HTTP layer.
///
/// Build it with [`HttpConfig::new`] (or [`HttpConfig::new_insecure`] for local development)
/// and adjust with the `with_*` methods.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct HttpConfig {
    // All fields are private so that the validated `public_base_url` cannot be replaced.
    public_base_url: String,
    cookie_secure: bool,
    max_body_bytes: usize,
    csrf_cookie_ttl: time::Duration,
    content_security_policy: ContentSecurityPolicy,
}

impl HttpConfig {
    /// Requires an absolute `https` URL with a host and no query or fragment, e.g.
    /// `https://auth.example.com` or `https://example.com/oauth`. Trailing '/' characters are
    /// removed. Paths are built by plain concatenation: `format!("{public_base_url}/login")`.
    ///
    /// Defaults: `cookie_secure` is `true`, `max_body_bytes` is 16384, `csrf_cookie_ttl` is
    /// 600 seconds and the policy is [`ContentSecurityPolicy::strict`].
    ///
    /// # Errors
    ///
    /// Returns an [`HttpConfigError`] when the URL breaks one of the rules above.
    pub fn new(public_base_url: &str) -> Result<Self, HttpConfigError> {
        Self::build(public_base_url, false)
    }

    /// Same as [`HttpConfig::new`] but also accepts `http` (local development only), and
    /// `cookie_secure` defaults to `false`.
    ///
    /// # Errors
    ///
    /// Returns an [`HttpConfigError`] when the URL breaks one of the rules of `new`
    /// (other than the `https` requirement).
    pub fn new_insecure(public_base_url: &str) -> Result<Self, HttpConfigError> {
        Self::build(public_base_url, true)
    }

    fn build(public_base_url: &str, allow_http: bool) -> Result<Self, HttpConfigError> {
        let url = url::Url::parse(public_base_url)
            .map_err(|e| HttpConfigError::NotAbsolute(e.to_string()))?;
        if url.query().is_some() || url.fragment().is_some() {
            return Err(HttpConfigError::QueryOrFragment);
        }
        match url.scheme() {
            "https" => {}
            "http" if allow_http => {}
            "http" => return Err(HttpConfigError::InsecureScheme),
            other => return Err(HttpConfigError::UnsupportedScheme(other.to_owned())),
        }
        if !url.has_host() {
            return Err(HttpConfigError::MissingHost);
        }
        Ok(Self {
            public_base_url: public_base_url.trim_end_matches('/').to_owned(),
            cookie_secure: !allow_http,
            max_body_bytes: 16 * 1024,
            csrf_cookie_ttl: time::Duration::seconds(600),
            content_security_policy: ContentSecurityPolicy::strict(),
        })
    }

    /// Adds `Secure` to cookies.
    #[must_use]
    pub fn with_cookie_secure(mut self, value: bool) -> Self {
        self.cookie_secure = value;
        self
    }

    /// Sets the maximum request body of the form posts.
    #[must_use]
    pub fn with_max_body_bytes(mut self, value: usize) -> Self {
        self.max_body_bytes = value;
        self
    }

    /// Sets the `Max-Age` of the `komainu_csrf` cookie; it should match
    /// `ApplicationConfig::authorization_request_ttl`.
    ///
    /// `komainu::KomainuBuilder` overrides this value with
    /// `ApplicationConfig::authorization_request_ttl`; it only takes effect when you use this
    /// crate directly.
    #[must_use]
    pub fn with_csrf_cookie_ttl(mut self, value: time::Duration) -> Self {
        self.csrf_cookie_ttl = value;
        self
    }

    /// Sets the `Content-Security-Policy` of HTML responses.
    #[must_use]
    pub fn with_content_security_policy(mut self, value: ContentSecurityPolicy) -> Self {
        self.content_security_policy = value;
        self
    }

    /// The external base URL without a trailing '/'.
    pub fn public_base_url(&self) -> &str {
        &self.public_base_url
    }

    /// Whether cookies get the `Secure` attribute.
    pub fn cookie_secure(&self) -> bool {
        self.cookie_secure
    }

    /// The maximum request body of the form posts.
    pub fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }

    /// The `Max-Age` of the `komainu_csrf` cookie.
    pub fn csrf_cookie_ttl(&self) -> time::Duration {
        self.csrf_cookie_ttl
    }

    /// The `Content-Security-Policy` of HTML responses.
    pub fn content_security_policy(&self) -> &ContentSecurityPolicy {
        &self.content_security_policy
    }
}

/// Why a `public_base_url` was rejected by [`HttpConfig::new`] or [`HttpConfig::new_insecure`].
#[non_exhaustive]
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HttpConfigError {
    /// Not an absolute URL. Holds `url::ParseError::to_string()`.
    #[error("public_base_url is not an absolute URL: {0}")]
    NotAbsolute(String),
    /// The URL has a query or a fragment.
    #[error("public_base_url must not have a query or a fragment")]
    QueryOrFragment,
    /// The URL uses `http` where only `https` is accepted.
    #[error("public_base_url must use https")]
    InsecureScheme,
    /// The scheme is neither `https` nor `http`.
    #[error("public_base_url has an unsupported scheme: {0}")]
    UnsupportedScheme(String),
    /// The URL has no host.
    #[error("public_base_url must have a host")]
    MissingHost,
}

/// The shared state of the handlers.
#[derive(Clone)]
pub struct AppState {
    pub(crate) authorization: AuthorizationService,
    pub(crate) token: TokenService,
    pub(crate) config: Arc<HttpConfig>,
    pub(crate) screens: Arc<dyn ScreenRenderer>,
    pub(crate) metadata: Arc<AuthorizationServerMetadata>,
    pub(crate) signing_keys: Option<Arc<SigningKeyService>>,
}

impl AppState {
    /// Creates the state with the built-in screens.
    ///
    /// `authorization` and `token` must be built from the same `Dependencies` (the same
    /// `ApplicationConfig`). The published metadata is derived once, here, from the
    /// `TokenService` configuration, which is the authority.
    pub fn new(
        authorization: AuthorizationService,
        token: TokenService,
        config: HttpConfig,
    ) -> Self {
        let metadata = AuthorizationServerMetadata::new(&config, &token.server_capabilities());
        Self {
            authorization,
            token,
            config: Arc::new(config),
            screens: Arc::new(DefaultScreens),
            metadata: Arc::new(metadata),
            signing_keys: None,
        }
    }

    /// The metadata served at `/.well-known/oauth-authorization-server`.
    pub fn metadata(&self) -> &AuthorizationServerMetadata {
        &self.metadata
    }

    /// Passes the signing key service. `GET /jwks` then serves its keys and the metadata gets
    /// a `jwks_uri` (`{public_base_url}/jwks`); the metadata is derived again.
    #[must_use]
    pub fn with_signing_keys(mut self, service: Arc<SigningKeyService>) -> Self {
        let mut metadata = (*self.metadata).clone();
        metadata.jwks_uri = Some(format!("{}/jwks", self.config.public_base_url()));
        self.metadata = Arc::new(metadata);
        self.signing_keys = Some(service);
        self
    }

    /// Replaces the built-in screens with `screens`.
    #[must_use]
    pub fn with_screens(mut self, screens: Arc<dyn ScreenRenderer>) -> Self {
        self.screens = screens;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_trims_trailing_slashes_and_sets_defaults() {
        let config = HttpConfig::new("https://auth.example.com/").unwrap();
        assert_eq!(config.public_base_url(), "https://auth.example.com");
        assert!(config.cookie_secure());
        assert_eq!(config.max_body_bytes(), 16384);
        assert_eq!(config.csrf_cookie_ttl(), time::Duration::seconds(600));
        assert_eq!(
            config.content_security_policy(),
            &ContentSecurityPolicy::strict()
        );
        assert_eq!(
            HttpConfig::new("https://example.com/oauth//")
                .unwrap()
                .public_base_url(),
            "https://example.com/oauth"
        );
    }

    #[test]
    fn http_needs_new_insecure() {
        assert_eq!(
            HttpConfig::new("http://localhost:8080").unwrap_err(),
            HttpConfigError::InsecureScheme
        );
        let config = HttpConfig::new_insecure("http://localhost:8080").unwrap();
        assert!(!config.cookie_secure());
    }

    #[test]
    fn invalid_urls_are_rejected() {
        assert_eq!(
            HttpConfig::new("https://a.example/?x=1").unwrap_err(),
            HttpConfigError::QueryOrFragment
        );
        assert_eq!(
            HttpConfig::new("https://a.example/#x").unwrap_err(),
            HttpConfigError::QueryOrFragment
        );
        assert!(matches!(
            HttpConfig::new("/relative").unwrap_err(),
            HttpConfigError::NotAbsolute(_)
        ));
        assert_eq!(
            HttpConfig::new("ftp://a.example").unwrap_err(),
            HttpConfigError::UnsupportedScheme("ftp".to_owned())
        );
        // A host-less http(s) URL is already rejected by the URL parser.
        assert!(matches!(
            HttpConfig::new_insecure("https:///").unwrap_err(),
            HttpConfigError::NotAbsolute(_)
        ));
    }
}
