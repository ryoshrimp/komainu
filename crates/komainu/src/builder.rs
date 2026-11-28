//! [`KomainuBuilder`] and the [`Komainu`] it builds.

use std::sync::Arc;

use komainu_application::{
    AdminService, ApplicationConfig, ApplicationConfigError, AssertionSubjectResolver,
    AuthorizationService, BuiltinAuthenticator, Clock, Dependencies, JwksFetcher, JwksResolver,
    KeySealer, MaintenanceService, MappingTableSubjectResolver, PasswordHasher,
    ResourceOwnerAuthenticator, SecureRandom, SigningKeyService, TokenService, UnitOfWorkFactory,
};
#[cfg(feature = "http")]
use komainu_http::{AppState, HttpConfig, ScreenRenderer};

/// The use case services and, with the `http` feature, the HTTP router.
///
/// Cloning is cheap: the services share their dependencies.
#[derive(Clone)]
pub struct Komainu {
    authorization: AuthorizationService,
    token: TokenService,
    admin: AdminService,
    maintenance: MaintenanceService,
    signing_keys: Option<Arc<SigningKeyService>>,
    #[cfg(feature = "http")]
    state: AppState,
}

impl Komainu {
    /// Starts a builder.
    pub fn builder() -> KomainuBuilder {
        KomainuBuilder::default()
    }

    /// The authorization use cases.
    pub fn authorization(&self) -> &AuthorizationService {
        &self.authorization
    }

    /// The token use cases.
    pub fn token(&self) -> &TokenService {
        &self.token
    }

    /// Client and user administration.
    pub fn admin(&self) -> &AdminService {
        &self.admin
    }

    /// Readiness checks and the purge of expired data.
    pub fn maintenance(&self) -> &MaintenanceService {
        &self.maintenance
    }

    /// The signing key service, when `ApplicationConfig::signing` is set. Call its
    /// `rotate_due` at startup and periodically to create and retire keys.
    pub fn signing_keys(&self) -> Option<&Arc<SigningKeyService>> {
        self.signing_keys.as_ref()
    }

    /// The router with the authorization server endpoints. Every call returns a new router
    /// over the same state, so it can be merged into or nested in your own axum app.
    #[cfg(feature = "http")]
    pub fn router(&self) -> axum::Router {
        komainu_http::router(self.state.clone())
    }

    /// The RFC 8414 metadata. It is the same value the router serves at
    /// `/.well-known/oauth-authorization-server`, and it implements
    /// `axum::response::IntoResponse`.
    ///
    /// The router always serves the metadata at that path relative to where it is mounted.
    /// When the issuer has a path and you mount the router with
    /// `Router::nest("/auth", komainu.router())`, RFC 8414 §3.1 expects the metadata at
    /// `/.well-known/oauth-authorization-server/auth` on the host. Route that URL to
    /// `/auth/.well-known/oauth-authorization-server`, or add your own route that returns
    /// this value.
    #[cfg(feature = "http")]
    pub fn metadata(&self) -> &komainu_http::AuthorizationServerMetadata {
        self.state.metadata()
    }
}

/// Collects the parts of a [`Komainu`]; see [`KomainuBuilder::build`].
///
/// Setting the same part twice keeps the later value.
#[must_use]
#[derive(Default)]
pub struct KomainuBuilder {
    store: Option<Arc<dyn UnitOfWorkFactory>>,
    application_config: Option<ApplicationConfig>,
    clock: Option<Arc<dyn Clock>>,
    random: Option<Arc<dyn SecureRandom>>,
    password_hasher: Option<Arc<dyn PasswordHasher>>,
    authenticator: Option<Arc<dyn ResourceOwnerAuthenticator>>,
    jwks_fetcher: Option<Arc<dyn JwksFetcher>>,
    subject_resolver: Option<Arc<dyn AssertionSubjectResolver>>,
    key_sealer: Option<Arc<dyn KeySealer>>,
    #[cfg(feature = "http")]
    http_config: Option<HttpConfig>,
    #[cfg(feature = "http")]
    screens: Option<Arc<dyn ScreenRenderer>>,
}

impl KomainuBuilder {
    /// The persistence. Required.
    pub fn store(mut self, store: impl UnitOfWorkFactory + 'static) -> Self {
        self.store = Some(Arc::new(store));
        self
    }

    /// The persistence, already shared. Replaces a store set by [`Self::store`].
    pub fn store_arc(mut self, store: Arc<dyn UnitOfWorkFactory>) -> Self {
        self.store = Some(store);
        self
    }

    /// Default: `ApplicationConfig::default()`.
    pub fn application_config(mut self, config: ApplicationConfig) -> Self {
        self.application_config = Some(config);
        self
    }

    /// Default with `std`: `SystemClock`. Required without `std`.
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Default with `std`: `OsSecureRandom`. Required without `std`.
    pub fn random(mut self, random: Arc<dyn SecureRandom>) -> Self {
        self.random = Some(random);
        self
    }

    /// Default with `std`: `Argon2PasswordHasher::new()`. Required without `std`. Also used
    /// by the administration to hash the passwords it sets.
    pub fn password_hasher(mut self, hasher: Arc<dyn PasswordHasher>) -> Self {
        self.password_hasher = Some(hasher);
        self
    }

    /// Default: `BuiltinAuthenticator` over the password hasher.
    pub fn authenticator(mut self, authenticator: Arc<dyn ResourceOwnerAuthenticator>) -> Self {
        self.authenticator = Some(authenticator);
        self
    }

    /// Fetches the JWKS of clients registered with `jwks_uri`. Default with `jwks-uri`:
    /// `ReqwestJwksFetcher` with its default settings. Without a fetcher, `jwks_uri` clients
    /// cannot authenticate.
    pub fn jwks_fetcher(mut self, fetcher: Arc<dyn JwksFetcher>) -> Self {
        self.jwks_fetcher = Some(fetcher);
        self
    }

    /// Maps the `sub` of a jwt-bearer assertion to a user. Default:
    /// `MappingTableSubjectResolver`.
    pub fn subject_resolver(mut self, resolver: Arc<dyn AssertionSubjectResolver>) -> Self {
        self.subject_resolver = Some(resolver);
        self
    }

    /// Encrypts the signing keys at rest. Required when `ApplicationConfig::signing` is set;
    /// ignored otherwise.
    pub fn key_sealer(mut self, sealer: Arc<dyn KeySealer>) -> Self {
        self.key_sealer = Some(sealer);
        self
    }

    /// The HTTP settings. Required with `http`.
    ///
    /// The `csrf_cookie_ttl` of `config` is replaced by
    /// `ApplicationConfig::authorization_request_ttl`, because the CSRF cookie must live as
    /// long as the authorization request. When `ApplicationConfig::issuer` is unset it
    /// becomes the public base URL, which enables `private_key_jwt`.
    #[cfg(feature = "http")]
    pub fn http_config(mut self, config: HttpConfig) -> Self {
        self.http_config = Some(config);
        self
    }

    /// The screens. Default: `DefaultScreens`.
    #[cfg(feature = "http")]
    pub fn screens(mut self, screens: Arc<dyn ScreenRenderer>) -> Self {
        self.screens = Some(screens);
        self
    }

    /// Assembles the parts. Does no I/O: connect and migrate the store beforehand.
    ///
    /// # Errors
    ///
    /// Returns a [`BuildError`] when the application configuration is invalid, a required
    /// part is missing or the password hasher cannot be created.
    pub fn build(self) -> Result<Komainu, BuildError> {
        #[cfg_attr(not(feature = "http"), expect(unused_mut))]
        let mut application_config = self.application_config.unwrap_or_default();
        application_config
            .validate()
            .map_err(BuildError::InvalidConfig)?;
        let store = self.store.ok_or(BuildError::MissingStore)?;

        #[cfg(not(feature = "std"))]
        let (clock, random, password_hasher) = (
            self.clock.ok_or(BuildError::MissingComponent("clock"))?,
            self.random.ok_or(BuildError::MissingComponent("random"))?,
            self.password_hasher
                .ok_or(BuildError::MissingComponent("password_hasher"))?,
        );
        #[cfg(feature = "std")]
        let (clock, random, password_hasher) = {
            let clock = self
                .clock
                .unwrap_or_else(|| Arc::new(komainu_adapter_std::SystemClock));
            let random = self
                .random
                .unwrap_or_else(|| Arc::new(komainu_adapter_std::OsSecureRandom));
            let hasher: Arc<dyn PasswordHasher> = match self.password_hasher {
                Some(hasher) => hasher,
                None => Arc::new(
                    komainu_adapter_std::Argon2PasswordHasher::new()
                        .map_err(|e| BuildError::PasswordHasher(Box::new(e)))?,
                ),
            };
            (clock, random, hasher)
        };

        let authenticator = self
            .authenticator
            .unwrap_or_else(|| Arc::new(BuiltinAuthenticator::new(password_hasher.clone())));

        #[cfg(feature = "http")]
        let http_config = self.http_config.ok_or(BuildError::MissingHttpConfig)?;
        #[cfg(feature = "http")]
        let http_config =
            http_config.with_csrf_cookie_ttl(application_config.authorization_request_ttl);
        #[cfg(feature = "http")]
        if application_config.issuer.is_none() {
            application_config.issuer = Some(http_config.public_base_url().to_owned());
        }

        let jwks_fetcher = self.jwks_fetcher;
        #[cfg(feature = "jwks-uri")]
        let jwks_fetcher = match jwks_fetcher {
            Some(fetcher) => Some(fetcher),
            None => {
                let fetcher = komainu_adapter_http::ReqwestJwksFetcher::new(
                    komainu_adapter_http::JwksFetcherConfig::default(),
                )
                .map_err(BuildError::JwksFetcher)?;
                Some(Arc::new(fetcher) as Arc<dyn JwksFetcher>)
            }
        };

        let signing_keys = match &application_config.signing {
            Some(signing) => {
                let sealer = self.key_sealer.ok_or(BuildError::MissingKeySealer)?;
                Some(Arc::new(SigningKeyService::new(
                    store.clone(),
                    sealer,
                    clock.clone(),
                    random.clone(),
                    signing.clone(),
                )))
            }
            None => None,
        };

        let deps = Dependencies {
            store,
            jwks: Arc::new(JwksResolver::new(jwks_fetcher, clock.clone())),
            subject_resolver: self
                .subject_resolver
                .unwrap_or_else(|| Arc::new(MappingTableSubjectResolver)),
            clock,
            random,
            password_hasher,
            signing_keys: signing_keys.clone(),
            authenticator,
            config: Arc::new(application_config),
        };
        let authorization = AuthorizationService::new(deps.clone());
        let token = TokenService::new(deps.clone());

        #[cfg(feature = "http")]
        let state = {
            let state = AppState::new(authorization.clone(), token.clone(), http_config);
            let state = match &signing_keys {
                Some(service) => state.with_signing_keys(service.clone()),
                None => state,
            };
            match self.screens {
                Some(screens) => state.with_screens(screens),
                None => state,
            }
        };

        Ok(Komainu {
            authorization,
            token,
            admin: AdminService::new(deps.clone()),
            maintenance: MaintenanceService::new(deps),
            signing_keys,
            #[cfg(feature = "http")]
            state,
        })
    }
}

/// Why [`KomainuBuilder::build`] failed. All of them are programming or startup errors.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    /// No store was given.
    #[error("a store is required; call KomainuBuilder::store")]
    MissingStore,
    /// Without the `std` feature, this component has no default.
    #[error("{0} is required when the `std` feature is disabled")]
    MissingComponent(&'static str),
    /// With the `http` feature, the HTTP settings are required.
    #[error("an HTTP configuration is required; call KomainuBuilder::http_config")]
    MissingHttpConfig,
    /// `ApplicationConfig::signing` is set but no key sealer was given.
    #[error("a key sealer is required when signing is enabled; call KomainuBuilder::key_sealer")]
    MissingKeySealer,
    /// `ApplicationConfig::validate` failed.
    #[error("invalid application configuration: {0}")]
    InvalidConfig(#[source] ApplicationConfigError),
    /// The Argon2 hasher could not be initialized.
    #[error("failed to initialize the password hasher: {0}")]
    PasswordHasher(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The HTTP client for `jwks_uri` could not be created.
    #[cfg(feature = "jwks-uri")]
    #[error("failed to build the JWKS fetcher: {0}")]
    JwksFetcher(#[source] komainu_adapter_http::BuildError),
}
