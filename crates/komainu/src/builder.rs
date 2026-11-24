//! [`KomainuBuilder`] and the [`Komainu`] it builds.

use std::sync::Arc;

use komainu_application::{
    AdminService, ApplicationConfig, AuthorizationService, BuiltinAuthenticator, Clock,
    Dependencies, MaintenanceService, PasswordHasher, ResourceOwnerAuthenticator, SecureRandom,
    TokenService, UnitOfWorkFactory,
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

    /// The HTTP settings. Required with `http`.
    ///
    /// The `csrf_cookie_ttl` of `config` is replaced by
    /// `ApplicationConfig::authorization_request_ttl`, because the CSRF cookie must live as
    /// long as the authorization request.
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
    /// Returns a [`BuildError`] when a required part is missing or the password hasher
    /// cannot be created.
    pub fn build(self) -> Result<Komainu, BuildError> {
        let store = self.store.ok_or(BuildError::MissingStore)?;
        let application_config = self.application_config.unwrap_or_default();

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

        let deps = Dependencies {
            store,
            clock,
            random,
            password_hasher,
            authenticator,
            config: Arc::new(application_config),
        };
        let authorization = AuthorizationService::new(deps.clone());
        let token = TokenService::new(deps.clone());

        #[cfg(feature = "http")]
        let state = {
            let state = AppState::new(authorization.clone(), token.clone(), http_config);
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
    /// The Argon2 hasher could not be initialized.
    #[error("failed to initialize the password hasher: {0}")]
    PasswordHasher(#[source] Box<dyn std::error::Error + Send + Sync>),
}
