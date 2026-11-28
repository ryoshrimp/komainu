//! The client authentication methods of `/token` and `/revoke`, as registered handlers.

use komainu_domain::{Client, TokenEndpointAuthMethod};
use komainu_jose::Algorithm;

use super::{ClientAuthentication, Endpoint, TokenError, TokenService};
use crate::config::ApplicationConfig;
use crate::context::RequestContext;
use crate::port::{BoxFuture, UnitOfWork};

/// The request's unit of work and the authenticated client.
pub(crate) type Authenticated = (Box<dyn UnitOfWork>, Client);

/// How the client presented its credentials. `None` when it presented none.
pub(crate) fn presented_method(auth: &ClientAuthentication) -> Option<TokenEndpointAuthMethod> {
    match auth {
        ClientAuthentication::Basic { .. } => Some(TokenEndpointAuthMethod::ClientSecretBasic),
        ClientAuthentication::Post { .. } => Some(TokenEndpointAuthMethod::ClientSecretPost),
        ClientAuthentication::PublicId { .. } => Some(TokenEndpointAuthMethod::None),
        ClientAuthentication::Assertion { .. } => Some(TokenEndpointAuthMethod::PrivateKeyJwt),
        ClientAuthentication::None => None,
    }
}

/// One client authentication method of `/token` and `/revoke`.
pub(crate) trait ClientAuthMethod: Send + Sync {
    /// The method this handler serves.
    fn method(&self) -> TokenEndpointAuthMethod;
    /// Whether to list it, from the configuration: `none` follows
    /// `config.allow_public_clients`, `private_key_jwt` follows `config.issuer.is_some()`,
    /// `client_secret_basic` and `client_secret_post` are always available. Whether
    /// authentication succeeds is decided in `authenticate`.
    fn is_available(&self, config: &ApplicationConfig) -> bool;
    /// Values for `*_auth_signing_alg_values_supported`.
    fn signing_algs(&self) -> &'static [Algorithm];
    /// Called only when `presented_method(auth) == Some(self.method())`. On success returns
    /// the request's unit of work and the client; failures are audited here.
    fn authenticate<'a>(
        &'a self,
        service: &'a TokenService,
        ctx: &'a RequestContext,
        auth: &'a ClientAuthentication,
        endpoint: Endpoint,
    ) -> BoxFuture<'a, Result<Authenticated, TokenError>>;
}

pub(crate) struct AuthMethodRegistry {
    methods: Vec<Box<dyn ClientAuthMethod>>,
}

impl AuthMethodRegistry {
    /// Registers every built-in method in the order client_secret_basic,
    /// client_secret_post, private_key_jwt, none, except `config.disabled_auth_methods`.
    pub(crate) fn builtin(config: &ApplicationConfig) -> Self {
        let methods: Vec<Box<dyn ClientAuthMethod>> = vec![
            Box::new(ClientSecretBasic),
            Box::new(ClientSecretPost),
            Box::new(PrivateKeyJwt),
            Box::new(PublicNone),
        ];
        Self {
            methods: methods
                .into_iter()
                .filter(|m| !config.disabled_auth_methods.contains(&m.method()))
                .collect(),
        }
    }

    pub(crate) fn find(&self, method: TokenEndpointAuthMethod) -> Option<&dyn ClientAuthMethod> {
        self.methods
            .iter()
            .find(|m| m.method() == method)
            .map(|m| &**m)
    }

    /// Registered and available methods, in registration order.
    pub(crate) fn available(&self, config: &ApplicationConfig) -> Vec<TokenEndpointAuthMethod> {
        self.methods
            .iter()
            .filter(|m| m.is_available(config))
            .map(|m| m.method())
            .collect()
    }

    /// The union of the available methods' `signing_algs`, without duplicates.
    pub(crate) fn signing_algs(&self, config: &ApplicationConfig) -> Vec<Algorithm> {
        let mut algs = Vec::new();
        for method in self.methods.iter().filter(|m| m.is_available(config)) {
            for alg in method.signing_algs() {
                if !algs.contains(alg) {
                    algs.push(*alg);
                }
            }
        }
        algs
    }

    /// Whether registered (not disabled). Ignores `is_available`.
    #[allow(
        dead_code,
        reason = "only the tests use it; authentication goes through `find`"
    )]
    pub(crate) fn is_registered(&self, method: TokenEndpointAuthMethod) -> bool {
        self.find(method).is_some()
    }
}

struct ClientSecretBasic;
struct ClientSecretPost;
struct PrivateKeyJwt;
struct PublicNone;

impl ClientAuthMethod for ClientSecretBasic {
    fn method(&self) -> TokenEndpointAuthMethod {
        TokenEndpointAuthMethod::ClientSecretBasic
    }
    fn is_available(&self, _config: &ApplicationConfig) -> bool {
        true
    }
    fn signing_algs(&self) -> &'static [Algorithm] {
        &[]
    }
    fn authenticate<'a>(
        &'a self,
        service: &'a TokenService,
        ctx: &'a RequestContext,
        auth: &'a ClientAuthentication,
        _endpoint: Endpoint,
    ) -> BoxFuture<'a, Result<Authenticated, TokenError>> {
        Box::pin(service.authenticate_presented(ctx, auth))
    }
}

impl ClientAuthMethod for ClientSecretPost {
    fn method(&self) -> TokenEndpointAuthMethod {
        TokenEndpointAuthMethod::ClientSecretPost
    }
    fn is_available(&self, _config: &ApplicationConfig) -> bool {
        true
    }
    fn signing_algs(&self) -> &'static [Algorithm] {
        &[]
    }
    fn authenticate<'a>(
        &'a self,
        service: &'a TokenService,
        ctx: &'a RequestContext,
        auth: &'a ClientAuthentication,
        _endpoint: Endpoint,
    ) -> BoxFuture<'a, Result<Authenticated, TokenError>> {
        Box::pin(service.authenticate_presented(ctx, auth))
    }
}

impl ClientAuthMethod for PublicNone {
    fn method(&self) -> TokenEndpointAuthMethod {
        TokenEndpointAuthMethod::None
    }
    fn is_available(&self, config: &ApplicationConfig) -> bool {
        config.allow_public_clients
    }
    fn signing_algs(&self) -> &'static [Algorithm] {
        &[]
    }
    fn authenticate<'a>(
        &'a self,
        service: &'a TokenService,
        ctx: &'a RequestContext,
        auth: &'a ClientAuthentication,
        _endpoint: Endpoint,
    ) -> BoxFuture<'a, Result<Authenticated, TokenError>> {
        Box::pin(service.authenticate_presented(ctx, auth))
    }
}

impl ClientAuthMethod for PrivateKeyJwt {
    fn method(&self) -> TokenEndpointAuthMethod {
        TokenEndpointAuthMethod::PrivateKeyJwt
    }
    fn is_available(&self, config: &ApplicationConfig) -> bool {
        config.issuer.is_some()
    }
    fn signing_algs(&self) -> &'static [Algorithm] {
        &[Algorithm::Rs256, Algorithm::Es256]
    }
    fn authenticate<'a>(
        &'a self,
        service: &'a TokenService,
        ctx: &'a RequestContext,
        auth: &'a ClientAuthentication,
        endpoint: Endpoint,
    ) -> BoxFuture<'a, Result<Authenticated, TokenError>> {
        Box::pin(async move {
            let ClientAuthentication::Assertion {
                client_id,
                assertion,
            } = auth
            else {
                unreachable!("only called for a presented assertion");
            };
            service
                .authenticate_assertion(ctx, client_id.as_deref(), assertion, endpoint)
                .await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn available_methods_follow_the_configuration() {
        use TokenEndpointAuthMethod::*;
        let config = ApplicationConfig::default();
        let registry = AuthMethodRegistry::builtin(&config);
        assert_eq!(
            registry.available(&config),
            [ClientSecretBasic, ClientSecretPost]
        );
        assert!(registry.signing_algs(&config).is_empty());

        let with_issuer = config.clone().with_issuer("https://as.example.com");
        assert_eq!(
            registry.available(&with_issuer),
            [ClientSecretBasic, ClientSecretPost, PrivateKeyJwt]
        );
        assert_eq!(
            registry.signing_algs(&with_issuer),
            [Algorithm::Rs256, Algorithm::Es256]
        );

        let public_only = config.with_allow_public_clients(true);
        assert_eq!(
            registry.available(&public_only),
            [ClientSecretBasic, ClientSecretPost, None]
        );

        let with_public = with_issuer.with_allow_public_clients(true);
        assert_eq!(
            registry.available(&with_public),
            [ClientSecretBasic, ClientSecretPost, PrivateKeyJwt, None]
        );
        assert!(registry.is_registered(None));
    }
}
