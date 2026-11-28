//! The grant types of the token endpoint, as registered handlers.

use komainu_domain::{Client, GrantType};

use super::{Step, TokenError, TokenRequest, TokenService};
use crate::config::ApplicationConfig;
use crate::context::RequestContext;
use crate::port::{BoxFuture, UnitOfWork};

/// One grant type of the token endpoint.
pub(crate) trait GrantHandler: Send + Sync {
    /// The grant type this handler serves.
    fn grant_type(&self) -> GrantType;
    /// Whether the configuration allows it. When false it is not listed and the request
    /// gets `unsupported_grant_type` (decided before client authentication).
    fn is_available(&self, config: &ApplicationConfig) -> bool;
    /// Called after client authentication and the `client.supports_grant` check.
    fn handle<'a>(
        &'a self,
        service: &'a TokenService,
        ctx: &'a RequestContext,
        uow: &'a mut dyn UnitOfWork,
        client: &'a Client,
        request: &'a TokenRequest,
    ) -> BoxFuture<'a, Result<Step, TokenError>>;
}

pub(crate) struct GrantRegistry {
    handlers: Vec<Box<dyn GrantHandler>>,
}

impl GrantRegistry {
    /// Registers every built-in handler in the order authorization_code,
    /// client_credentials, refresh_token, jwt-bearer.
    pub(crate) fn builtin(_config: &ApplicationConfig) -> Self {
        Self {
            handlers: vec![
                Box::new(AuthorizationCodeGrant),
                Box::new(ClientCredentialsGrant),
                Box::new(RefreshTokenGrant),
                Box::new(JwtBearerGrant),
            ],
        }
    }

    /// Looks up by the `grant_type` parameter. `None` when unregistered or unavailable.
    pub(crate) fn find(
        &self,
        grant_type: &str,
        config: &ApplicationConfig,
    ) -> Option<&dyn GrantHandler> {
        self.handlers
            .iter()
            .find(|h| h.grant_type().as_str() == grant_type && h.is_available(config))
            .map(|h| &**h)
    }

    /// Registered and available grant types, in registration order.
    pub(crate) fn available(&self, config: &ApplicationConfig) -> Vec<GrantType> {
        self.handlers
            .iter()
            .filter(|h| h.is_available(config))
            .map(|h| h.grant_type())
            .collect()
    }

    /// Whether registered (not disabled). Ignores `is_available`.
    #[allow(dead_code, reason = "used once grant types can be disabled")]
    pub(crate) fn is_registered(&self, grant_type: GrantType) -> bool {
        self.handlers.iter().any(|h| h.grant_type() == grant_type)
    }
}

struct AuthorizationCodeGrant;
struct ClientCredentialsGrant;
struct RefreshTokenGrant;
struct JwtBearerGrant;

impl GrantHandler for AuthorizationCodeGrant {
    fn grant_type(&self) -> GrantType {
        GrantType::AuthorizationCode
    }
    fn is_available(&self, _config: &ApplicationConfig) -> bool {
        true
    }
    fn handle<'a>(
        &'a self,
        service: &'a TokenService,
        ctx: &'a RequestContext,
        uow: &'a mut dyn UnitOfWork,
        client: &'a Client,
        request: &'a TokenRequest,
    ) -> BoxFuture<'a, Result<Step, TokenError>> {
        Box::pin(service.authorization_code(ctx, uow, client, request))
    }
}

impl GrantHandler for ClientCredentialsGrant {
    fn grant_type(&self) -> GrantType {
        GrantType::ClientCredentials
    }
    fn is_available(&self, _config: &ApplicationConfig) -> bool {
        true
    }
    fn handle<'a>(
        &'a self,
        service: &'a TokenService,
        ctx: &'a RequestContext,
        uow: &'a mut dyn UnitOfWork,
        client: &'a Client,
        request: &'a TokenRequest,
    ) -> BoxFuture<'a, Result<Step, TokenError>> {
        Box::pin(service.client_credentials(ctx, uow, client, request))
    }
}

impl GrantHandler for RefreshTokenGrant {
    fn grant_type(&self) -> GrantType {
        GrantType::RefreshToken
    }
    fn is_available(&self, _config: &ApplicationConfig) -> bool {
        true
    }
    fn handle<'a>(
        &'a self,
        service: &'a TokenService,
        ctx: &'a RequestContext,
        uow: &'a mut dyn UnitOfWork,
        client: &'a Client,
        request: &'a TokenRequest,
    ) -> BoxFuture<'a, Result<Step, TokenError>> {
        Box::pin(service.refresh_token(ctx, uow, client, request))
    }
}

impl GrantHandler for JwtBearerGrant {
    fn grant_type(&self) -> GrantType {
        GrantType::JwtBearer
    }
    fn is_available(&self, config: &ApplicationConfig) -> bool {
        config.issuer.is_some()
    }
    fn handle<'a>(
        &'a self,
        service: &'a TokenService,
        ctx: &'a RequestContext,
        uow: &'a mut dyn UnitOfWork,
        client: &'a Client,
        request: &'a TokenRequest,
    ) -> BoxFuture<'a, Result<Step, TokenError>> {
        Box::pin(service.jwt_bearer(ctx, uow, client, request))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn available_grants_follow_the_configuration() {
        let config = ApplicationConfig::default();
        let registry = GrantRegistry::builtin(&config);
        assert_eq!(
            registry.available(&config),
            [
                GrantType::AuthorizationCode,
                GrantType::ClientCredentials,
                GrantType::RefreshToken
            ]
        );
        let config = config.with_issuer("https://as.example.com");
        assert_eq!(
            registry.available(&config).last(),
            Some(&GrantType::JwtBearer)
        );
        assert_eq!(registry.available(&config).len(), 4);
    }

    #[test]
    fn find_requires_registration_and_availability() {
        let config = ApplicationConfig::default();
        let registry = GrantRegistry::builtin(&config);
        let jwt = GrantType::JwtBearer.as_str();
        assert!(registry.find("refresh_token", &config).is_some());
        assert!(registry.find(jwt, &config).is_none());
        assert!(registry.find("password", &config).is_none());
        let config = config.with_issuer("https://as.example.com");
        assert!(registry.find(jwt, &config).is_some());
        assert!(registry.is_registered(GrantType::JwtBearer));
    }
}
