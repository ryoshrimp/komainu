//! Use cases and ports of the komainu OAuth 2.0 authorization server.
//!
//! This crate defines the port traits that adapters implement (persistence,
//! clock, randomness, password hashing, resource owner authentication) and the
//! building blocks shared by the use cases: request context, audit events,
//! configuration, dependency wiring, and ID/token generation.

pub mod admin;
pub mod assertion;
pub mod audit;
pub mod authentication;
pub mod authorization;
pub mod capabilities;
pub mod config;
pub mod context;
pub mod deps;
pub mod ids;
pub mod maintenance;
pub mod port;
pub mod signing;
mod support;
pub mod token;

pub use admin::{
    AdminError, AdminService, ClientView, IssuerView, RegisterClient, RegisterIssuer,
    RegisteredClient, SubjectMappingView, UserView,
};
pub use assertion::{
    ASSERTION_LEEWAY, ASSERTION_MAX_LEN, ASSERTION_MAX_LIFETIME, CLIENT_ASSERTION_TYPE_JWT_BEARER,
    GRANT_TYPE_JWT_BEARER, JWKS_CACHE_TTL, JWKS_MIN_REFETCH_INTERVAL, JwksResolver,
};
pub use audit::{AuditActor, AuditEvent, AuditKind, AuditOutcome};
pub use authentication::BuiltinAuthenticator;
pub use authorization::{
    AuthorizationService, AuthorizeError, AuthorizeErrorCode, AuthorizeOutcome, AuthorizeParams,
    ConsentPrompt, LoggedIn, LoginError, LoginFormView, NonRedirectableError, ScopeView,
    StartResult,
};
pub use capabilities::{ResponseMode, ResponseType, ServerCapabilities};
pub use config::{ApplicationConfig, ApplicationConfigError, ScopeDefinition};
pub use context::RequestContext;
pub use deps::Dependencies;
pub use ids::{new_opaque_token, new_uuid_v7};
pub use maintenance::{MaintenanceService, PurgeReport};
pub use port::*;
pub use signing::{
    RevokeOutcome, RotationReport, SigningConfig, SigningConfigError, SigningKeyError,
    SigningKeyService, SigningKeySummary,
};
pub use token::{
    AccessTokenInfo, ClientAuthentication, RevocationError, RevocationRequest, TokenError,
    TokenRequest, TokenResponse, TokenService, TokenTypeHint,
};
