//! Use cases and ports of the komainu OAuth 2.0 authorization server.
//!
//! This crate defines the port traits that adapters implement (persistence,
//! clock, randomness, password hashing, resource owner authentication) and the
//! building blocks shared by the use cases: request context, audit events,
//! configuration, dependency wiring, and ID/token generation.

pub mod admin;
pub mod audit;
pub mod authentication;
pub mod authorization;
pub mod config;
pub mod context;
pub mod deps;
pub mod ids;
pub mod maintenance;
pub mod port;
mod support;
pub mod token;

pub use admin::{AdminError, AdminService, ClientView, RegisterClient, RegisteredClient, UserView};
pub use audit::{AuditActor, AuditEvent, AuditKind, AuditOutcome};
pub use authentication::BuiltinAuthenticator;
pub use authorization::{
    AuthorizationService, AuthorizeError, AuthorizeErrorCode, AuthorizeOutcome, AuthorizeParams,
    ConsentPrompt, LoggedIn, LoginError, LoginFormView, NonRedirectableError, ScopeView,
    StartResult,
};
pub use config::{ApplicationConfig, ScopeDefinition};
pub use context::RequestContext;
pub use deps::Dependencies;
pub use ids::{new_opaque_token, new_uuid_v7};
pub use maintenance::{MaintenanceService, PurgeReport};
pub use port::*;
pub use token::{
    AccessTokenInfo, ClientAuthentication, TokenError, TokenRequest, TokenResponse, TokenService,
};
