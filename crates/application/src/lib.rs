//! Use cases and ports of the komainu OAuth 2.0 authorization server.
//!
//! This crate defines the port traits that adapters implement (persistence,
//! clock, randomness, password hashing, resource owner authentication) and the
//! building blocks shared by the use cases: request context, audit events,
//! configuration, dependency wiring, and ID/token generation.

pub mod audit;
pub mod authentication;
pub mod config;
pub mod context;
pub mod deps;
pub mod ids;
pub mod port;

pub use audit::{AuditActor, AuditEvent, AuditKind, AuditOutcome};
pub use authentication::BuiltinAuthenticator;
pub use config::{ApplicationConfig, ScopeDefinition};
pub use context::RequestContext;
pub use deps::Dependencies;
pub use ids::{new_opaque_token, new_uuid_v7};
pub use port::*;
