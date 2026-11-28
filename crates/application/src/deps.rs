use std::sync::Arc;

use crate::assertion::JwksResolver;
use crate::config::ApplicationConfig;
use crate::port::{
    AssertionSubjectResolver, Clock, PasswordHasher, ResourceOwnerAuthenticator, SecureRandom,
    UnitOfWorkFactory,
};

/// Everything a use-case service needs, wired by the caller.
#[derive(Clone)]
pub struct Dependencies {
    pub store: Arc<dyn UnitOfWorkFactory>,
    pub clock: Arc<dyn Clock>,
    pub random: Arc<dyn SecureRandom>,
    pub password_hasher: Arc<dyn PasswordHasher>,
    pub authenticator: Arc<dyn ResourceOwnerAuthenticator>,
    pub config: Arc<ApplicationConfig>,
    /// Shared by every clone of `Dependencies`, so the `jwks_uri` cache is one.
    pub jwks: Arc<JwksResolver>,
    pub subject_resolver: Arc<dyn AssertionSubjectResolver>,
}
