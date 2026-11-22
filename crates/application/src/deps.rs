use std::sync::Arc;

use crate::config::ApplicationConfig;
use crate::port::{
    Clock, PasswordHasher, ResourceOwnerAuthenticator, SecureRandom, UnitOfWorkFactory,
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
}
