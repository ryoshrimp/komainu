//! Port traits implemented by adapters.

use std::future::Future;
use std::pin::Pin;

mod authenticator;
mod clock;
mod password;
mod random;
mod repository;
mod store;

pub use authenticator::{AuthenticationOutcome, LoginCredentials, ResourceOwnerAuthenticator};
pub use clock::Clock;
pub use password::{PasswordHashError, PasswordHasher};
pub use random::SecureRandom;
pub use repository::*;
pub use store::{ListPage, PurgeCounts, StoreError, UnitOfWork, UnitOfWorkFactory};

/// Boxed future returned by port methods so that ports can be trait objects.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
