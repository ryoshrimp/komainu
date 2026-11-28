//! Port traits implemented by adapters.

use std::future::Future;
use std::pin::Pin;

mod authenticator;
mod clock;
mod jwks;
mod password;
mod random;
mod repository;
mod sealer;
mod store;
mod subject;

pub use authenticator::{AuthenticationOutcome, LoginCredentials, ResourceOwnerAuthenticator};
pub use clock::Clock;
pub use jwks::{JwksFetchError, JwksFetcher};
pub use password::{PasswordHashError, PasswordHasher};
pub use random::SecureRandom;
pub use repository::*;
pub use sealer::{KeySealer, SealError};
pub use store::{ListPage, PurgeCounts, StoreError, UnitOfWork, UnitOfWorkFactory};
pub use subject::{AssertionSubjectResolver, MappingTableSubjectResolver};

/// Boxed future returned by port methods so that ports can be trait objects.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
