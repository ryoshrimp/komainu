//! In-memory adapters for testing komainu, and conformance tests for store implementations.
//!
//! **Not for production.** [`PlainPasswordHasher`] stores passwords in plain text and
//! [`SequenceRandom`] produces predictable values; use them only in tests.

mod clock;
pub mod conformance;
mod env;
mod jwks;
mod password;
mod random;
mod sealer;
mod store;

pub use clock::FixedClock;
pub use env::TestEnv;
pub use jwks::StaticJwksFetcher;
pub use password::PlainPasswordHasher;
pub use random::SequenceRandom;
pub use sealer::TestKeySealer;
pub use store::{InMemoryState, InMemoryUnitOfWorkFactory};

#[cfg(test)]
mod test_util {
    use std::future::Future;
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    /// Polls a future that never actually suspends (all adapters here are synchronous).
    pub fn block_on<F: Future>(future: F) -> F::Output {
        let mut cx = Context::from_waker(Waker::noop());
        let mut future = pin!(future);
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("in-memory adapters must never suspend"),
        }
    }
}
