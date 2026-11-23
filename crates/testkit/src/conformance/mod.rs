//! Conformance tests for [`UnitOfWorkFactory`] implementations.
//!
//! The cases check the contract the application layer relies on: round trips of every
//! record, rollback of dropped units of work, `StoreError::Conflict` on unique violations,
//! purging, and that one authorization code is redeemed only once under concurrency.
//! They only talk to the store through the `komainu_application` ports.
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use komainu_application::UnitOfWorkFactory;
//! # use komainu_testkit::InMemoryUnitOfWorkFactory;
//! # async fn run() {
//! komainu_testkit::conformance::run_store_conformance(|| async {
//!     // Replace with a factory for your own, empty store.
//!     Arc::new(InMemoryUnitOfWorkFactory::new()) as Arc<dyn UnitOfWorkFactory>
//! })
//! .await;
//! # }
//! ```
//!
//! The cases run on the caller's async runtime; no task is spawned, so both
//! `current_thread` and `multi_thread` work.

use std::fmt;
use std::future::Future;
use std::sync::Arc;

use komainu_application::{BoxFuture, StoreError, UnitOfWorkFactory};

mod cases;
mod fixtures;

/// Runs every case against a fresh, empty store from `make_store` and panics with the
/// names and messages of all failed cases.
///
/// `make_store` is called once per case. Each store must be empty (no rows) and must
/// not share data with stores returned by earlier calls.
///
/// # Panics
///
/// Panics when at least one case fails.
pub async fn run_store_conformance<F, Fut>(mut make_store: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Arc<dyn UnitOfWorkFactory>>,
{
    let cases = store_cases();
    let mut failures = Vec::new();
    for case in cases {
        let store = make_store().await;
        if let Err(failure) = (case.run)(store).await {
            failures.push(format!("- {}: {}", case.name, failure));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} store conformance cases failed:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}

/// The individual cases, for adapters that want one test per case.
pub fn store_cases() -> &'static [StoreCase] {
    cases::CASES.as_slice()
}

/// One conformance case.
#[non_exhaustive]
pub struct StoreCase {
    /// The name of the case, unique within [`store_cases`].
    pub name: &'static str,
    /// Runs the case against an empty store.
    #[allow(clippy::type_complexity)]
    pub run: fn(Arc<dyn UnitOfWorkFactory>) -> BoxFuture<'static, Result<(), CaseFailure>>,
}

impl fmt::Debug for StoreCase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoreCase")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// Why a case failed; `Display` gives a one-line message.
#[derive(Debug)]
pub struct CaseFailure {
    message: String,
}

impl CaseFailure {
    /// Creates a failure with `message`.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for CaseFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CaseFailure {}

impl From<StoreError> for CaseFailure {
    fn from(error: StoreError) -> Self {
        Self::new(format!("unexpected store error: {error}"))
    }
}
