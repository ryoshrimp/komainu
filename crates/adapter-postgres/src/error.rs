//! Mapping from sqlx errors to the application's [`StoreError`].

use komainu_application::StoreError;

/// SQLSTATE of a unique (or primary key) violation.
const UNIQUE_VIOLATION: &str = "23505";
/// SQLSTATEs of serialization failures and deadlocks, which callers may retry.
const RETRYABLE: [&str; 2] = ["40001", "40P01"];

/// Converts a sqlx error: unique violations become `Conflict`, connectivity and
/// retryable transaction failures become `Unavailable`, everything else `Other`.
pub(crate) fn map_sqlx(error: sqlx::Error) -> StoreError {
    match &error {
        sqlx::Error::Database(db) => match db.code().as_deref() {
            Some(UNIQUE_VIOLATION) => StoreError::Conflict,
            Some(code) if RETRYABLE.contains(&code) => StoreError::Unavailable(error.to_string()),
            _ => StoreError::Other(error.to_string()),
        },
        sqlx::Error::PoolTimedOut
        | sqlx::Error::PoolClosed
        | sqlx::Error::Io(_)
        | sqlx::Error::Tls(_) => StoreError::Unavailable(error.to_string()),
        _ => StoreError::Other(error.to_string()),
    }
}

/// A value read from the database that the domain rejects or does not recognise.
pub(crate) fn corrupted(column: &str) -> StoreError {
    StoreError::Other(format!("corrupted {column}"))
}

/// The error for an `UPDATE` that matched no row, same as the in-memory store.
pub(crate) fn not_found(what: &str) -> StoreError {
    StoreError::Other(format!("{what} not found"))
}
