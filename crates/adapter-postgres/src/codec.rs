//! Conversions between domain values and database column values.

use komainu_application::StoreError;
use komainu_domain::{DomainError, ScopeSet, ScopeToken, TokenHash};
use sqlx::postgres::PgRow;
use sqlx::{Decode, Row, Type};

use crate::error::{corrupted, map_sqlx};

/// Reads a column, mapping decode failures to a `StoreError`.
pub(crate) fn col<'r, T>(row: &'r PgRow, name: &str) -> Result<T, StoreError>
where
    T: Decode<'r, sqlx::Postgres> + Type<sqlx::Postgres>,
{
    row.try_get(name).map_err(map_sqlx)
}

/// Marks a domain validation failure on `column` as corrupted data.
pub(crate) fn valid<T>(value: Result<T, DomainError>, column: &str) -> Result<T, StoreError> {
    value.map_err(|_| corrupted(column))
}

pub(crate) fn scope_to_db(scope: &ScopeSet) -> Vec<String> {
    scope.iter().map(|t| t.as_str().to_owned()).collect()
}

pub(crate) fn scope_from_db(values: Vec<String>, column: &str) -> Result<ScopeSet, StoreError> {
    let tokens = values
        .into_iter()
        .map(|v| ScopeToken::try_new(v).map_err(|_| corrupted(column)))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ScopeSet::from_tokens(tokens))
}

pub(crate) fn hash_to_db(hash: &TokenHash) -> &[u8] {
    hash.as_bytes().as_slice()
}

pub(crate) fn hash_from_db(bytes: Vec<u8>, column: &str) -> Result<TokenHash, StoreError> {
    let array: [u8; 32] = bytes.try_into().map_err(|_| corrupted(column))?;
    Ok(TokenHash::from_bytes(array))
}
