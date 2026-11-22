/// Errors raised by value-object validation and aggregate invariants.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DomainError {
    /// A value failed validation. `field` is the snake_case type name.
    #[error("invalid {field}: {reason}")]
    InvalidValue {
        field: &'static str,
        reason: &'static str,
    },
    /// A client invariant would be broken by the operation.
    #[error("client invariant violated: {0}")]
    ClientInvariant(&'static str),
    /// The operation is not allowed in the current state.
    #[error("operation not allowed in current state: {0}")]
    InvalidState(&'static str),
}

impl DomainError {
    pub(crate) fn invalid(field: &'static str, reason: &'static str) -> Self {
        Self::InvalidValue { field, reason }
    }
}
