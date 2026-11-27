use ddd_toolkit::ValueObject;
use time::OffsetDateTime;

use super::IssuerId;
use crate::UserId;
use crate::error::DomainError;

/// The `sub` of an external assertion (1-255 bytes, no control characters).
#[derive(ValueObject, PartialOrd, Ord)]
#[value_object(validate = validate_external_subject, error = DomainError)]
pub struct ExternalSubject(String);

fn validate_external_subject(value: &ExternalSubject) -> Result<(), DomainError> {
    let s = &value.0;
    if s.is_empty() || s.len() > 255 {
        return Err(DomainError::invalid(
            "external_subject",
            "length must be 1 to 255 bytes",
        ));
    }
    if s.chars().any(char::is_control) {
        return Err(DomainError::invalid(
            "external_subject",
            "control character",
        ));
    }
    Ok(())
}

/// Maps a `sub` of a trusted issuer to a local user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectMapping {
    pub issuer_id: IssuerId,
    pub subject: ExternalSubject,
    pub user_id: UserId,
    /// When the mapping was created or last overwritten.
    pub updated_at: OffsetDateTime,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_subject_rules() {
        assert!(ExternalSubject::try_new("user@example.com".to_owned()).is_ok());
        assert!(ExternalSubject::try_new("a b".to_owned()).is_ok());
        assert!(ExternalSubject::try_new(String::new()).is_err());
        assert!(ExternalSubject::try_new("a".repeat(255)).is_ok());
        assert!(ExternalSubject::try_new("a".repeat(256)).is_err());
        assert!(ExternalSubject::try_new("a\nb".to_owned()).is_err());
        assert!(ExternalSubject::try_new("a\u{7f}".to_owned()).is_err());
    }
}
