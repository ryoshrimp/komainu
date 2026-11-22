use ddd_toolkit::ValueObject;

use crate::error::DomainError;

/// Identifier of a registered client (1-64 chars of `[A-Za-z0-9._~-]`).
#[derive(ValueObject, PartialOrd, Ord)]
#[value_object(validate = validate_client_id, error = DomainError)]
pub struct ClientId(String);

fn validate_client_id(value: &ClientId) -> Result<(), DomainError> {
    let s = &value.0;
    if s.is_empty() || s.chars().count() > 64 {
        return Err(DomainError::invalid("client_id", "length must be 1 to 64"));
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '~' | '-'))
    {
        return Err(DomainError::invalid("client_id", "invalid character"));
    }
    Ok(())
}

/// Human-readable client name (1-100 chars, no control characters).
#[derive(ValueObject)]
#[value_object(validate = validate_client_name, error = DomainError)]
pub struct ClientName(String);

fn validate_client_name(value: &ClientName) -> Result<(), DomainError> {
    let s = &value.0;
    if s.is_empty() || s.chars().count() > 100 {
        return Err(DomainError::invalid(
            "client_name",
            "length must be 1 to 100",
        ));
    }
    if s.chars().any(char::is_control) {
        return Err(DomainError::invalid("client_name", "control character"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_id_rules() {
        assert!(ClientId::try_new("abc-1._~".to_owned()).is_ok());
        assert!(ClientId::try_new(String::new()).is_err());
        assert!(ClientId::try_new("a".repeat(65)).is_err());
        assert!(ClientId::try_new("a b".to_owned()).is_err());
        assert!(ClientId::try_new("a".repeat(64)).is_ok());
    }

    #[test]
    fn client_name_rules() {
        assert!(ClientName::try_new("My App".to_owned()).is_ok());
        assert!(ClientName::try_new(String::new()).is_err());
        assert!(ClientName::try_new("a\nb".to_owned()).is_err());
        assert!(ClientName::try_new("あ".repeat(100)).is_ok());
        assert!(ClientName::try_new("あ".repeat(101)).is_err());
    }
}
