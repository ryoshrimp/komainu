use ddd_toolkit::ValueObject;

use crate::error::DomainError;

/// The opaque `state` request parameter (1-1024 VSCHAR characters).
#[derive(ValueObject)]
#[value_object(validate = validate_state, error = DomainError)]
pub struct State(String);

fn validate_state(value: &State) -> Result<(), DomainError> {
    let s = &value.0;
    if s.is_empty() || s.chars().count() > 1024 {
        return Err(DomainError::invalid("state", "length must be 1 to 1024"));
    }
    if !s.chars().all(|c| matches!(c, '\u{20}'..='\u{7e}')) {
        return Err(DomainError::invalid("state", "invalid character"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_rules() {
        assert!(State::try_new("s t".to_owned()).is_ok());
        assert!(State::try_new(String::new()).is_err());
        assert!(State::try_new("a".repeat(1025)).is_err());
        assert!(State::try_new("é".to_owned()).is_err());
        assert!(State::try_new("a\nb".to_owned()).is_err());
    }
}
