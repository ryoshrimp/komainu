use std::fmt;

use ddd_toolkit::ValueObject;

use crate::Secret;
use crate::error::DomainError;

/// The `sub` of a token: an opaque identifier of the resource owner.
#[derive(ValueObject, PartialOrd, Ord)]
#[value_object(validate = validate_subject, error = DomainError)]
pub struct Subject(String);

fn validate_subject(value: &Subject) -> Result<(), DomainError> {
    let s = &value.0;
    if s.is_empty() || s.len() > 255 {
        return Err(DomainError::invalid(
            "subject",
            "length must be 1 to 255 bytes",
        ));
    }
    if s.chars().any(char::is_control) {
        return Err(DomainError::invalid("subject", "control character"));
    }
    Ok(())
}

/// Identifier of a [`User`](crate::User).
#[derive(ValueObject, Copy, PartialOrd, Ord)]
pub struct UserId(uuid::Uuid);

/// Identifier of an [`AuthorizationRequest`](crate::AuthorizationRequest).
#[derive(ValueObject, Copy, PartialOrd, Ord)]
pub struct AuthorizationRequestId(uuid::Uuid);

/// Identifier of a [`Grant`](crate::Grant).
#[derive(ValueObject, Copy, PartialOrd, Ord)]
pub struct GrantId(uuid::Uuid);

impl From<UserId> for Subject {
    fn from(id: UserId) -> Self {
        Subject(id.0.hyphenated().to_string())
    }
}

/// Login name, stored in ASCII lowercase (3-64 chars of `[A-Za-z0-9._-]`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Username(String);

impl Username {
    /// Lowercases `value` and validates it.
    pub fn try_new(value: String) -> Result<Username, DomainError> {
        let s = value.to_ascii_lowercase();
        if !(3..=64).contains(&s.chars().count()) {
            return Err(DomainError::invalid("username", "length must be 3 to 64"));
        }
        if !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        {
            return Err(DomainError::invalid("username", "invalid character"));
        }
        Ok(Username(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A password presented at login (1-128 chars).
pub struct Password(Secret<String>);

impl Password {
    pub fn try_new(value: Secret<String>) -> Result<Password, DomainError> {
        let len = value.expose_secret_ref().chars().count();
        if !(1..=128).contains(&len) {
            return Err(DomainError::invalid("password", "length must be 1 to 128"));
        }
        Ok(Password(value))
    }

    pub fn expose(&self) -> &str {
        self.0.expose_secret_ref()
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Password").field(&self.0).finish()
    }
}

/// A password chosen at user creation or password change (8-128 chars).
pub struct NewPassword(Password);

impl NewPassword {
    pub fn try_new(value: Secret<String>) -> Result<NewPassword, DomainError> {
        let password = Password::try_new(value)?;
        if password.expose().chars().count() < 8 {
            return Err(DomainError::invalid(
                "new_password",
                "must be at least 8 characters",
            ));
        }
        Ok(NewPassword(password))
    }

    pub fn as_password(&self) -> &Password {
        &self.0
    }
}

impl fmt::Debug for NewPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("NewPassword").field(&self.0.0).finish()
    }
}

/// A password hash in PHC string format (the format is the adapter's concern).
#[derive(ValueObject)]
#[value_object(validate = validate_password_hash, error = DomainError)]
pub struct PasswordHash(String);

fn validate_password_hash(value: &PasswordHash) -> Result<(), DomainError> {
    if value.0.is_empty() {
        return Err(DomainError::invalid("password_hash", "must not be empty"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(s: &str) -> Secret<String> {
        Secret::new(s.to_owned())
    }

    #[test]
    fn username_is_lowercased_and_validated() {
        assert_eq!(
            Username::try_new("Alice".to_owned()).unwrap().as_str(),
            "alice"
        );
        assert!(Username::try_new("al".to_owned()).is_err());
        assert!(Username::try_new("a b c".to_owned()).is_err());
        assert!(Username::try_new("a".repeat(65)).is_err());
    }

    #[test]
    fn password_length_rules() {
        assert!(Password::try_new(secret("a")).is_ok());
        assert!(Password::try_new(secret("")).is_err());
        assert!(Password::try_new(secret(&"a".repeat(128))).is_ok());
        assert!(Password::try_new(secret(&"a".repeat(129))).is_err());
        assert!(NewPassword::try_new(secret("1234567")).is_err());
        assert!(NewPassword::try_new(secret("12345678")).is_ok());
    }

    #[test]
    fn secret_debug_is_redacted() {
        let p = Password::try_new(secret("hunter2")).unwrap();
        assert_eq!(format!("{p:?}"), "Password([REDACTED])");
        let n = NewPassword::try_new(secret("hunter222")).unwrap();
        assert_eq!(format!("{n:?}"), "NewPassword([REDACTED])");
        assert_eq!(n.as_password().expose(), "hunter222");
    }

    #[test]
    fn subject_from_user_id_is_hyphenated_lowercase() {
        let id = UserId::new(uuid::Uuid::from_u128(0xAB));
        assert_eq!(
            Subject::from(id).as_inner(),
            "00000000-0000-0000-0000-0000000000ab"
        );
        assert!(Subject::try_new(String::new()).is_err());
        assert!(Subject::try_new("a".repeat(256)).is_err());
        assert!(Subject::try_new("a\tb".to_owned()).is_err());
    }
}
