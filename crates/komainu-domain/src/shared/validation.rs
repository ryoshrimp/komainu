use crate::{error::DomainError, secret::SecretKind};

/// **English:**<br>
/// Returns [`DomainError::EmptyText`] if `s` is empty after [`str::trim`].
/// Otherwise returns `Ok(())` without modifying the input.
///
/// **日本語:**<br>
/// `s` が [`str::trim`] 後に空なら [`DomainError::EmptyText`] を返します。
/// それ以外は入力を変更せず `Ok(())` を返します。
pub fn validate_non_empty_text(s: &str) -> Result<(), DomainError> {
    if s.trim().is_empty() {
        Err(DomainError::EmptyText)
    } else {
        Ok(())
    }
}

/// **English:**<br>
/// Returns [`DomainError::WhitespaceCharacter`] if `s` contains a character matched
/// by [`char::is_whitespace`]. Accepts empty strings.
///
/// **日本語:**<br>
/// `s` が [`char::is_whitespace`] に一致する文字を含む場合に
/// [`DomainError::WhitespaceCharacter`] を返します。空文字は受理します。
pub fn validate_non_whitespace_character(s: &str) -> Result<(), DomainError> {
    if s.chars().any(char::is_whitespace) {
        Err(DomainError::WhitespaceCharacter)
    } else {
        Ok(())
    }
}

/// **English:**<br>
/// Returns [`DomainError::ControlCharacter`] if `s` contains a character matched
/// by [`char::is_control`]. Accepts empty strings.
///
/// **日本語:**<br>
/// `s` が [`char::is_control`] に一致する文字を含む場合に
/// [`DomainError::ControlCharacter`] を返します。空文字は受理します。
pub fn validate_non_control_character(s: &str) -> Result<(), DomainError> {
    if s.chars().any(char::is_control) {
        Err(DomainError::ControlCharacter)
    } else {
        Ok(())
    }
}

/// **English:**<br>
/// Accepts `a <= b`, including equality; otherwise returns [`DomainError::OutOfRange`].
///
/// **日本語:**<br>
/// 等値を含む `a <= b` を受理し、それ以外は [`DomainError::OutOfRange`] を返します。
pub fn validate_less_than_or_equal<T: Ord>(a: T, b: T) -> Result<(), DomainError> {
    if a <= b {
        Ok(())
    } else {
        Err(DomainError::OutOfRange)
    }
}

/// **English:**<br>
/// Accepts matching secret categories; returns [`DomainError::WrongSecretKind`] if `a != b`.
/// Does not inspect or compare secret bytes.
///
/// **日本語:**<br>
/// 一致する秘密値の種別を受理し、`a != b` なら [`DomainError::WrongSecretKind`] を返します。
/// 秘密値のバイト列の検査や比較は行いません。
pub fn validate_digest_kind(a: &SecretKind, b: &SecretKind) -> Result<(), DomainError> {
    if a == b {
        Ok(())
    } else {
        Err(DomainError::WrongSecretKind)
    }
}
