use crate::error::DomainError;

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
