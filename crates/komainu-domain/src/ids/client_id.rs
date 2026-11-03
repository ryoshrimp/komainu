use crate::{
    error::DomainError,
    shared::{
        validate_non_control_character, validate_non_empty_text, validate_non_whitespace_character,
    },
};

fn validate_client_id(s: &str) -> Result<(), DomainError> {
    validate_non_empty_text(s)?;
    validate_non_whitespace_character(s)?;
    validate_non_control_character(s)?;
    Ok(())
}

/// **English:**<br>
/// Identifies a client with a non-empty string containing no whitespace or control characters.
///
/// [`Self::try_new`] preserves accepted input without trimming or normalization.
/// Validation returns [`DomainError::EmptyText`] for empty or whitespace-only input,
/// then [`DomainError::WhitespaceCharacter`] for any character matched by
/// [`char::is_whitespace`], then [`DomainError::ControlCharacter`] for any character
/// matched by [`char::is_control`]. Whitespace errors take precedence over control errors.
///
/// Serde serializes the identifier as a string and validates it during deserialization.
/// Invalid input becomes an error of the deserializer's error type.
///
/// **日本語:**<br>
/// 空白文字と制御文字を含まない、空でない文字列でクライアントを識別します。
///
/// [`Self::try_new`] は受理した入力をトリムや正規化をせず保持します。
/// 検証は、空文字または空白のみなら [`DomainError::EmptyText`]、
/// 次に [`char::is_whitespace`] に一致する文字を含むなら
/// [`DomainError::WhitespaceCharacter`]、次に [`char::is_control`] に一致する
/// 文字を含むなら [`DomainError::ControlCharacter`] を返します。
/// 空白文字のエラーは制御文字のエラーに優先します。
///
/// Serde は識別子を文字列としてシリアライズし、デシリアライズ時に検証します。
/// 不正な入力はデシリアライザー固有のエラー型に変換されます。
///
/// # Example / 使用例
///
/// ```rust
/// use komainu_domain::{error::DomainError, ids::ClientId};
///
/// let id = ClientId::try_new("client-a".to_owned()).unwrap();
/// assert_eq!(id.as_inner(), "client-a");
/// assert!(matches!(
///     ClientId::try_new("client a".to_owned()),
///     Err(DomainError::WhitespaceCharacter)
/// ));
///
/// let json = serde_json::to_string(&id).unwrap();
/// assert_eq!(serde_json::from_str::<ClientId>(&json).unwrap(), id);
/// assert!(serde_json::from_str::<ClientId>(r#""client a""#).is_err());
/// ```
#[derive(ddd_toolkit::ValueObject)]
#[value_object(validate = validate_client_id, error = DomainError, serde)]
pub struct ClientId(String);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_new_accepts_valid_client_id() {
        let id = ClientId::try_new("client-a".to_owned()).unwrap();
        assert_eq!(id.as_inner(), "client-a")
    }
    #[test]
    fn try_new_rejects_empty_string() {
        assert_eq!(
            ClientId::try_new("".to_owned()).unwrap_err(),
            DomainError::EmptyText
        )
    }
    #[test]
    fn try_new_rejects_whitespace_only() {
        assert_eq!(
            ClientId::try_new("   ".to_owned()).unwrap_err(),
            DomainError::EmptyText
        )
    }
    #[test]
    fn try_new_rejects_leading_whitespace() {
        assert_eq!(
            ClientId::try_new(" client-a".to_owned()).unwrap_err(),
            DomainError::WhitespaceCharacter
        )
    }
    #[test]
    fn try_new_rejects_trailing_whitespace() {
        assert_eq!(
            ClientId::try_new("client-a ".to_owned()).unwrap_err(),
            DomainError::WhitespaceCharacter
        )
    }
    #[test]
    fn try_new_rejects_internal_whitespace() {
        assert_eq!(
            ClientId::try_new("client a".to_owned()).unwrap_err(),
            DomainError::WhitespaceCharacter
        )
    }
    #[test]
    fn try_new_rejects_unicode_whitespace() {
        assert_eq!(
            ClientId::try_new("client\u{3000}a".to_owned()).unwrap_err(),
            DomainError::WhitespaceCharacter
        )
    }
    #[test]
    fn try_new_rejects_control_characters() {
        assert_eq!(
            ClientId::try_new("client\0a".to_owned()).unwrap_err(),
            DomainError::ControlCharacter
        )
    }
    #[test]
    fn try_new_rejects_tabs_and_newlines_as_whitespace() {
        assert_eq!(
            ClientId::try_new("client\ta".to_owned()).unwrap_err(),
            DomainError::WhitespaceCharacter
        );
        assert_eq!(
            ClientId::try_new("client\na".to_owned()).unwrap_err(),
            DomainError::WhitespaceCharacter
        )
    }
    #[test]
    fn serialize_produces_string() {
        assert_eq!(
            serde_json::to_string(&ClientId::try_new("client-a".to_owned()).unwrap()).unwrap(),
            r#""client-a""#
        )
    }
    #[test]
    fn deserialize_accepts_valid_client_id() {
        assert_eq!(
            serde_json::from_str::<ClientId>(r#""client-a""#).unwrap(),
            ClientId::try_new("client-a".to_owned()).unwrap()
        )
    }
    #[test]
    fn deserialize_rejects_invalid_client_id() {
        assert!(serde_json::from_str::<ClientId>(r#""client a""#).is_err());
    }
    #[test]
    fn serde_round_trip_preserves_value() {
        let id = ClientId::try_new("client-a".to_owned()).unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(serde_json::from_str::<ClientId>(&json).unwrap(), id);
    }
}
