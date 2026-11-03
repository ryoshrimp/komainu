use crate::{error::DomainError, shared::validate_non_empty_text};

fn validate_scope(s: &str) -> Result<(), DomainError> {
    validate_non_empty_text(s)?;
    if !s
        .bytes()
        .all(|b| matches!(b, 0x21 | 0x23..=0x5B | 0x5D..=0x7E))
    {
        Err(DomainError::InvalidScopeSyntax)
    } else {
        Ok(())
    }
}

/// **English:**<br>
/// A case-sensitive OAuth scope token using the RFC 6749 scope-token character set.
///
/// [`Self::try_new`] accepts ASCII bytes `0x21`, `0x23..=0x5B`, and `0x5D..=0x7E`
/// without normalization. Empty or whitespace-only input returns [`DomainError::EmptyText`];
/// any other invalid input returns [`DomainError::InvalidScopeSyntax`].
/// Spaces, double quotes, backslashes, and non-ASCII characters are not tokens.
/// Serde writes a string and applies the same validation when reading it.
///
/// **日本語:**<br>
/// RFC 6749 の scope-token 文字集合を使う、大文字小文字を区別する OAuth スコープトークンです。
///
/// [`Self::try_new`] は ASCII バイト `0x21`、`0x23..=0x5B`、`0x5D..=0x7E` を
/// 正規化せず受理します。空文字または空白のみの入力には [`DomainError::EmptyText`]、
/// その他の不正な入力には [`DomainError::InvalidScopeSyntax`] を返します。
/// スペース、二重引用符、バックスラッシュ、非 ASCII 文字は使用できません。
/// Serde は文字列として出力し、読み込み時にも同じ検証を行います。
///
/// # Example / 使用例
/// ```rust
/// use komainu_domain::scope::Scope;
///
/// let scope = Scope::try_new("read:profile".to_owned()).unwrap();
/// assert_eq!(scope.as_inner(), "read:profile");
/// assert!(Scope::try_new("read write".to_owned()).is_err());
/// ```
#[derive(ddd_toolkit::ValueObject, PartialOrd, Ord)]
#[value_object(validate = validate_scope, error = DomainError, serde)]
pub struct Scope(String);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_accepts_exactly_the_rfc6749_scope_token_characters() {
        for byte in 0..=127u8 {
            let value = char::from(byte).to_string();
            assert_eq!(
                Scope::try_new(value).is_ok(),
                matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e),
                "byte {byte:#x}"
            );
        }
        for value in ["", "日本語", "read write"] {
            assert!(Scope::try_new(value.to_owned()).is_err());
        }
    }

    #[test]
    fn serde_round_trip_preserves_value() {
        let value = Scope::try_new("read".to_owned()).unwrap();
        let json = serde_json::to_string(&value).unwrap();
        assert_eq!(serde_json::from_str::<Scope>(&json).unwrap(), value);
    }

    #[test]
    fn serde_rejects_invalid_values() {
        for value in ["", "read write", "read\twrite", "日本語", "\"", "\\"] {
            let json = serde_json::to_string(value).unwrap();
            assert!(serde_json::from_str::<Scope>(&json).is_err(), "{value:?}");
        }
    }
}
