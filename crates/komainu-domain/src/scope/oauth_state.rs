use crate::error::DomainError;

fn validate_oauth_state(s: &str) -> Result<(), DomainError> {
    if s.is_empty() {
        return Err(DomainError::EmptyText);
    }
    // RFC 6749 Appendix A.5: state = 1*VSCHAR, VSCHAR = %x20-7E.
    if !s.bytes().all(|b| matches!(b, 0x20..=0x7E)) {
        Err(DomainError::InvalidStateValue)
    } else {
        Ok(())
    }
}

/// **English:**<br>
/// An OAuth state value containing one or more visible ASCII bytes (`0x20..=0x7E`).
///
/// [`Self::try_new`] preserves spaces, quotes, and backslashes; even whitespace-only
/// strings of ASCII spaces are accepted. Empty input returns [`DomainError::EmptyText`];
/// control or non-ASCII characters return [`DomainError::InvalidStateValue`].
/// Serde writes a string and validates it on deserialization.
/// This type validates syntax only: it does not generate randomness or verify request correlation.
///
/// **日本語:**<br>
/// 可視 ASCII バイト（`0x20..=0x7E`）を 1 個以上含む OAuth state 値です。
///
/// [`Self::try_new`] はスペース、引用符、バックスラッシュを保持し、
/// ASCII スペースのみの文字列も受理します。空文字には [`DomainError::EmptyText`]、
/// 制御文字や非 ASCII 文字には [`DomainError::InvalidStateValue`] を返します。
/// Serde は文字列として出力し、デシリアライズ時に検証します。
/// この型は構文のみを検証し、乱数の生成やリクエストの対応関係の検証は行いません。
///
/// # Example / 使用例
/// ```rust
/// use komainu_domain::scope::OAuthState;
///
/// let state = OAuthState::try_new(" state value ".to_owned()).unwrap();
/// assert_eq!(state.as_inner(), " state value ");
/// assert!(OAuthState::try_new("state\n".to_owned()).is_err());
/// ```
#[derive(ddd_toolkit::ValueObject)]
#[value_object(validate = validate_oauth_state, error = DomainError, serde)]
pub struct OAuthState(String);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oauth_state_accepts_exactly_the_rfc6749_vschar_characters() {
        for byte in 0..=127u8 {
            assert_eq!(
                OAuthState::try_new(char::from(byte).to_string()).is_ok(),
                matches!(byte, 0x20..=0x7e),
                "byte {byte:#x}"
            );
        }
        for value in [" ", "   ", " a b ", "\"\\"] {
            let state = OAuthState::try_new(value.to_owned()).unwrap();
            assert_eq!(state.as_inner(), value);
        }
        assert_eq!(
            OAuthState::try_new(String::new()),
            Err(DomainError::EmptyText)
        );
        for value in ["日本語", "\u{a0}", "a\nb", "\t"] {
            assert_eq!(
                OAuthState::try_new(value.to_owned()),
                Err(DomainError::InvalidStateValue)
            );
        }
    }

    #[test]
    fn serde_round_trip_preserves_values() {
        for value in ["   ", "a\"\\b"] {
            let state = OAuthState::try_new(value.to_owned()).unwrap();
            let json = serde_json::to_string(&state).unwrap();
            assert_eq!(serde_json::from_str::<OAuthState>(&json).unwrap(), state);
        }
    }

    #[test]
    fn serde_rejects_invalid_values() {
        for value in ["", "\t", "a\nb", "日本語"] {
            let json = serde_json::to_string(value).unwrap();
            assert!(
                serde_json::from_str::<OAuthState>(&json).is_err(),
                "{value:?}"
            );
        }
    }
}
