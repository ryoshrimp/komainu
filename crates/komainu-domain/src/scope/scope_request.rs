use crate::scope::ScopeSet;

/// **English:**<br>
/// Distinguishes an omitted OAuth scope parameter from an explicitly supplied set.
///
/// [`Self::Explicit`] can hold an empty set; [`super::ScopePolicy::resolve`] rejects it
/// rather than treating it as omission. Serde uses the externally tagged enum format
/// and validates nested scope tokens during deserialization.
///
/// **日本語:**<br>
/// OAuth scope パラメーターの省略と、明示的な集合の指定を区別します。
///
/// [`Self::Explicit`] は空集合も保持できますが、[`super::ScopePolicy::resolve`] は
/// 省略とみなさず拒否します。Serde は外部タグ付きの列挙型形式を使い、
/// デシリアライズ時に内側のスコープトークンを検証します。
///
/// # Example / 使用例
/// ```rust
/// use komainu_domain::scope::{ScopeRequest, ScopeSet};
///
/// let request = ScopeRequest::Explicit(ScopeSet::parse("read").unwrap());
/// let json = serde_json::to_string(&request).unwrap();
/// assert_eq!(json, r#"{"Explicit":["read"]}"#);
/// assert_eq!(serde_json::from_str::<ScopeRequest>(&json).unwrap(), request);
/// assert_ne!(ScopeRequest::Omitted, ScopeRequest::Explicit(ScopeSet::from_scopes(vec![])));
/// ```
#[derive(ddd_toolkit::ValueObject)]
#[value_object(serde)]
pub enum ScopeRequest {
    /// **English:**<br>
    /// No scope parameter was supplied; resolution uses the configured defaults.
    ///
    /// **日本語:**<br>
    /// scope パラメーターが指定されていないため、解決時に設定済みの既定値を使います。
    Omitted,
    /// **English:**<br>
    /// The caller supplied this set, which must be checked against the scope policy.
    ///
    /// **日本語:**<br>
    /// 呼び出し元が指定した集合です。スコープポリシーによる検証が必要です。
    Explicit(ScopeSet),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_round_trip_preserves_variants() {
        for value in [
            ScopeRequest::Omitted,
            ScopeRequest::Explicit(ScopeSet::parse("read").unwrap()),
        ] {
            let json = serde_json::to_string(&value).unwrap();
            assert_eq!(serde_json::from_str::<ScopeRequest>(&json).unwrap(), value);
        }
    }
}
