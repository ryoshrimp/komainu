use crate::scope::Scope;

/// **English:**<br>
/// A scope definition containing a validated token name, without additional metadata.
///
/// [`Self::new`] takes the name and [`Self::as_inner`] borrows it. Creating a definition
/// does not register it with a policy. Serde serializes the name as a string and
/// validates the nested [`Scope`] when deserializing.
///
/// **日本語:**<br>
/// 検証済みのトークン名を保持するスコープ定義です。追加のメタデータは持ちません。
///
/// [`Self::new`] は名前を受け取り、[`Self::as_inner`] はその名前を借用します。
/// 定義の作成だけではポリシーに登録されません。Serde は名前を文字列として出力し、
/// デシリアライズ時に内側の [`Scope`] を検証します。
///
/// # Example / 使用例
/// ```rust
/// use komainu_domain::scope::{Scope, ScopeDefinition};
///
/// let definition = ScopeDefinition::new(Scope::try_new("read".to_owned()).unwrap());
/// assert_eq!(definition.as_inner().as_inner(), "read");
/// assert_eq!(serde_json::to_string(&definition).unwrap(), r#""read""#);
/// ```
#[derive(ddd_toolkit::ValueObject)]
#[value_object(serde)]
pub struct ScopeDefinition {
    name: Scope,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_round_trip_preserves_value() {
        let value = ScopeDefinition::new(Scope::try_new("read".to_owned()).unwrap());
        let json = serde_json::to_string(&value).unwrap();
        assert_eq!(
            serde_json::from_str::<ScopeDefinition>(&json).unwrap(),
            value
        );
    }
}
