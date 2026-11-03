use std::collections::BTreeSet;

use crate::{
    error::DomainError,
    scope::{RedirectUri, ResolvedRedirect},
};

/// **English:**<br>
/// A possibly empty set of registered redirect URIs with exact-string matching.
///
/// Duplicates are removed using the original strings, not normalized URLs.
/// Iteration is in lexical order. Serde uses a sequence of URI strings and validates
/// each [`RedirectUri`] on input, removing duplicates.
///
/// **日本語:**<br>
/// 文字列の完全一致で照合する登録済みリダイレクト URI の集合です。空集合も表せます。
///
/// 正規化した URL ではなく元の文字列に基づき重複を除去し、辞書順で走査します。
/// Serde は URI 文字列の列を使い、入力時に各 [`RedirectUri`] を検証して重複を除去します。
///
/// # Example / 使用例
/// ```rust
/// use komainu_domain::scope::{RedirectUri, RedirectUriSet};
///
/// let uri = RedirectUri::parse("https://example.com/cb").unwrap();
/// let registered = RedirectUriSet::from_uris(vec![uri.clone(), uri.clone()]);
/// let resolved = registered.resolve(None).unwrap();
/// assert_eq!(resolved.uri(), &uri);
/// assert!(!resolved.uri_supplied());
/// assert!(registered.resolve(Some(&uri)).unwrap().uri_supplied());
/// ```
#[derive(ddd_toolkit::ValueObject)]
#[value_object(serde)]
pub struct RedirectUriSet(BTreeSet<RedirectUri>);

impl RedirectUriSet {
    /// **English:**<br>
    /// Consumes the URI vector `scopes` and removes exact-string duplicates, accepting an empty vector.
    ///
    /// **日本語:**<br>
    /// URI ベクター `scopes` を消費し、文字列が完全一致する重複を除去します。空も受理します。
    pub fn from_uris(scopes: Vec<RedirectUri>) -> Self {
        let set: BTreeSet<RedirectUri> = scopes.into_iter().collect();
        RedirectUriSet::new(set)
    }

    /// **English:**<br>
    /// Borrows the distinct URIs in lexical order of their original strings.
    ///
    /// **日本語:**<br>
    /// 元の文字列の辞書順で、重複しない URI を借用して走査します。
    pub fn iter(&self) -> impl Iterator<Item = &RedirectUri> {
        self.0.iter()
    }

    /// **English:**<br>
    /// Returns whether no redirect URIs are registered.
    ///
    /// **日本語:**<br>
    /// リダイレクト URI が 1 件も登録されていないかどうかを返します。
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// **English:**<br>
    /// Selects a registered URI and records whether the authorization request supplied it.
    ///
    /// With `Some`, requires an exact-string match or returns [`DomainError::RedirectMismatch`];
    /// the result records `uri_supplied = true`. With `None`, selects the sole distinct
    /// registered URI and records `false`; zero or multiple URIs return
    /// [`DomainError::MissingOrAmbiguousRedirect`]. The selected URI is cloned.
    ///
    /// **日本語:**<br>
    /// 登録済み URI を選択し、認可リクエストで明示されたかを記録します。
    ///
    /// `Some` では文字列の完全一致を要求し、不一致なら [`DomainError::RedirectMismatch`]、
    /// 一致なら `uri_supplied = true` の結果を返します。`None` では登録済みの異なる URI が
    /// 1 件だけならそれを選び `false` を記録します。0 件または複数件なら
    /// [`DomainError::MissingOrAmbiguousRedirect`] を返します。選択した URI は複製します。
    pub fn resolve(&self, supplied: Option<&RedirectUri>) -> Result<ResolvedRedirect, DomainError> {
        match supplied {
            None => match (self.0.len(), self.0.first()) {
                (1, Some(uri)) => Ok(ResolvedRedirect::new(uri.clone(), false)),
                _ => Err(DomainError::MissingOrAmbiguousRedirect),
            },
            Some(redirect_uri) => {
                if self.0.contains(redirect_uri) {
                    Ok(ResolvedRedirect::new(redirect_uri.clone(), true))
                } else {
                    Err(DomainError::RedirectMismatch)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uri(value: &str) -> RedirectUri {
        RedirectUri::parse(value).unwrap()
    }

    #[test]
    fn redirect_uri_set_resolves_only_a_single_distinct_default() {
        let callback = uri("https://example.com/cb");
        let empty = RedirectUriSet::from_uris(vec![]);
        assert!(empty.is_empty());
        assert_eq!(
            empty.resolve(None),
            Err(DomainError::MissingOrAmbiguousRedirect)
        );
        assert_eq!(
            empty.resolve(Some(&callback)),
            Err(DomainError::RedirectMismatch)
        );
        let single = RedirectUriSet::from_uris(vec![callback.clone(), callback.clone()]);
        assert_eq!(single.iter().count(), 1);
        assert!(!single.is_empty());
        assert_eq!(
            single.resolve(None),
            Ok(ResolvedRedirect::new(callback.clone(), false))
        );
        assert_eq!(
            single.resolve(Some(&callback)),
            Ok(ResolvedRedirect::new(callback.clone(), true))
        );
        let multiple =
            RedirectUriSet::from_uris(vec![callback.clone(), uri("https://example.com/other")]);
        assert_eq!(
            multiple.resolve(None),
            Err(DomainError::MissingOrAmbiguousRedirect)
        );
        assert_eq!(
            multiple.resolve(Some(&callback)),
            Ok(ResolvedRedirect::new(callback, true))
        );
    }

    #[test]
    fn redirect_uri_matching_uses_exact_strings() {
        let callback = uri("https://example.com/cb?x=%2F");
        let registered = RedirectUriSet::from_uris(vec![callback]);
        for value in [
            "https://EXAMPLE.com/cb?x=%2F",
            "https://example.com:443/cb?x=%2F",
            "https://example.com/cb?x=%2f",
            "https://example.com/cb?x=/",
            "https://example.com/a/../cb?x=%2F",
            "https://example.com/other",
        ] {
            assert_eq!(
                registered.resolve(Some(&uri(value))),
                Err(DomainError::RedirectMismatch)
            );
        }
    }

    #[test]
    fn serde_round_trip_preserves_values() {
        let callback = uri("HTTPS://EXAMPLE.com:443/cb?x=%2f");
        for value in [
            RedirectUriSet::from_uris(vec![]),
            RedirectUriSet::from_uris(vec![callback]),
        ] {
            let json = serde_json::to_string(&value).unwrap();
            assert_eq!(
                serde_json::from_str::<RedirectUriSet>(&json).unwrap(),
                value
            );
        }
    }

    #[test]
    fn serde_rejects_invalid_redirect_values() {
        for value in [
            "http://example.com/cb",
            "https://example.com/[x]",
            "https://example.com/?x=[a]",
            "https://example.com/#x",
        ] {
            let json = serde_json::to_string(&[value]).unwrap();
            assert!(serde_json::from_str::<RedirectUriSet>(&json).is_err());
        }
    }
}
