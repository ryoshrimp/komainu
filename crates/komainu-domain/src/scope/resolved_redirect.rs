use crate::{error::DomainError, scope::RedirectUri};

/// **English:**<br>
/// A selected redirect URI and whether it was supplied in the authorization request.
///
/// Prefer [`super::RedirectUriSet::resolve`] to check registration before construction.
/// [`Self::new`] accepts a validated `uri` and a `uri_supplied` flag without checking
/// registration. The generated accessors borrow those fields.
/// Serde uses an object with `uri` and `uri_supplied` fields; deserialization validates
/// the URI syntax but does not prove registration or the flag's provenance.
///
/// **日本語:**<br>
/// 選択済みリダイレクト URI と、認可リクエストで明示されたかを保持します。
///
/// 構築前に登録を確認するため [`super::RedirectUriSet::resolve`] の利用を推奨します。
/// [`Self::new`] は検証済みの `uri` と `uri_supplied` フラグを受け取り、登録は確認しません。
/// 自動生成されるアクセサーは各フィールドを借用します。
/// Serde は `uri` と `uri_supplied` フィールドを持つオブジェクトを使います。
/// デシリアライズでは URI 構文を検証しますが、登録やフラグの由来は確認しません。
///
/// # Example / 使用例
/// ```rust
/// use komainu_domain::scope::{RedirectUri, RedirectUriSet};
///
/// let uri = RedirectUri::parse("https://example.com/cb").unwrap();
/// let registered = RedirectUriSet::from_uris(vec![uri.clone()]);
/// let explicit = registered.resolve(Some(&uri)).unwrap();
/// assert!(explicit.check_token_request(None).is_err());
/// assert_eq!(explicit.check_token_request(Some(&uri)), Ok(()));
/// let implicit = registered.resolve(None).unwrap();
/// assert_eq!(implicit.check_token_request(None), Ok(()));
/// ```
#[derive(ddd_toolkit::ValueObject)]
#[value_object(serde)]
pub struct ResolvedRedirect {
    uri: RedirectUri,
    uri_supplied: bool,
}

impl ResolvedRedirect {
    /// **English:**<br>
    /// Checks the token request's redirect URI against the authorization-time selection.
    ///
    /// A supplied URI must match the stored string exactly. Omission is accepted only
    /// when the authorization request also omitted it (`uri_supplied` is `false`).
    /// Returns `Ok(())` on a match or permitted omission, otherwise
    /// [`DomainError::RedirectMismatch`]. Does not modify the selection.
    ///
    /// **日本語:**<br>
    /// トークンリクエストのリダイレクト URI を、認可時の選択結果と照合します。
    ///
    /// 指定された URI は保持する文字列と完全一致する必要があります。省略は認可リクエストでも
    /// 省略されていた場合（`uri_supplied` が `false`）のみ許可します。
    /// 一致または許可された省略には `Ok(())`、それ以外には
    /// [`DomainError::RedirectMismatch`] を返します。選択結果は変更しません。
    pub fn check_token_request(&self, supplied: Option<&RedirectUri>) -> Result<(), DomainError> {
        match (self.uri_supplied, supplied) {
            (_, Some(uri)) => {
                if &self.uri == uri {
                    Ok(())
                } else {
                    Err(DomainError::RedirectMismatch)
                }
            }
            (true, None) => Err(DomainError::RedirectMismatch),
            (false, None) => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::RedirectUriSet;

    fn uri(value: &str) -> RedirectUri {
        RedirectUri::parse(value).unwrap()
    }

    #[test]
    fn token_request_checks_authorization_request_uri_presence() {
        let callback = uri("https://example.com/cb");
        let registered = RedirectUriSet::from_uris(vec![callback.clone()]);
        for supplied in [None, Some(&callback)] {
            let resolved = registered.resolve(supplied).unwrap();
            assert_eq!(resolved.check_token_request(Some(&callback)), Ok(()));
            assert_eq!(
                resolved.check_token_request(None),
                if supplied.is_some() {
                    Err(DomainError::RedirectMismatch)
                } else {
                    Ok(())
                }
            );
            assert_eq!(
                resolved.check_token_request(Some(&uri("https://example.com/other"))),
                Err(DomainError::RedirectMismatch)
            );
        }
    }

    #[test]
    fn token_request_uri_matching_uses_exact_strings() {
        let callback = uri("https://example.com/cb?x=%2F");
        let registered = RedirectUriSet::from_uris(vec![callback.clone()]);
        let resolved = registered.resolve(Some(&callback)).unwrap();
        for value in [
            "https://EXAMPLE.com/cb?x=%2F",
            "https://example.com:443/cb?x=%2F",
            "https://example.com/cb?x=%2f",
            "https://example.com/cb?x=/",
            "https://example.com/a/../cb?x=%2F",
            "https://example.com/other",
        ] {
            assert_eq!(
                resolved.check_token_request(Some(&uri(value))),
                Err(DomainError::RedirectMismatch)
            );
        }
    }

    #[test]
    fn serde_round_trip_preserves_values() {
        let callback = uri("HTTPS://EXAMPLE.com:443/cb?x=%2f");
        for supplied in [false, true] {
            let value = ResolvedRedirect::new(callback.clone(), supplied);
            let json = serde_json::to_string(&value).unwrap();
            assert_eq!(
                serde_json::from_str::<ResolvedRedirect>(&json).unwrap(),
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
            let json = serde_json::json!({"uri": value, "uri_supplied": true}).to_string();
            assert!(serde_json::from_str::<ResolvedRedirect>(&json).is_err());
        }
    }
}
