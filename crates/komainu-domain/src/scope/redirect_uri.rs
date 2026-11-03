use crate::error::DomainError;

fn validate_redirect_uri(s: &str) -> Result<(), DomainError> {
    let invalid = || DomainError::InvalidRedirectUri;
    let bytes = s.as_bytes();

    if s.is_empty()
        || !bytes.iter().all(|&b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'-' | b'.'
                        | b'_'
                        | b'~'
                        | b':'
                        | b'/'
                        | b'?'
                        | b'#'
                        | b'['
                        | b']'
                        | b'@'
                        | b'!'
                        | b'$'
                        | b'&'
                        | b'\''
                        | b'('
                        | b')'
                        | b'*'
                        | b'+'
                        | b','
                        | b';'
                        | b'='
                        | b'%'
                )
        })
    {
        return Err(invalid());
    }

    for (i, &b) in bytes.iter().enumerate() {
        if b == b'%'
            && !bytes
                .get(i + 1..i + 3)
                .is_some_and(|pair| pair.iter().all(u8::is_ascii_hexdigit))
        {
            return Err(invalid());
        }
    }

    let (scheme, rest) = s.split_once("://").ok_or_else(invalid)?;
    if !scheme.eq_ignore_ascii_case("https") {
        return Err(invalid());
    }

    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return Err(invalid());
    }

    // RFC 3986 permits raw brackets in an IP literal in the authority,
    // but not in path or query components. Url::parse accepts the latter.
    if rest[authority.len()..].contains(['[', ']']) {
        return Err(invalid());
    }

    let url = url::Url::parse(s).map_err(|_| invalid())?;
    if !url.has_host() || url.fragment().is_some() {
        return Err(invalid());
    }

    Ok(())
}

/// **English:**<br>
/// An absolute HTTPS redirect URI stored and compared as its original string.
///
/// [`Self::parse`] and [`Self::try_new`] require a host and reject user information,
/// fragments (including an empty fragment), non-ASCII characters, whitespace,
/// malformed percent escapes, and characters outside the URI character set.
/// Raw brackets are permitted only in the authority, not in the path or query.
/// Validation also requires acceptance by [`url::Url::parse`]; the parsed URL is discarded.
/// Every rejection returns [`DomainError::InvalidRedirectUri`].
///
/// No normalization occurs: host case, explicit ports, path segments, and percent-escape
/// spelling remain significant for equality and ordering. Serde writes the original
/// string and performs the same validation when reading it. Validation does not
/// contact the host or establish that the destination is trustworthy.
///
/// **日本語:**<br>
/// 元の文字列を保持し、そのまま比較する絶対 HTTPS リダイレクト URI です。
///
/// [`Self::parse`] と [`Self::try_new`] はホストを必須とし、ユーザー情報、
/// 空の場合を含むフラグメント、非 ASCII 文字、空白、不正なパーセントエスケープ、
/// URI 文字集合外の文字を拒否します。
/// エスケープされていない角括弧は authority 内でのみ許可し、パスやクエリでは拒否します。
/// [`url::Url::parse`] で解析できることも確認しますが、解析結果は保持しません。
/// 拒否時はすべて [`DomainError::InvalidRedirectUri`] を返します。
///
/// 正規化は行いません。ホストの大文字小文字、明示ポート、パス要素、
/// パーセントエスケープの表記は等値比較と並び順に影響します。
/// Serde は元の文字列を出力し、読み込み時にも同じ検証を行います。
/// 検証はホストに接続せず、宛先の信頼性も保証しません。
///
/// # Example / 使用例
/// ```rust
/// use komainu_domain::scope::RedirectUri;
///
/// let uri = RedirectUri::parse("HTTPS://EXAMPLE.com:443/cb?x=%2f").unwrap();
/// assert_eq!(uri.as_inner(), "HTTPS://EXAMPLE.com:443/cb?x=%2f");
/// assert!(RedirectUri::parse("https://example.com/cb#fragment").is_err());
/// ```
#[derive(ddd_toolkit::ValueObject, PartialOrd, Ord)]
#[value_object(validate = validate_redirect_uri, error = DomainError, serde)]
pub struct RedirectUri(String);

impl RedirectUri {
    /// **English:**<br>
    /// Copies `value` into a validated URI without normalization.
    /// Returns [`DomainError::InvalidRedirectUri`] if any constraint on [`RedirectUri`] fails.
    ///
    /// **日本語:**<br>
    /// `value` を正規化せずコピーして検証済み URI を作ります。
    /// [`RedirectUri`] の制約に違反すると [`DomainError::InvalidRedirectUri`] を返します。
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        RedirectUri::try_new(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_uri_accepts_https_without_normalizing_the_value() {
        for value in [
            "https://example.com",
            "HTTPS://EXAMPLE.com:443/a/../cb?x=%2f",
            "https://example.com/cb?x=1&y=2",
            "https://example.com/%5Bx%5D?x=%5ba%5d",
            "https://[::1]/cb",
            "https://[2001:db8::1]:8443/cb?x=1",
            "https://example.com/!$&'()*+,;=:@-._~?x=/?:@",
        ] {
            assert_eq!(RedirectUri::parse(value).unwrap().as_inner(), value);
        }
    }

    #[test]
    fn redirect_uri_rejects_invalid_or_prohibited_values() {
        for value in [
            "",
            "/cb",
            "http://example.com/cb",
            "javascript:alert(1)",
            "https:///cb",
            "https://",
            "https://user@example.com/cb",
            "https://user:pass@example.com/cb",
            "https://example.com/cb#fragment",
            "https://example.com/cb#",
            "https://example.com/a b",
            "https://example.com/日本語",
            "https://example.com/\\cb",
            "https://example.com/\ncb",
            "https://example.com/%",
            "https://example.com/%0",
            "https://example.com/%GG",
            "https://example.com/[x]",
            "https://example.com/a]",
            "https://example.com/?x=[a]",
            "https://example.com/?x=]",
            "https://[::1]/[x]",
            "https://[::1]/?x=[a]",
            "https://[invalid]/cb",
            "https://example.com:99999/cb",
        ] {
            assert_eq!(
                RedirectUri::parse(value),
                Err(DomainError::InvalidRedirectUri),
                "{value:?}"
            );
        }
    }

    #[test]
    fn serde_round_trip_preserves_value() {
        let value = RedirectUri::parse("HTTPS://EXAMPLE.com:443/cb?x=%2f").unwrap();
        let json = serde_json::to_string(&value).unwrap();
        assert_eq!(serde_json::from_str::<RedirectUri>(&json).unwrap(), value);
    }

    #[test]
    fn serde_rejects_invalid_values() {
        for value in [
            "http://example.com/cb",
            "https://example.com/[x]",
            "https://example.com/?x=[a]",
            "https://example.com/#x",
        ] {
            let json = serde_json::to_string(value).unwrap();
            assert!(serde_json::from_str::<RedirectUri>(&json).is_err());
        }
    }
}
