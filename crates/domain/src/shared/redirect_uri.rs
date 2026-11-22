use std::hash::{Hash, Hasher};

use crate::error::DomainError;

/// An absolute redirection URI without fragment (RFC 6749 §3.1.2).
///
/// Equality is exact comparison of the original string; nothing is normalized.
///
/// Hand-written instead of `#[derive(ValueObject)]` so the parsed form can be kept next to the
/// original string, which lets `scheme()` and `host()` return `&str`.
#[derive(Clone)]
pub struct RedirectUri {
    raw: String,
    parsed: url::Url,
}

impl PartialEq for RedirectUri {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}

impl Eq for RedirectUri {}

impl Hash for RedirectUri {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
    }
}

impl std::fmt::Debug for RedirectUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("RedirectUri").field(&self.raw).finish()
    }
}

fn parse_redirect_uri(s: &str) -> Result<url::Url, DomainError> {
    if s.len() > 2000 {
        return Err(DomainError::invalid(
            "redirect_uri",
            "longer than 2000 bytes",
        ));
    }
    if s.contains('#') {
        return Err(DomainError::invalid(
            "redirect_uri",
            "must not contain a fragment",
        ));
    }
    // `url` silently strips tabs/newlines and surrounding spaces; refuse them so that
    // the stored string and the parsed URI never disagree.
    if s.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(DomainError::invalid(
            "redirect_uri",
            "whitespace or control character",
        ));
    }
    url::Url::parse(s).map_err(|_| DomainError::invalid("redirect_uri", "not an absolute URI"))
}

impl RedirectUri {
    /// Validates `raw` and keeps it unchanged.
    pub fn try_new(raw: String) -> Result<Self, DomainError> {
        let parsed = parse_redirect_uri(&raw)?;
        Ok(Self { raw, parsed })
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Lowercase scheme, as parsed by `url` (the same parser browsers agree with).
    pub fn scheme(&self) -> &str {
        self.parsed.scheme()
    }

    /// Host for http/https URIs (IPv6 as `[::1]`); None otherwise.
    pub fn host(&self) -> Option<&str> {
        if !matches!(self.parsed.scheme(), "http" | "https") {
            return None;
        }
        self.parsed.host_str()
    }

    /// Appends params to the existing query component, keeping existing params (§3.1.2, §4.1.2).
    /// Values are application/x-www-form-urlencoded.
    pub fn with_query_params(&self, params: &[(&str, &str)]) -> String {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        serializer.extend_pairs(params);
        let encoded = serializer.finish();
        let sep = if self.raw.contains('?') {
            if self.raw.ends_with('?') || self.raw.ends_with('&') {
                ""
            } else {
                "&"
            }
        } else {
            "?"
        };
        format!("{}{sep}{encoded}", self.raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uri(s: &str) -> RedirectUri {
        RedirectUri::try_new(s.to_owned()).unwrap()
    }

    #[test]
    fn rejects_fragment_relative_and_too_long() {
        assert!(RedirectUri::try_new("https://a.example/cb#x".to_owned()).is_err());
        assert!(RedirectUri::try_new("/cb".to_owned()).is_err());
        let long = format!("https://a.example/{}", "a".repeat(2000));
        assert!(RedirectUri::try_new(long).is_err());
    }

    #[test]
    fn accepts_custom_scheme() {
        let u = uri("com.example.app:/cb");
        assert_eq!(u.scheme(), "com.example.app");
        assert_eq!(uri("HTTPS://A.example/cb").scheme(), "https");
        assert_eq!(u.host(), None);
    }

    #[test]
    fn host_of_http_uris() {
        assert_eq!(uri("https://a.example/cb").host(), Some("a.example"));
        assert_eq!(uri("http://127.0.0.1:8080/cb").host(), Some("127.0.0.1"));
        assert_eq!(uri("http://[::1]:8080/cb").host(), Some("[::1]"));
        assert_eq!(uri("http://localhost").host(), Some("localhost"));
    }

    #[test]
    fn host_follows_the_url_parser() {
        assert_eq!(
            uri("http://evil.com\\@localhost/cb").host(),
            Some("evil.com")
        );
        assert_eq!(uri("http://localhost@evil.com/cb").host(), Some("evil.com"));
        assert_eq!(uri("HTTP://LocalHost/cb").host(), Some("localhost"));
        for bad in [
            " http://evil.com/cb",
            "\thttp://evil.com/cb",
            "http://a.example/cb ",
            "http://a.example/\ncb",
        ] {
            assert!(RedirectUri::try_new(bad.to_owned()).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn appends_to_existing_query() {
        let u = uri("https://a.example/cb?x=1");
        assert_eq!(
            u.with_query_params(&[("code", "abc"), ("state", "s t")]),
            "https://a.example/cb?x=1&code=abc&state=s+t"
        );
        assert_eq!(
            uri("https://a.example/cb").with_query_params(&[("code", "abc")]),
            "https://a.example/cb?code=abc"
        );
    }
}
