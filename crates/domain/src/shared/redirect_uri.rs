use ddd_toolkit::ValueObject;

use crate::error::DomainError;

/// An absolute redirection URI without fragment (RFC 6749 §3.1.2).
///
/// Equality is exact comparison of the original string; nothing is normalized.
#[derive(ValueObject)]
#[value_object(validate = validate_redirect_uri, error = DomainError)]
pub struct RedirectUri(String);

fn validate_redirect_uri(value: &RedirectUri) -> Result<(), DomainError> {
    let s = &value.0;
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
    url::Url::parse(s).map_err(|_| DomainError::invalid("redirect_uri", "not an absolute URI"))?;
    Ok(())
}

impl RedirectUri {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Lowercase scheme, as parsed by `url` (the same parser browsers agree with).
    pub fn scheme(&self) -> String {
        self.parsed().scheme().to_owned()
    }

    /// Host for http/https URIs (IPv6 as `[::1]`); None otherwise.
    pub fn host(&self) -> Option<String> {
        let url = self.parsed();
        if !matches!(url.scheme(), "http" | "https") {
            return None;
        }
        url.host_str().map(str::to_owned)
    }

    fn parsed(&self) -> url::Url {
        // Validated in `validate_redirect_uri`.
        url::Url::parse(&self.0).expect("validated absolute URI")
    }

    /// Appends params to the existing query component, keeping existing params (§3.1.2, §4.1.2).
    /// Values are application/x-www-form-urlencoded.
    pub fn with_query_params(&self, params: &[(&str, &str)]) -> String {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        serializer.extend_pairs(params);
        let encoded = serializer.finish();
        let sep = if self.0.contains('?') {
            if self.0.ends_with('?') || self.0.ends_with('&') {
                ""
            } else {
                "&"
            }
        } else {
            "?"
        };
        format!("{}{sep}{encoded}", self.0)
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
        assert_eq!(
            uri("https://a.example/cb").host(),
            Some("a.example".to_owned())
        );
        assert_eq!(
            uri("http://127.0.0.1:8080/cb").host(),
            Some("127.0.0.1".to_owned())
        );
        assert_eq!(uri("http://[::1]:8080/cb").host(), Some("[::1]".to_owned()));
        assert_eq!(uri("http://localhost").host(), Some("localhost".to_owned()));
    }

    #[test]
    fn host_follows_the_url_parser() {
        assert_eq!(
            uri("http://evil.com\\@localhost/cb").host(),
            Some("evil.com".to_owned())
        );
        assert_eq!(
            uri("http://localhost@evil.com/cb").host(),
            Some("evil.com".to_owned())
        );
        assert_eq!(
            uri("HTTP://LocalHost/cb").host(),
            Some("localhost".to_owned())
        );
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
