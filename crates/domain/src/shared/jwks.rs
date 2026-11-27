use ddd_toolkit::ValueObject;

use crate::error::DomainError;

/// A JWKS as a JSON string. Only the length is checked (1-65536 bytes); whether it is valid
/// JSON and usable as keys is the application's concern.
#[derive(ValueObject)]
#[value_object(validate = validate_jwks_document, error = DomainError)]
pub struct JwksDocument(String);

impl JwksDocument {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn validate_jwks_document(value: &JwksDocument) -> Result<(), DomainError> {
    if value.0.is_empty() || value.0.len() > 65536 {
        return Err(DomainError::invalid(
            "jwks",
            "length must be 1 to 65536 bytes",
        ));
    }
    Ok(())
}

/// A `jwks_uri`: absolute https URL without userinfo or fragment, at most 2048 bytes.
#[derive(ValueObject)]
#[value_object(validate = validate_jwks_uri, error = DomainError)]
pub struct JwksUri(String);

impl JwksUri {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Skips validation so tests can use http and arbitrary hosts. Never call from production code.
    #[doc(hidden)]
    pub fn new_unchecked_for_testing(value: String) -> Self {
        Self(value)
    }
}

fn validate_jwks_uri(value: &JwksUri) -> Result<(), DomainError> {
    let s = &value.0;
    if s.len() > 2048 {
        return Err(DomainError::invalid("jwks_uri", "longer than 2048 bytes"));
    }
    // `url` silently strips tabs/newlines and surrounding spaces; refuse them so that
    // the stored string and the parsed URL never disagree.
    if s.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(DomainError::invalid(
            "jwks_uri",
            "whitespace or control character",
        ));
    }
    // `url` normalizes `\` to `/`, which would make the stored string differ from the parsed URL.
    if s.contains('\\') {
        return Err(DomainError::invalid(
            "jwks_uri",
            "must not contain a backslash",
        ));
    }
    if s.contains('#') {
        return Err(DomainError::invalid(
            "jwks_uri",
            "must not contain a fragment",
        ));
    }
    let url =
        url::Url::parse(s).map_err(|_| DomainError::invalid("jwks_uri", "not an absolute URL"))?;
    if url.scheme() != "https" {
        return Err(DomainError::invalid("jwks_uri", "scheme must be https"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(DomainError::invalid(
            "jwks_uri",
            "must not contain userinfo",
        ));
    }
    if url.host_str().is_none() {
        return Err(DomainError::invalid("jwks_uri", "host is required"));
    }
    Ok(())
}

/// How a client holds its public keys: exactly one of an inline JWKS or a `jwks_uri`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientKeys {
    Jwks(JwksDocument),
    JwksUri(JwksUri),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwks_document_length() {
        assert!(JwksDocument::try_new("{}".to_owned()).is_ok());
        assert!(JwksDocument::try_new(String::new()).is_err());
        assert!(JwksDocument::try_new("a".repeat(65536)).is_ok());
        assert!(JwksDocument::try_new("a".repeat(65537)).is_err());
    }

    #[test]
    fn jwks_uri_rules() {
        let ok = JwksUri::try_new("https://idp.example.com/jwks".to_owned()).unwrap();
        assert_eq!(ok.as_str(), "https://idp.example.com/jwks");
        for bad in [
            "http://idp.example.com/jwks",
            "https://u:p@h/",
            "https://u@h/",
            "https://h/#f",
            "https://h/#",
            "/jwks",
            "idp.example.com/jwks",
            " https://h/jwks",
            "https://h/jwks\n",
            "https://h/\tjwks",
            "https:\\\\h/jwks",
            "https://h\\jwks",
        ] {
            assert!(JwksUri::try_new(bad.to_owned()).is_err(), "{bad:?}");
        }
        let prefix = "https://h/";
        let at_limit = format!("{prefix}{}", "a".repeat(2048 - prefix.len()));
        assert!(JwksUri::try_new(at_limit).is_ok());
        let over = format!("{prefix}{}", "a".repeat(2049 - prefix.len()));
        assert_eq!(over.len(), 2049);
        assert!(JwksUri::try_new(over).is_err());
    }

    #[test]
    fn unchecked_constructor_allows_http() {
        let u = JwksUri::new_unchecked_for_testing("http://127.0.0.1:1/jwks".to_owned());
        assert_eq!(u.as_str(), "http://127.0.0.1:1/jwks");
    }
}
