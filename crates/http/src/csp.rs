use axum::http::HeaderValue;

const STRICT: &str = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'";
const FRAME_ANCESTORS_NONE: &str = "frame-ancestors 'none'";

/// The `Content-Security-Policy` komainu sends with HTML responses.
///
/// The policy always ends with `frame-ancestors 'none'`; it cannot be changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentSecurityPolicy {
    value: String,
}

impl ContentSecurityPolicy {
    /// `default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'`.
    pub fn strict() -> Self {
        Self {
            value: STRICT.to_owned(),
        }
    }

    /// Uses `directives` followed by `; frame-ancestors 'none'`.
    ///
    /// Surrounding whitespace and trailing `;` are removed. The content of the directives is
    /// not validated.
    ///
    /// The built-in `DefaultScreens` use an inline `<style>`, so keep `'unsafe-inline'` in
    /// `style-src` when you delegate to them.
    ///
    /// # Errors
    ///
    /// - [`CspError::Empty`] when nothing is left after trimming.
    /// - [`CspError::FrameAncestorsNotAllowed`] when a directive is `frame-ancestors`.
    /// - [`CspError::InvalidHeaderValue`] when the result cannot be a header value.
    pub fn custom(directives: &str) -> Result<Self, CspError> {
        let directives = directives
            .trim_start_matches(|c: char| c.is_ascii_whitespace())
            .trim_end_matches(|c: char| c.is_ascii_whitespace() || c == ';');
        if directives.is_empty() {
            return Err(CspError::Empty);
        }
        let sets_frame_ancestors = directives.split(';').any(|directive| {
            directive
                .trim_matches(|c: char| c.is_ascii_whitespace())
                .split_ascii_whitespace()
                .next()
                .is_some_and(|name| name.eq_ignore_ascii_case("frame-ancestors"))
        });
        if sets_frame_ancestors {
            return Err(CspError::FrameAncestorsNotAllowed);
        }
        let value = format!("{directives}; {FRAME_ANCESTORS_NONE}");
        HeaderValue::from_str(&value).map_err(|_| CspError::InvalidHeaderValue)?;
        Ok(Self { value })
    }

    /// The full header value komainu sends.
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl Default for ContentSecurityPolicy {
    fn default() -> Self {
        Self::strict()
    }
}

/// Why a [`ContentSecurityPolicy`] was rejected.
#[non_exhaustive]
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CspError {
    /// No directive is left after trimming.
    #[error("content security policy must not be empty")]
    Empty,
    /// The policy sets `frame-ancestors`, which komainu always sends as `'none'`.
    #[error(
        "content security policy must not set frame-ancestors; komainu always sends frame-ancestors 'none'"
    )]
    FrameAncestorsNotAllowed,
    /// The policy contains characters that a header value cannot hold (e.g. a newline).
    #[error("content security policy is not a valid header value")]
    InvalidHeaderValue,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_is_todays_value() {
        assert_eq!(ContentSecurityPolicy::strict().as_str(), STRICT);
        assert_eq!(
            ContentSecurityPolicy::default(),
            ContentSecurityPolicy::strict()
        );
    }

    #[test]
    fn custom_appends_frame_ancestors() {
        for input in [
            "default-src 'self'",
            "default-src 'self';",
            "default-src 'self'\n",
        ] {
            assert_eq!(
                ContentSecurityPolicy::custom(input).unwrap().as_str(),
                "default-src 'self'; frame-ancestors 'none'"
            );
        }
        assert_eq!(
            ContentSecurityPolicy::custom("default-src 'self' ;; ")
                .unwrap()
                .as_str(),
            "default-src 'self'; frame-ancestors 'none'"
        );
    }

    #[test]
    fn custom_rejects_empty() {
        assert_eq!(ContentSecurityPolicy::custom("  "), Err(CspError::Empty));
        assert_eq!(ContentSecurityPolicy::custom(" ; "), Err(CspError::Empty));
        assert_eq!(ContentSecurityPolicy::custom(""), Err(CspError::Empty));
    }

    #[test]
    fn custom_rejects_frame_ancestors() {
        for input in [
            "default-src 'self'; Frame-Ancestors https://a.example",
            "frame-ancestors 'self'",
            "default-src 'self';\tframe-ancestors\t*",
        ] {
            assert_eq!(
                ContentSecurityPolicy::custom(input),
                Err(CspError::FrameAncestorsNotAllowed),
                "{input}"
            );
        }
    }

    #[test]
    fn custom_rejects_invalid_header_value() {
        assert_eq!(
            ContentSecurityPolicy::custom("default-src\n'self'"),
            Err(CspError::InvalidHeaderValue)
        );
    }

    #[test]
    fn custom_keeps_inner_empty_directives() {
        assert_eq!(
            ContentSecurityPolicy::custom("a;; b").unwrap().as_str(),
            "a;; b; frame-ancestors 'none'"
        );
    }
}
