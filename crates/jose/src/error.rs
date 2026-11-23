//! The error type of this crate.

/// An error from this crate.
///
/// No variant holds a token, a key or a claim value; every message is a fixed string.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JoseError {
    /// A `Kid` or `typ` value violates its rules.
    #[error("invalid {field}: {reason}")]
    InvalidValue {
        /// The name of the rejected value.
        field: &'static str,
        /// Why it was rejected.
        reason: &'static str,
    },
    /// The input is not well-formed (length, segments, base64url, JSON, header member types).
    #[error("malformed input: {0}")]
    Malformed(&'static str),
    /// The `alg` is not supported, or is `none`.
    #[error("unsupported algorithm")]
    UnsupportedAlgorithm,
    /// A header parameter that must not be present (`crit`, or `cty` in a JWT).
    #[error("unsupported header parameter: {0}")]
    UnsupportedHeader(&'static str),
    /// No key could be selected for the token.
    #[error("no matching key")]
    KeyNotFound,
    /// The `alg` of the header differs from the algorithm of the selected key.
    #[error("algorithm does not match the key")]
    AlgorithmMismatch,
    /// The signature does not verify.
    #[error("invalid signature")]
    InvalidSignature,
    /// The `typ` header is missing or differs from the required one.
    #[error("invalid typ")]
    InvalidTyp,
    /// A key could not be loaded, or is not supported.
    #[error("invalid key: {0}")]
    InvalidKey(&'static str),
    /// Key generation failed (for example the OS random number generator failed).
    #[error("key generation failed")]
    KeyGeneration,
    /// Writing PEM, DER or JSON failed, or signing failed.
    #[error("encoding failed: {0}")]
    Encoding(&'static str),
    /// A required claim is missing.
    #[error("missing claim: {0}")]
    MissingClaim(&'static str),
    /// A claim has the wrong type or value.
    #[error("invalid claim: {0}")]
    InvalidClaim(&'static str),
    /// A custom claim uses the name of a registered claim.
    #[error("duplicate claim: {0}")]
    DuplicateClaim(&'static str),
    /// The `iss` claim does not match.
    #[error("invalid issuer")]
    InvalidIssuer,
    /// The `aud` claim does not contain the expected audience.
    #[error("invalid audience")]
    InvalidAudience,
    /// The token has expired.
    #[error("token expired")]
    Expired,
    /// The token is not valid yet.
    #[error("token not yet valid")]
    NotYetValid,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_messages() {
        assert_eq!(
            JoseError::InvalidValue {
                field: "kid",
                reason: "length"
            }
            .to_string(),
            "invalid kid: length"
        );
        assert_eq!(
            JoseError::Malformed("segments").to_string(),
            "malformed input: segments"
        );
        assert_eq!(
            JoseError::UnsupportedAlgorithm.to_string(),
            "unsupported algorithm"
        );
        assert_eq!(
            JoseError::UnsupportedHeader("crit").to_string(),
            "unsupported header parameter: crit"
        );
        assert_eq!(JoseError::KeyNotFound.to_string(), "no matching key");
        assert_eq!(
            JoseError::AlgorithmMismatch.to_string(),
            "algorithm does not match the key"
        );
        assert_eq!(JoseError::InvalidSignature.to_string(), "invalid signature");
        assert_eq!(JoseError::InvalidTyp.to_string(), "invalid typ");
        assert_eq!(JoseError::InvalidKey("der").to_string(), "invalid key: der");
        assert_eq!(
            JoseError::KeyGeneration.to_string(),
            "key generation failed"
        );
        assert_eq!(
            JoseError::Encoding("pem").to_string(),
            "encoding failed: pem"
        );
        assert_eq!(
            JoseError::MissingClaim("exp").to_string(),
            "missing claim: exp"
        );
        assert_eq!(
            JoseError::InvalidClaim("iat").to_string(),
            "invalid claim: iat"
        );
        assert_eq!(
            JoseError::DuplicateClaim("iss").to_string(),
            "duplicate claim: iss"
        );
        assert_eq!(JoseError::InvalidIssuer.to_string(), "invalid issuer");
        assert_eq!(JoseError::InvalidAudience.to_string(), "invalid audience");
        assert_eq!(JoseError::Expired.to_string(), "token expired");
        assert_eq!(JoseError::NotYetValid.to_string(), "token not yet valid");
    }
}
