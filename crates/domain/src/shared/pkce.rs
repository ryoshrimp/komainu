use std::fmt;
use std::str::FromStr;

use base64::Engine;
use base64::alphabet::URL_SAFE;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use ddd_toolkit::ValueObject;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::Secret;
use crate::error::DomainError;

/// base64url without padding; only canonical encodings are accepted.
const ENGINE: GeneralPurpose = GeneralPurpose::new(
    &URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::RequireNone)
        .with_decode_allow_trailing_bits(false),
);

/// `code_challenge_method`. Only `S256` is supported (RFC 7636 §4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CodeChallengeMethod {
    S256,
}

impl CodeChallengeMethod {
    /// `"S256"`. Stored in the database as-is.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::S256 => "S256",
        }
    }
}

/// Case-sensitive: only `"S256"` is accepted.
impl FromStr for CodeChallengeMethod {
    type Err = DomainError;
    fn from_str(s: &str) -> Result<Self, DomainError> {
        match s {
            "S256" => Ok(Self::S256),
            _ => Err(DomainError::invalid(
                "code_challenge_method",
                "must be S256",
            )),
        }
    }
}

/// `code_challenge` for S256: base64url (no padding) of a 32-byte SHA-256 digest.
#[derive(ValueObject)]
#[value_object(validate = validate_code_challenge, error = DomainError)]
pub struct CodeChallenge(String);

fn validate_code_challenge(value: &CodeChallenge) -> Result<(), DomainError> {
    match ENGINE.decode(&value.0) {
        Ok(bytes) if bytes.len() == 32 => Ok(()),
        _ => Err(DomainError::invalid(
            "code_challenge",
            "must be 43 base64url characters",
        )),
    }
}

/// `code_verifier` (RFC 7636 §4.1): 43-128 characters of `[A-Za-z0-9-._~]`.
pub struct CodeVerifier(Secret<String>);

impl CodeVerifier {
    pub fn try_new(value: Secret<String>) -> Result<Self, DomainError> {
        let s = value.expose_secret_ref();
        if !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
        {
            return Err(DomainError::invalid("code_verifier", "invalid character"));
        }
        if !(43..=128).contains(&s.len()) {
            return Err(DomainError::invalid(
                "code_verifier",
                "length must be 43 to 128",
            ));
        }
        Ok(CodeVerifier(value))
    }

    pub fn expose(&self) -> &str {
        self.0.expose_secret_ref()
    }
}

impl fmt::Debug for CodeVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("CodeVerifier").field(&self.0).finish()
    }
}

/// The challenge stored with an authorization request and its code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkceChallenge {
    challenge: CodeChallenge,
    method: CodeChallengeMethod,
}

impl PkceChallenge {
    pub fn new(challenge: CodeChallenge, method: CodeChallengeMethod) -> Self {
        PkceChallenge { challenge, method }
    }

    pub fn challenge(&self) -> &CodeChallenge {
        &self.challenge
    }

    pub fn method(&self) -> CodeChallengeMethod {
        self.method
    }

    /// Constant-time comparison of the S256 transform of `verifier` with the challenge.
    pub fn verify(&self, verifier: &CodeVerifier) -> bool {
        match self.method {
            CodeChallengeMethod::S256 => {
                let computed = ENGINE.encode(Sha256::digest(verifier.expose().as_bytes()));
                computed
                    .as_bytes()
                    .ct_eq(self.challenge.as_inner().as_bytes())
                    .into()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verifier(s: &str) -> CodeVerifier {
        CodeVerifier::try_new(Secret::new(s.to_owned())).unwrap()
    }

    fn pkce(challenge: &str) -> PkceChallenge {
        PkceChallenge::new(
            CodeChallenge::try_new(challenge.to_owned()).unwrap(),
            CodeChallengeMethod::S256,
        )
    }

    #[test]
    fn verify_known_pairs() {
        let a43 = "a".repeat(43);
        let p = pkce("ZtNPunH49FD35FWYhT5Tv8I7vRKQJ8uxMaL0_9eHjNA");
        assert!(p.verify(&verifier(&a43)));
        assert!(!p.verify(&verifier(&"b".repeat(43))));
        assert!(
            pkce("8BtXImJhrjdWuTk24cTmuEn5pbCTP6O5GEO_QZW52WQ").verify(&verifier(&"b".repeat(43)))
        );
        assert!(
            pkce("aDbPE7rEAOkQUHHNavRwhN-srU5eMCyUv-0k4BOvtz4").verify(&verifier(&"a".repeat(128)))
        );
        // RFC 7636 Appendix B.
        assert!(
            pkce("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
                .verify(&verifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))
        );
    }

    #[test]
    fn challenge_rules() {
        let ok = "ZtNPunH49FD35FWYhT5Tv8I7vRKQJ8uxMaL0_9eHjNA";
        assert!(CodeChallenge::try_new(ok.to_owned()).is_ok());
        assert!(CodeChallenge::try_new(ok[..42].to_owned()).is_err());
        assert!(CodeChallenge::try_new(format!("{ok}A")).is_err());
        assert!(CodeChallenge::try_new(format!("{ok}=")).is_err());
        assert!(CodeChallenge::try_new(format!("{}+", &ok[..42])).is_err());
        assert!(CodeChallenge::try_new(format!("{}/", &ok[..42])).is_err());
        // Non-zero trailing bits.
        assert!(
            CodeChallenge::try_new("ZtNPunH49FD35FWYhT5Tv8I7vRKQJ8uxMaL0_9eHjNB".to_owned())
                .is_err()
        );
        assert!(CodeChallenge::try_new(String::new()).is_err());
    }

    #[test]
    fn verifier_rules() {
        let try_new = |s: String| CodeVerifier::try_new(Secret::new(s));
        assert!(try_new("a".repeat(42)).is_err());
        assert!(try_new("a".repeat(43)).is_ok());
        assert!(try_new("a".repeat(128)).is_ok());
        assert!(try_new("a".repeat(129)).is_err());
        assert!(try_new(format!("{}~.-_", "a".repeat(43))).is_ok());
        assert!(try_new(format!("{} ", "a".repeat(43))).is_err());
        assert!(try_new(format!("{}+", "a".repeat(43))).is_err());
        assert!(try_new(format!("{}é", "a".repeat(43))).is_err());
    }

    #[test]
    fn method_is_case_sensitive_s256_only() {
        assert_eq!("S256".parse(), Ok(CodeChallengeMethod::S256));
        assert_eq!(CodeChallengeMethod::S256.as_str(), "S256");
        assert!("plain".parse::<CodeChallengeMethod>().is_err());
        assert!("s256".parse::<CodeChallengeMethod>().is_err());
        assert!("".parse::<CodeChallengeMethod>().is_err());
    }

    #[test]
    fn verifier_debug_is_redacted() {
        assert_eq!(
            format!("{:?}", verifier(&"a".repeat(43))),
            "CodeVerifier([REDACTED])"
        );
    }
}
