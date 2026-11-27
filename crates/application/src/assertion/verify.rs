//! The verification shared by `private_key_jwt` and jwt-bearer (RFC 7521 §5.2, RFC 7523 §3).

use komainu_jose::jwt::{self, NoCustomClaims, Validation};
use komainu_jose::{JoseError, VerifyingKey};
use time::OffsetDateTime;

use super::{ASSERTION_LEEWAY, ASSERTION_MAX_LEN, ASSERTION_MAX_LIFETIME};

/// What the assertion must say.
pub(crate) struct Expected<'a> {
    pub issuer: &'a str,
    /// If `Some`, `sub` must equal it (client authentication: the `client_id`).
    pub subject: Option<&'a str>,
    /// `[issuer, "{issuer}/token"]`; `aud` must contain at least one.
    pub audiences: [&'a str; 2],
}

/// The claims of an assertion that passed [`verify_assertion`].
pub(crate) struct VerifiedAssertion {
    pub issuer: String,
    pub subject: String,
    pub jti: String,
    /// The `exp` claim itself (leeway not added). Record with `+ ASSERTION_LEEWAY`.
    pub exp: OffsetDateTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AssertionError {
    Malformed,
    KeyNotFound,
    Signature,
    Issuer,
    Audience,
    Expired,
    NotYetValid,
    LifetimeTooLong,
    MissingSubject,
    SubjectMismatch,
    /// `jti` is missing, empty or longer than 255 bytes.
    MissingJti,
}

impl AssertionError {
    /// The reason recorded in the audit log.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::KeyNotFound => "key_not_found",
            Self::Signature => "signature",
            Self::Issuer => "issuer",
            Self::Audience => "audience",
            Self::Expired => "expired",
            Self::NotYetValid => "not_yet_valid",
            Self::LifetimeTooLong => "lifetime_too_long",
            Self::MissingSubject => "missing_sub",
            Self::SubjectMismatch => "subject_mismatch",
            Self::MissingJti => "missing_jti",
        }
    }
}

impl From<JoseError> for AssertionError {
    fn from(error: JoseError) -> Self {
        match error {
            JoseError::KeyNotFound => Self::KeyNotFound,
            JoseError::InvalidSignature
            | JoseError::AlgorithmMismatch
            | JoseError::UnsupportedAlgorithm => Self::Signature,
            JoseError::InvalidIssuer | JoseError::MissingClaim("iss") => Self::Issuer,
            JoseError::InvalidAudience | JoseError::MissingClaim("aud") => Self::Audience,
            JoseError::Expired | JoseError::MissingClaim("exp") => Self::Expired,
            JoseError::NotYetValid | JoseError::InvalidClaim("iat") => Self::NotYetValid,
            JoseError::Malformed(_)
            | JoseError::UnsupportedHeader(_)
            | JoseError::InvalidTyp
            | JoseError::InvalidClaim(_)
            | JoseError::DuplicateClaim(_)
            | JoseError::MissingClaim(_)
            | JoseError::InvalidValue { .. }
            | JoseError::InvalidKey(_)
            | JoseError::KeyGeneration
            | JoseError::Encoding(_) => Self::Malformed,
            // `JoseError` is `#[non_exhaustive]`: variants added later are `malformed`.
            _ => Self::Malformed,
        }
    }
}

const MAX_JTI_LEN: usize = 255;

/// Verifies the signature with `keys` and the claims against `expected` at `now`.
pub(crate) fn verify_assertion(
    token: &str,
    keys: &[VerifyingKey],
    expected: &Expected<'_>,
    now: OffsetDateTime,
) -> Result<VerifiedAssertion, AssertionError> {
    let validation = Validation::new(expected.issuer, expected.audiences[0])
        .accept_audience(expected.audiences[1])
        .leeway(ASSERTION_LEEWAY.unsigned_abs())
        .max_token_len(ASSERTION_MAX_LEN);
    let registered = jwt::decode::<NoCustomClaims>(token, keys, &validation, now)?
        .claims
        .registered;

    let subject = registered
        .sub
        .filter(|s| !s.is_empty())
        .ok_or(AssertionError::MissingSubject)?;
    if expected.subject.is_some_and(|want| want != subject) {
        return Err(AssertionError::SubjectMismatch);
    }
    let jti = registered
        .jti
        .filter(|j| !j.is_empty() && j.len() <= MAX_JTI_LEN)
        .ok_or(AssertionError::MissingJti)?;
    // `decode` guarantees `exp` and `iss`.
    let exp = registered.exp.ok_or(AssertionError::Expired)?;
    if exp - now > ASSERTION_MAX_LIFETIME {
        return Err(AssertionError::LifetimeTooLong);
    }
    Ok(VerifiedAssertion {
        issuer: expected.issuer.to_owned(),
        subject,
        jti,
        exp,
    })
}

#[cfg(test)]
mod tests {
    use komainu_jose::jws::SignOptions;
    use komainu_jose::jwt::{Audience, Claims, RegisteredClaims};
    use komainu_jose::{RsaKeySize, SigningKey};

    use super::*;

    const ISS: &str = "https://idp.example.com";
    const AS: &str = "https://as.example.com";
    const T: i64 = 1_800_000_000;

    fn at(secs: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(secs).unwrap()
    }

    fn claims(exp: i64) -> RegisteredClaims {
        RegisteredClaims {
            iss: Some(ISS.into()),
            sub: Some("alice".into()),
            aud: Some(Audience::One(AS.into())),
            exp: Some(at(exp)),
            nbf: None,
            iat: None,
            jti: Some("jti-1".into()),
        }
    }

    fn expected() -> Expected<'static> {
        Expected {
            issuer: ISS,
            subject: None,
            audiences: [AS, "https://as.example.com/token"],
        }
    }

    fn sign(registered: RegisteredClaims, key: &SigningKey) -> String {
        jwt::encode(
            &Claims {
                registered,
                custom: NoCustomClaims,
            },
            key,
            &SignOptions::new(),
        )
        .unwrap()
    }

    struct Fixture {
        key: SigningKey,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                key: SigningKey::generate_es256().unwrap(),
            }
        }

        fn check(&self, registered: RegisteredClaims) -> Result<VerifiedAssertion, AssertionError> {
            let token = sign(registered, &self.key);
            verify_assertion(&token, &[self.key.verifying_key()], &expected(), at(T))
        }
    }

    #[test]
    fn valid_assertion_passes() {
        let ok = Fixture::new().check(claims(T + 60)).unwrap();
        assert_eq!(ok.issuer, ISS);
        assert_eq!(ok.subject, "alice");
        assert_eq!(ok.jti, "jti-1");
        assert_eq!(ok.exp, at(T + 60));
    }

    #[test]
    fn lifetime_and_expiry_boundaries() {
        let f = Fixture::new();
        assert!(f.check(claims(T + 300)).is_ok());
        assert_eq!(
            f.check(claims(T + 301)).err(),
            Some(AssertionError::LifetimeTooLong)
        );
        assert!(f.check(claims(T - 59)).is_ok());
        assert_eq!(f.check(claims(T - 60)).err(), Some(AssertionError::Expired));
    }

    #[test]
    fn audience_forms() {
        let f = Fixture::new();
        for aud in [
            Audience::One(AS.into()),
            Audience::One("https://as.example.com/token".into()),
            Audience::Many(vec![AS.into(), "https://as.example.com/token".into()]),
            Audience::Many(vec!["other".into(), AS.into(), "x/token".into()]),
        ] {
            let mut c = claims(T + 60);
            c.aud = Some(aud);
            assert!(f.check(c).is_ok());
        }
        let mut c = claims(T + 60);
        c.aud = Some(Audience::One("https://as.example.com/revoke".into()));
        assert_eq!(f.check(c).err(), Some(AssertionError::Audience));
        let mut c = claims(T + 60);
        c.aud = None;
        assert_eq!(f.check(c).err(), Some(AssertionError::Audience));
    }

    #[test]
    fn subject_rules() {
        let f = Fixture::new();
        let mut c = claims(T + 60);
        c.sub = None;
        assert_eq!(f.check(c).err(), Some(AssertionError::MissingSubject));
        let mut c = claims(T + 60);
        c.sub = Some(String::new());
        assert_eq!(f.check(c).err(), Some(AssertionError::MissingSubject));

        let token = sign(claims(T + 60), &f.key);
        let mut want = expected();
        want.subject = Some("alice");
        assert!(verify_assertion(&token, &[f.key.verifying_key()], &want, at(T)).is_ok());
        want.subject = Some("bob");
        assert_eq!(
            verify_assertion(&token, &[f.key.verifying_key()], &want, at(T)).err(),
            Some(AssertionError::SubjectMismatch)
        );
    }

    #[test]
    fn jti_rules() {
        let f = Fixture::new();
        for jti in [None, Some(String::new()), Some("a".repeat(256))] {
            let mut c = claims(T + 60);
            c.jti = jti;
            assert_eq!(f.check(c).err(), Some(AssertionError::MissingJti));
        }
        let mut c = claims(T + 60);
        c.jti = Some("a".repeat(255));
        assert!(f.check(c).is_ok());
    }

    #[test]
    fn issuer_and_signature_errors() {
        let f = Fixture::new();
        let mut c = claims(T + 60);
        c.iss = Some("https://evil.example".into());
        assert_eq!(f.check(c).err(), Some(AssertionError::Issuer));

        let other = SigningKey::generate_es256().unwrap();
        let token = sign(claims(T + 60), &other);
        assert_eq!(
            verify_assertion(&token, &[f.key.verifying_key()], &expected(), at(T)).err(),
            Some(AssertionError::Signature)
        );
        assert_eq!(
            verify_assertion(&token, &[], &expected(), at(T)).err(),
            Some(AssertionError::KeyNotFound)
        );
        assert_eq!(
            verify_assertion("not-a-jwt", &[], &expected(), at(T)).err(),
            Some(AssertionError::Malformed)
        );
    }

    #[test]
    fn not_yet_valid() {
        let f = Fixture::new();
        let mut c = claims(T + 60);
        c.nbf = Some(at(T + 61));
        assert_eq!(f.check(c).err(), Some(AssertionError::NotYetValid));
        let mut c = claims(T + 60);
        c.iat = Some(at(T + 61));
        assert_eq!(f.check(c).err(), Some(AssertionError::NotYetValid));
    }

    #[test]
    fn none_and_hs256_are_rejected() {
        let f = Fixture::new();
        let payload = format!(
            r#"{{"iss":"{ISS}","sub":"alice","aud":"{AS}","exp":{},"jti":"j"}}"#,
            T + 60
        );
        let b64 = |s: &str| {
            use base64::Engine;
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s)
        };
        for alg in ["none", "HS256"] {
            let token = format!(
                "{}.{}.{}",
                b64(&format!(r#"{{"alg":"{alg}"}}"#)),
                b64(&payload),
                b64("sig")
            );
            let got = verify_assertion(&token, &[f.key.verifying_key()], &expected(), at(T));
            assert_eq!(got.err(), Some(AssertionError::Signature), "{alg}");
        }
    }

    #[test]
    fn rs256_and_es256_keys_both_work() {
        let rsa = SigningKey::generate_rsa(RsaKeySize::Bits2048).unwrap();
        let token = sign(claims(T + 60), &rsa);
        assert!(verify_assertion(&token, &[rsa.verifying_key()], &expected(), at(T)).is_ok());
        assert!(Fixture::new().check(claims(T + 60)).is_ok());
    }

    #[test]
    fn jose_error_mapping_reasons() {
        assert_eq!(
            AssertionError::from(JoseError::InvalidTyp).reason(),
            "malformed"
        );
        assert_eq!(
            AssertionError::from(JoseError::MissingClaim("exp")).reason(),
            "expired"
        );
        assert_eq!(
            AssertionError::from(JoseError::MissingClaim("sub")).reason(),
            "malformed"
        );
    }
}
