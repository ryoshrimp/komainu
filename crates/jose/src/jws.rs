//! JWS Compact Serialization (RFC 7515).

use serde::ser::{Serialize, SerializeMap, Serializer};
use serde_json::Value;

use crate::algorithm::Algorithm;
use crate::b64;
use crate::error::JoseError;
use crate::json::{self, Kind};
use crate::key::{SigningKey, VerifyingKey};
use crate::kid::Kid;

/// The default limit on the length of a token, in bytes.
pub const DEFAULT_MAX_TOKEN_LEN: usize = 8192;

/// Options for [`sign`].
#[derive(Debug, Clone, Default)]
pub struct SignOptions {
    typ: Option<String>,
}

impl SignOptions {
    /// Options with no `typ`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the header `typ`. It is checked when signing.
    pub fn typ(mut self, typ: impl Into<String>) -> Self {
        self.typ = Some(typ.into());
        self
    }
}

/// Options for [`verify`].
#[derive(Debug, Clone)]
pub struct VerifyOptions {
    typ: Option<String>,
    max_token_len: usize,
}

impl VerifyOptions {
    /// No `typ` requirement and a token length limit of [`DEFAULT_MAX_TOKEN_LEN`].
    pub fn new() -> Self {
        Self {
            typ: None,
            max_token_len: DEFAULT_MAX_TOKEN_LEN,
        }
    }

    /// Requires the header `typ` to match (case-insensitive, optional `application/` prefix).
    pub fn require_typ(mut self, typ: impl Into<String>) -> Self {
        self.typ = Some(typ.into());
        self
    }

    /// Sets the token length limit in bytes.
    pub fn max_token_len(mut self, len: usize) -> Self {
        self.max_token_len = len;
        self
    }
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// A verified header. Only `alg`, `kid`, `typ` and `cty` are read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    alg: Algorithm,
    kid: Option<Kid>,
    typ: Option<String>,
    cty: Option<String>,
}

impl Header {
    /// The `alg` header.
    pub fn algorithm(&self) -> Algorithm {
        self.alg
    }

    /// The `kid` header.
    pub fn kid(&self) -> Option<&Kid> {
        self.kid.as_ref()
    }

    /// The `typ` header.
    pub fn typ(&self) -> Option<&str> {
        self.typ.as_deref()
    }

    /// The `cty` header.
    pub fn cty(&self) -> Option<&str> {
        self.cty.as_deref()
    }
}

/// A verified JWS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The header.
    pub header: Header,
    /// The payload bytes.
    pub payload: Vec<u8>,
}

/// A `typ` must be 1 to 64 printable ASCII bytes without spaces.
fn check_typ(typ: &str) -> Result<(), JoseError> {
    if !(1..=64).contains(&typ.len()) {
        return Err(JoseError::InvalidValue {
            field: "typ",
            reason: "length must be 1 to 64",
        });
    }
    if !typ.bytes().all(|b| (0x21..=0x7E).contains(&b)) {
        return Err(JoseError::InvalidValue {
            field: "typ",
            reason: "invalid character",
        });
    }
    Ok(())
}

/// RFC 7515 §4.1.9: ignore a leading `application/` and the case.
fn typ_matches(a: &str, b: &str) -> bool {
    fn strip(s: &str) -> &str {
        const PREFIX: &str = "application/";
        match s.get(..PREFIX.len()) {
            Some(head) if head.eq_ignore_ascii_case(PREFIX) => &s[PREFIX.len()..],
            _ => s,
        }
    }
    strip(a).eq_ignore_ascii_case(strip(b))
}

struct HeaderOut<'a> {
    alg: Algorithm,
    kid: Option<&'a Kid>,
    typ: Option<&'a str>,
}

impl Serialize for HeaderOut<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("alg", self.alg.as_str())?;
        if let Some(kid) = self.kid {
            map.serialize_entry("kid", kid.as_inner())?;
        }
        if let Some(typ) = self.typ {
            map.serialize_entry("typ", typ)?;
        }
        map.end()
    }
}

/// Signs `payload` and returns a JWS Compact string.
///
/// The header has `alg` (from the key), `kid` (if the key has one) and `typ` (if set).
pub fn sign(payload: &[u8], key: &SigningKey, options: &SignOptions) -> Result<String, JoseError> {
    if let Some(typ) = &options.typ {
        check_typ(typ)?;
    }
    let header = serde_json::to_vec(&HeaderOut {
        alg: key.algorithm(),
        kid: key.kid(),
        typ: options.typ.as_deref(),
    })
    .map_err(|_| JoseError::Encoding("header"))?;
    let signing_input = format!("{}.{}", b64::encode(header), b64::encode(payload));
    let signature = key.sign_raw(signing_input.as_bytes())?;
    Ok(format!("{signing_input}.{}", b64::encode(signature)))
}

/// Reads the optional string header `name`.
fn header_str(
    map: &serde_json::Map<String, Value>,
    name: &str,
    reason: &'static str,
) -> Result<Option<String>, JoseError> {
    match map.get(name) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(JoseError::Malformed(reason)),
    }
}

fn parse_header(bytes: &[u8]) -> Result<Header, JoseError> {
    let map = json::parse_object(bytes, Kind::Header)?;
    let Some(Value::String(alg)) = map.get("alg") else {
        return Err(JoseError::Malformed("header.alg"));
    };
    let alg: Algorithm = alg.parse()?;
    if map.contains_key("crit") {
        return Err(JoseError::UnsupportedHeader("crit"));
    }
    let kid = header_str(&map, "kid", "header.kid")?
        .map(|kid| Kid::try_new(kid).map_err(|_| JoseError::Malformed("header.kid")))
        .transpose()?;
    let typ = header_str(&map, "typ", "header.typ")?;
    let cty = header_str(&map, "cty", "header.cty")?;
    Ok(Header { alg, kid, typ, cty })
}

/// Verifies a JWS Compact string against `keys`.
///
/// With a `kid` header, the first key with that kid is used. Without one, every key with the
/// same algorithm is tried in order.
pub fn verify(
    token: &str,
    keys: &[VerifyingKey],
    options: &VerifyOptions,
) -> Result<Verified, JoseError> {
    if let Some(typ) = &options.typ {
        check_typ(typ)?;
    }
    if token.len() > options.max_token_len {
        return Err(JoseError::Malformed("token too long"));
    }
    let segments: Vec<&str> = token.split('.').collect();
    let [header_b64, payload_b64, signature_b64] = segments[..] else {
        return Err(JoseError::Malformed("segments"));
    };
    if header_b64.is_empty() || signature_b64.is_empty() {
        return Err(JoseError::Malformed("segments"));
    }
    let decode = |s: &str| b64::decode(s).ok_or(JoseError::Malformed("base64url"));
    let header_bytes = decode(header_b64)?;
    let payload = decode(payload_b64)?;
    let signature = decode(signature_b64)?;

    let header = parse_header(&header_bytes)?;
    if let Some(required) = &options.typ {
        match header.typ() {
            Some(typ) if typ_matches(typ, required) => {}
            _ => return Err(JoseError::InvalidTyp),
        }
    }

    let signing_input = &token[..header_b64.len() + 1 + payload_b64.len()];
    match header.kid() {
        Some(kid) => {
            let key = keys
                .iter()
                .find(|k| k.kid() == Some(kid))
                .ok_or(JoseError::KeyNotFound)?;
            if key.algorithm() != header.algorithm() {
                return Err(JoseError::AlgorithmMismatch);
            }
            key.verify_raw(signing_input.as_bytes(), &signature)?;
        }
        None => {
            let mut candidates = keys
                .iter()
                .filter(|k| k.algorithm() == header.algorithm())
                .peekable();
            if candidates.peek().is_none() {
                return Err(JoseError::KeyNotFound);
            }
            if !candidates.any(|k| k.verify_raw(signing_input.as_bytes(), &signature).is_ok()) {
                return Err(JoseError::InvalidSignature);
            }
        }
    }
    Ok(Verified { header, payload })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ddd_toolkit::secret::Secret;

    const ES_PEM: &str = include_str!("../tests/fixtures/es256.pem");
    const RSA_PEM: &str = include_str!("../tests/fixtures/rsa2048.pem");
    const ES_B_PEM: &str = include_str!("../tests/fixtures/es256b.pem");

    fn es() -> SigningKey {
        SigningKey::from_pkcs8_pem(&Secret::new(ES_PEM.to_owned())).unwrap()
    }

    fn rsa() -> SigningKey {
        SigningKey::from_pkcs8_pem(&Secret::new(RSA_PEM.to_owned())).unwrap()
    }

    fn es_b() -> SigningKey {
        SigningKey::from_pkcs8_pem(&Secret::new(ES_B_PEM.to_owned())).unwrap()
    }

    fn kid(s: &str) -> Kid {
        Kid::try_new(s.to_owned()).unwrap()
    }

    fn opts() -> VerifyOptions {
        VerifyOptions::new()
    }

    /// A token with a hand-written header, signed over the raw segments.
    fn token_with_header(header: &str, payload: &[u8], key: &SigningKey) -> String {
        let input = format!("{}.{}", b64::encode(header), b64::encode(payload));
        let sig = key.sign_raw(input.as_bytes()).unwrap();
        format!("{input}.{}", b64::encode(sig))
    }

    fn verify_one(token: &str, key: &SigningKey) -> Result<Verified, JoseError> {
        verify(token, &[key.verifying_key()], &opts())
    }

    #[test]
    fn sign_and_verify_round_trip() {
        for key in [es().with_kid(kid("k1")), rsa(), es()] {
            let token = sign(b"hello", &key, &SignOptions::new().typ("at+jwt")).unwrap();
            let verified = verify_one(&token, &key).unwrap();
            assert_eq!(verified.payload, b"hello");
            assert_eq!(verified.header.algorithm(), key.algorithm());
            assert_eq!(verified.header.kid(), key.kid());
            assert_eq!(verified.header.typ(), Some("at+jwt"));
            assert_eq!(verified.header.cty(), None);
        }
    }

    #[test]
    fn header_order_and_content() {
        let header_of = |token: &str| {
            String::from_utf8(b64::decode(token.split('.').next().unwrap()).unwrap()).unwrap()
        };
        let token = sign(
            b"",
            &es().with_kid(kid("k")),
            &SignOptions::new().typ("JWT"),
        )
        .unwrap();
        assert_eq!(
            header_of(&token),
            r#"{"alg":"ES256","kid":"k","typ":"JWT"}"#
        );
        let token = sign(b"", &rsa(), &SignOptions::new()).unwrap();
        assert_eq!(header_of(&token), r#"{"alg":"RS256"}"#);
    }

    #[test]
    fn empty_payload_is_allowed() {
        let key = es();
        let token = sign(b"", &key, &SignOptions::new()).unwrap();
        assert!(token.contains(".."));
        assert_eq!(verify_one(&token, &key).unwrap().payload, b"");
    }

    #[test]
    fn sign_rejects_bad_typ() {
        let long = "a".repeat(65);
        for typ in ["", "a b", "caf\u{e9}", long.as_str()] {
            assert!(matches!(
                sign(b"", &es(), &SignOptions::new().typ(typ)),
                Err(JoseError::InvalidValue { field: "typ", .. })
            ));
        }
        assert!(sign(b"", &es(), &SignOptions::new().typ("a".repeat(64))).is_ok());
        assert!(sign(b"", &es(), &SignOptions::new().typ("a")).is_ok());
    }

    #[test]
    fn verify_rejects_bad_required_typ_first() {
        // Step 0: before the token is looked at.
        assert!(matches!(
            verify("", &[], &opts().require_typ("a b")),
            Err(JoseError::InvalidValue { field: "typ", .. })
        ));
        assert!(matches!(
            verify("", &[], &opts().require_typ("")),
            Err(JoseError::InvalidValue { field: "typ", .. })
        ));
    }

    #[test]
    fn rejects_long_tokens() {
        let key = es();
        let token = sign(b"x", &key, &SignOptions::new()).unwrap();
        let len = token.len();
        assert!(verify(&token, &[key.verifying_key()], &opts().max_token_len(len)).is_ok());
        assert_eq!(
            verify(
                &token,
                &[key.verifying_key()],
                &opts().max_token_len(len - 1)
            )
            .unwrap_err(),
            JoseError::Malformed("token too long")
        );
        let big = "a".repeat(DEFAULT_MAX_TOKEN_LEN + 1);
        assert_eq!(
            verify(&big, &[], &opts()).unwrap_err(),
            JoseError::Malformed("token too long")
        );
    }

    #[test]
    fn rejects_bad_segments() {
        for token in [
            "", "a", "a.b", "a.b.c.d", "..", ".b.c", "a.b.", "a..", "..c",
        ] {
            assert_eq!(
                verify(token, &[], &opts()).unwrap_err(),
                JoseError::Malformed("segments"),
                "{token}"
            );
        }
    }

    #[test]
    fn rejects_bad_base64() {
        let key = es();
        let token = sign(b"abc", &key, &SignOptions::new()).unwrap();
        let [h, p, s] = token.split('.').collect::<Vec<_>>()[..] else {
            panic!()
        };
        for bad in [
            format!("{h}=.{p}.{s}"),
            format!("{h}.{p}=.{s}"),
            format!("{h}.{p}.{s}="),
            format!("{h}.a+b.{s}"),
            format!("{h}.{p}.a/b"),
            format!("{h}.{p} .{s}"),
            // Non-canonical trailing bits: "YQ" is "a", "YR" has a stray bit.
            format!("{h}.YR.{s}"),
            // Invalid length (1 mod 4).
            format!("{h}.Y.{s}"),
        ] {
            assert_eq!(
                verify(&bad, &[key.verifying_key()], &opts()).unwrap_err(),
                JoseError::Malformed("base64url"),
                "{bad}"
            );
        }
    }

    #[test]
    fn rejects_bad_header_json() {
        let key = es();
        for (header, reason) in [
            ("{", "header: syntax"),
            ("[]", "header: not an object"),
            (r#"{"alg":"ES256","alg":"ES256"}"#, "header: duplicate key"),
            (
                r#"{"alg":"ES256","x":{"a":1,"a":2}}"#,
                "header: duplicate key",
            ),
        ] {
            let token = token_with_header(header, b"", &key);
            assert_eq!(
                verify_one(&token, &key).unwrap_err(),
                JoseError::Malformed(reason)
            );
        }
        let input = format!("{}.{}", b64::encode([0xFF, 0xFE]), b64::encode(""));
        let token = format!("{input}.{}", b64::encode([1]));
        assert_eq!(
            verify_one(&token, &key).unwrap_err(),
            JoseError::Malformed("header: utf-8")
        );
    }

    #[test]
    fn rejects_bad_alg() {
        let key = es();
        for header in [
            r#"{}"#,
            r#"{"alg":1}"#,
            r#"{"alg":null}"#,
            r#"{"alg":["ES256"]}"#,
        ] {
            let token = token_with_header(header, b"", &key);
            assert_eq!(
                verify_one(&token, &key).unwrap_err(),
                JoseError::Malformed("header.alg"),
                "{header}"
            );
        }
        for alg in ["none", "None", "HS256", "es256", "ES384", "PS256", ""] {
            let token = token_with_header(&format!(r#"{{"alg":"{alg}"}}"#), b"", &key);
            assert_eq!(
                verify_one(&token, &key).unwrap_err(),
                JoseError::UnsupportedAlgorithm,
                "{alg}"
            );
        }
    }

    #[test]
    fn rejects_crit_whatever_its_value() {
        let key = es();
        for crit in ["[]", r#"["exp"]"#, "1", "null", r#""x""#] {
            let token =
                token_with_header(&format!(r#"{{"alg":"ES256","crit":{crit}}}"#), b"", &key);
            assert_eq!(
                verify_one(&token, &key).unwrap_err(),
                JoseError::UnsupportedHeader("crit")
            );
        }
    }

    #[test]
    fn rejects_bad_header_member_types() {
        let key = es();
        for (member, reason) in [
            (r#""kid":1"#, "header.kid"),
            (r#""kid":"""#, "header.kid"),
            (r#""kid":"a b""#, "header.kid"),
            (r#""typ":1"#, "header.typ"),
            (r#""typ":null"#, "header.typ"),
            (r#""cty":[]"#, "header.cty"),
        ] {
            let token = token_with_header(&format!(r#"{{"alg":"ES256",{member}}}"#), b"", &key);
            assert_eq!(
                verify_one(&token, &key).unwrap_err(),
                JoseError::Malformed(reason),
                "{member}"
            );
        }
    }

    #[test]
    fn typ_requirement() {
        let key = es();
        let verify_typ = |token: &str, required: &str| {
            verify(token, &[key.verifying_key()], &opts().require_typ(required)).map(|_| ())
        };
        let plain = sign(b"", &key, &SignOptions::new().typ("at+jwt")).unwrap();
        assert_eq!(verify_typ(&plain, "at+jwt"), Ok(()));
        assert_eq!(verify_typ(&plain, "AT+JWT"), Ok(()));
        assert_eq!(verify_typ(&plain, "application/at+jwt"), Ok(()));
        assert_eq!(verify_typ(&plain, "APPLICATION/At+Jwt"), Ok(()));
        assert_eq!(verify_typ(&plain, "jwt"), Err(JoseError::InvalidTyp));
        let prefixed = sign(b"", &key, &SignOptions::new().typ("Application/AT+JWT")).unwrap();
        assert_eq!(verify_typ(&prefixed, "at+jwt"), Ok(()));
        let none = sign(b"", &key, &SignOptions::new()).unwrap();
        assert_eq!(verify_typ(&none, "at+jwt"), Err(JoseError::InvalidTyp));
        // Without a requirement any typ is accepted.
        assert!(verify_one(&plain, &key).is_ok());
        // Multibyte input cannot panic the prefix handling.
        let odd = token_with_header(r#"{"alg":"ES256","typ":"ééééééé"}"#, b"", &key);
        assert_eq!(verify_typ(&odd, "at+jwt"), Err(JoseError::InvalidTyp));
    }

    #[test]
    fn typ_is_checked_after_header_errors() {
        // crit comes before typ.
        let key = es();
        let token = token_with_header(r#"{"alg":"ES256","crit":[],"typ":"x"}"#, b"", &key);
        assert_eq!(
            verify(&token, &[key.verifying_key()], &opts().require_typ("y")).unwrap_err(),
            JoseError::UnsupportedHeader("crit")
        );
    }

    #[test]
    fn key_selection_by_kid() {
        let a = es().with_kid(kid("a"));
        let b = es_b().with_kid(kid("b"));
        let keys = [a.verifying_key(), b.verifying_key()];
        let ta = sign(b"1", &a, &SignOptions::new()).unwrap();
        let tb = sign(b"2", &b, &SignOptions::new()).unwrap();
        assert_eq!(verify(&ta, &keys, &opts()).unwrap().payload, b"1");
        assert_eq!(verify(&tb, &keys, &opts()).unwrap().payload, b"2");
        // Unknown kid.
        assert_eq!(
            verify(&ta, &keys[1..], &opts()).unwrap_err(),
            JoseError::KeyNotFound
        );
        // A key without a kid is never used for a token with a kid.
        assert_eq!(
            verify(&ta, &[a.verifying_key().with_kid(kid("z"))], &opts()).unwrap_err(),
            JoseError::KeyNotFound
        );
        let no_kid_key = [es().verifying_key()];
        assert_eq!(
            verify(&ta, &no_kid_key, &opts()).unwrap_err(),
            JoseError::KeyNotFound
        );
        // Kid matches but the key is the other algorithm.
        let rsa_same_kid = rsa().with_kid(kid("a"));
        assert_eq!(
            verify(&ta, &[rsa_same_kid.verifying_key()], &opts()).unwrap_err(),
            JoseError::AlgorithmMismatch
        );
        // Wrong signature with a matching kid.
        let forged = sign(b"1", &b.clone().with_kid(kid("a")), &SignOptions::new()).unwrap();
        assert_eq!(
            verify(&forged, &keys, &opts()).unwrap_err(),
            JoseError::InvalidSignature
        );
        // No keys at all.
        assert_eq!(
            verify(&ta, &[], &opts()).unwrap_err(),
            JoseError::KeyNotFound
        );
    }

    /// F8: an ES256-only key set and an RS256 header with a random signature.
    #[test]
    fn f8_alg_is_bound_to_the_key() {
        let es_key = es();
        let garbage = b64::encode([0x5Au8; 256]);
        let with_kid = format!(
            "{}.{}.{garbage}",
            b64::encode(r#"{"alg":"RS256","kid":"a"}"#),
            b64::encode("{}")
        );
        let without_kid = format!(
            "{}.{}.{garbage}",
            b64::encode(r#"{"alg":"RS256"}"#),
            b64::encode("{}")
        );
        let keys = [es_key.with_kid(kid("a")).verifying_key()];
        assert_eq!(
            verify(&with_kid, &keys, &opts()).unwrap_err(),
            JoseError::AlgorithmMismatch
        );
        assert_eq!(
            verify(&without_kid, &keys, &opts()).unwrap_err(),
            JoseError::KeyNotFound
        );
    }

    /// §5.3: ES256 signatures with a high S value are accepted.
    #[test]
    fn es256_accepts_high_s() {
        let key = es();
        let token = sign(b"p", &key, &SignOptions::new()).unwrap();
        let [h, p, s] = token.split('.').collect::<Vec<_>>()[..] else {
            panic!()
        };
        let signature = p256::ecdsa::Signature::from_slice(&b64::decode(s).unwrap()).unwrap();
        let (r, s) = signature.split_scalars();
        let negated = p256::ecdsa::Signature::from_scalars(r.to_bytes(), (-*s).to_bytes()).unwrap();
        assert_ne!(negated.to_bytes(), signature.to_bytes());
        let flipped = format!("{h}.{p}.{}", b64::encode(negated.to_bytes()));
        assert_eq!(verify_one(&flipped, &key).unwrap().payload, b"p");
    }

    #[test]
    fn only_the_first_key_with_the_kid_is_used() {
        let a = es().with_kid(kid("a"));
        let other = es_b().with_kid(kid("a"));
        let token = sign(b"", &a, &SignOptions::new()).unwrap();
        let keys = [other.verifying_key(), a.verifying_key()];
        assert_eq!(
            verify(&token, &keys, &opts()).unwrap_err(),
            JoseError::InvalidSignature
        );
        let keys = [a.verifying_key(), other.verifying_key()];
        assert!(verify(&token, &keys, &opts()).is_ok());
    }

    #[test]
    fn keyless_tokens_try_candidates_by_algorithm() {
        let a = es();
        let other = es_b();
        let token = sign(b"", &a, &SignOptions::new()).unwrap();
        let keys = [
            rsa().verifying_key(),
            other.verifying_key(),
            a.verifying_key(),
        ];
        assert!(verify(&token, &keys, &opts()).is_ok());
        // Candidates exist but none verify.
        assert_eq!(
            verify(&token, &keys[..2], &opts()).unwrap_err(),
            JoseError::InvalidSignature
        );
        // No key of the algorithm.
        assert_eq!(
            verify(&token, &keys[..1], &opts()).unwrap_err(),
            JoseError::KeyNotFound
        );
        // Keys with kids are candidates too.
        let with_kid = [a.verifying_key().with_kid(kid("x"))];
        assert!(verify(&token, &with_kid, &opts()).is_ok());
    }

    #[test]
    fn rejects_tampering() {
        let key = es();
        let token = sign(b"payload", &key, &SignOptions::new()).unwrap();
        let [h, _, s] = token.split('.').collect::<Vec<_>>()[..] else {
            panic!()
        };
        let tampered = format!("{h}.{}.{s}", b64::encode("other"));
        assert_eq!(
            verify_one(&tampered, &key).unwrap_err(),
            JoseError::InvalidSignature
        );
        // A flipped signature byte.
        let mut sig = b64::decode(s).unwrap();
        sig[10] ^= 1;
        let tampered = format!("{h}.{}.{}", b64::encode("payload"), b64::encode(sig));
        assert_eq!(
            verify_one(&tampered, &key).unwrap_err(),
            JoseError::InvalidSignature
        );
        // Signature of the wrong length.
        let short = format!("{h}.{}.{}", b64::encode("payload"), b64::encode([1u8; 63]));
        assert_eq!(
            verify_one(&short, &key).unwrap_err(),
            JoseError::InvalidSignature
        );
    }

    #[test]
    fn signature_covers_the_received_header_text() {
        // The same header JSON with different spacing is a different signing input.
        let key = es();
        let compact = token_with_header(r#"{"alg":"ES256"}"#, b"p", &key);
        let [_, p, s] = compact.split('.').collect::<Vec<_>>()[..] else {
            panic!()
        };
        let spaced = format!("{}.{p}.{s}", b64::encode(r#"{"alg": "ES256"}"#));
        assert_eq!(
            verify_one(&spaced, &key).unwrap_err(),
            JoseError::InvalidSignature
        );
        // A header the verifier reads as the same is accepted if it was signed that way.
        let signed_spaced = token_with_header(r#"{"alg": "ES256"}"#, b"p", &key);
        assert!(verify_one(&signed_spaced, &key).is_ok());
    }

    #[test]
    fn rs256_signature_must_have_the_modulus_length() {
        let key = rsa();
        let token = sign(b"x", &key, &SignOptions::new()).unwrap();
        let [h, p, s] = token.split('.').collect::<Vec<_>>()[..] else {
            panic!()
        };
        let mut sig = b64::decode(s).unwrap();
        assert_eq!(sig.len(), 256);
        sig.insert(0, 0);
        let longer = format!("{h}.{p}.{}", b64::encode(&sig));
        assert_eq!(
            verify_one(&longer, &key).unwrap_err(),
            JoseError::InvalidSignature
        );
        sig.drain(..2);
        let shorter = format!("{h}.{p}.{}", b64::encode(&sig));
        assert_eq!(
            verify_one(&shorter, &key).unwrap_err(),
            JoseError::InvalidSignature
        );
    }

    #[test]
    fn ignores_key_embedding_headers() {
        // jwk, jku, x5u, x5c, x5t are read and thrown away.
        let key = es();
        let attacker = es_b();
        let header = format!(
            r#"{{"alg":"ES256","jwk":{},"jku":"https://evil.example/","x5u":"x","x5c":["x"],"x5t":"x"}}"#,
            attacker.verifying_key().to_jwk()
        );
        let forged = token_with_header(&header, b"", &attacker);
        assert_eq!(
            verify_one(&forged, &key).unwrap_err(),
            JoseError::InvalidSignature
        );
        let good = token_with_header(&header, b"", &key);
        assert!(verify_one(&good, &key).is_ok());
    }

    #[test]
    fn returns_cty() {
        let key = es();
        let token = token_with_header(r#"{"alg":"ES256","cty":"JWT"}"#, b"", &key);
        assert_eq!(verify_one(&token, &key).unwrap().header.cty(), Some("JWT"));
    }
}
