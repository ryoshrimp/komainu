//! JWK and JWK Set (RFC 7517), plus RFC 7638 thumbprints.

use std::collections::HashSet;

use rsa::BoxedUint;
use rsa::traits::PublicKeyParts;
use serde::ser::{Serialize, SerializeMap, Serializer};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::algorithm::Algorithm;
use crate::b64;
use crate::error::JoseError;
use crate::json::{self, Kind};
use crate::key::{SigningKey, VerifyingInner, VerifyingKey, check_rsa_exponent, check_rsa_modulus};
use crate::kid::Kid;

const PRIVATE_RSA: [&str; 7] = ["d", "p", "q", "dp", "dq", "qi", "oth"];

/// The public parameters of a key, base64url encoded.
enum Params {
    Rsa { n: String, e: String },
    Ec { x: String, y: String },
}

impl VerifyingKey {
    fn params(&self) -> Params {
        match &self.inner {
            VerifyingInner::Rsa(k) => Params::Rsa {
                n: b64::encode(k.n().to_be_bytes_trimmed_vartime()),
                e: b64::encode(k.e().to_be_bytes_trimmed_vartime()),
            },
            VerifyingInner::Ec(k) => {
                let point = k.to_sec1_point(false);
                let bytes = point.as_bytes();
                Params::Ec {
                    x: b64::encode(&bytes[1..33]),
                    y: b64::encode(&bytes[33..65]),
                }
            }
        }
    }

    /// Reads a JWK (a JSON object). Private key parameters are rejected.
    pub fn from_jwk(json: &str) -> Result<Self, JoseError> {
        let map = json::parse_object(json.as_bytes(), Kind::Jwk)?;
        Self::from_jwk_map(&map)
    }

    fn from_jwk_map(map: &Map<String, Value>) -> Result<Self, JoseError> {
        let kty = optional_str(map, "kty")?;
        let crv = optional_str(map, "crv")?;
        let use_ = optional_str(map, "use")?;
        let alg = optional_str(map, "alg")?;
        let kid = optional_str(map, "kid")?;

        let is_rsa = match kty {
            None => return Err(JoseError::InvalidKey("kty")),
            Some("RSA") => true,
            Some("EC") => {
                match crv {
                    None => return Err(JoseError::InvalidKey("crv")),
                    Some("P-256") => {}
                    Some(_) => return Err(JoseError::InvalidKey("unsupported key type")),
                }
                false
            }
            Some(_) => return Err(JoseError::InvalidKey("unsupported key type")),
        };

        let private: &[&str] = if is_rsa { &PRIVATE_RSA } else { &["d"] };
        if private.iter().any(|name| map.contains_key(*name)) {
            return Err(JoseError::InvalidKey("private key parameters"));
        }
        if use_.is_some_and(|u| u != "sig") {
            return Err(JoseError::InvalidKey("use"));
        }
        if let Some(alg) = alg {
            let alg: Algorithm = alg.parse()?;
            if (alg == Algorithm::Rs256) != is_rsa {
                return Err(JoseError::InvalidKey("alg"));
            }
        }
        let kid = kid
            .map(|kid| Kid::try_new(kid.to_owned()).map_err(|_| JoseError::InvalidKey("kid")))
            .transpose()?;

        let inner = if is_rsa {
            VerifyingInner::Rsa(rsa_from_params(map)?)
        } else {
            VerifyingInner::Ec(ec_from_params(map)?)
        };
        Ok(Self { inner, kid })
    }

    /// Writes the key as a JWK (a JSON object string).
    pub fn to_jwk(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// The RFC 7638 thumbprint (SHA-256, base64url without padding, 43 characters).
    pub fn thumbprint(&self) -> String {
        let input = match self.params() {
            Params::Rsa { n, e } => format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#),
            Params::Ec { x, y } => format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#),
        };
        b64::encode(Sha256::digest(input.as_bytes()))
    }
}

impl SigningKey {
    /// Sets the key ID to the RFC 7638 thumbprint of the public key.
    pub fn with_thumbprint_kid(self) -> Self {
        match Kid::try_new(self.verifying_key().thumbprint()) {
            Ok(kid) => self.with_kid(kid),
            // A thumbprint is 43 characters of the base64url alphabet, always a valid kid.
            Err(_) => self,
        }
    }
}

/// A member that must be a string when present.
fn optional_str<'a>(
    map: &'a Map<String, Value>,
    name: &'static str,
) -> Result<Option<&'a str>, JoseError> {
    match map.get(name) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(JoseError::InvalidKey(name)),
    }
}

/// Decodes a base64url member. A missing or non-string member is `missing`.
fn member_bytes(
    map: &Map<String, Value>,
    name: &str,
    missing: &'static str,
) -> Result<Vec<u8>, JoseError> {
    let Some(Value::String(s)) = map.get(name) else {
        return Err(JoseError::InvalidKey(missing));
    };
    b64::decode(s).ok_or(JoseError::InvalidKey("base64url"))
}

fn rsa_from_params(map: &Map<String, Value>) -> Result<rsa::PublicKey, JoseError> {
    let n = member_bytes(map, "n", "rsa n")?;
    let e = member_bytes(map, "e", "rsa e")?;
    if n.first().is_none_or(|b| *b == 0) {
        return Err(JoseError::InvalidKey("rsa n"));
    }
    if e.first().is_none_or(|b| *b == 0) {
        return Err(JoseError::InvalidKey("rsa e"));
    }
    let n = BoxedUint::from_be_slice_vartime(&n);
    let e = BoxedUint::from_be_slice_vartime(&e);
    check_rsa_modulus(&n)?;
    check_rsa_exponent(&e)?;
    rsa::PublicKey::new(n, e).map_err(|_| JoseError::InvalidKey("rsa n"))
}

fn ec_from_params(map: &Map<String, Value>) -> Result<p256::ecdsa::VerifyingKey, JoseError> {
    let x = member_bytes(map, "x", "ec point")?;
    let y = member_bytes(map, "y", "ec point")?;
    if x.len() != 32 || y.len() != 32 {
        return Err(JoseError::InvalidKey("ec point"));
    }
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| JoseError::InvalidKey("ec point"))
}

impl Serialize for VerifyingKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        let params = self.params();
        map.serialize_entry(
            "kty",
            if matches!(params, Params::Rsa { .. }) {
                "RSA"
            } else {
                "EC"
            },
        )?;
        if let Some(kid) = &self.kid {
            map.serialize_entry("kid", kid.as_inner())?;
        }
        map.serialize_entry("use", "sig")?;
        map.serialize_entry("alg", self.algorithm().as_str())?;
        match &params {
            Params::Rsa { n, e } => {
                map.serialize_entry("n", n)?;
                map.serialize_entry("e", e)?;
            }
            Params::Ec { x, y } => {
                map.serialize_entry("crv", "P-256")?;
                map.serialize_entry("x", x)?;
                map.serialize_entry("y", y)?;
            }
        }
        map.end()
    }
}

/// A set of public keys (RFC 7517 §5).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JwkSet {
    keys: Vec<VerifyingKey>,
}

impl JwkSet {
    /// Creates a set. Two keys with the same kid are `InvalidKey("duplicate kid")`.
    /// Keys without a kid may appear any number of times.
    pub fn new(keys: Vec<VerifyingKey>) -> Result<Self, JoseError> {
        let mut seen = HashSet::new();
        for kid in keys.iter().filter_map(VerifyingKey::kid) {
            if !seen.insert(kid.as_inner()) {
                return Err(JoseError::InvalidKey("duplicate kid"));
            }
        }
        Ok(Self { keys })
    }

    /// The keys, in order.
    pub fn keys(&self) -> &[VerifyingKey] {
        &self.keys
    }

    /// The key with this kid.
    pub fn find(&self, kid: &Kid) -> Option<&VerifyingKey> {
        self.keys.iter().find(|k| k.kid() == Some(kid))
    }

    /// Reads a JWK Set (`{"keys":[...]}`). Keys of unsupported kinds are skipped.
    pub fn from_json(json: &str) -> Result<Self, JoseError> {
        let map = json::parse_object(json.as_bytes(), Kind::Jwks)?;
        let Some(Value::Array(items)) = map.get("keys") else {
            return Err(JoseError::Malformed("jwks: keys"));
        };
        let mut keys = Vec::new();
        for item in items {
            let Value::Object(item) = item else {
                return Err(JoseError::Malformed("jwks: keys"));
            };
            if let Some(key) = Self::read_member(item)? {
                keys.push(key);
            }
        }
        Self::new(keys)
    }

    /// `None` means the member is skipped.
    fn read_member(item: &Map<String, Value>) -> Result<Option<VerifyingKey>, JoseError> {
        let Some(kty) = optional_str(item, "kty")? else {
            return Err(JoseError::InvalidKey("kty"));
        };
        if kty != "RSA" && kty != "EC" {
            return Ok(None);
        }
        let crv = optional_str(item, "crv")?;
        let use_ = optional_str(item, "use")?;
        let alg = optional_str(item, "alg")?;
        if kty == "EC" && crv.is_some_and(|c| c != "P-256") {
            return Ok(None);
        }
        if use_.is_some_and(|u| u != "sig") {
            return Ok(None);
        }
        if alg.is_some_and(|a| a.parse::<Algorithm>().is_err()) {
            return Ok(None);
        }
        VerifyingKey::from_jwk_map(item).map(Some)
    }

    /// Writes `{"keys":[<JWK>, ...]}`.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

impl Serialize for JwkSet {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry("keys", &self.keys)?;
        map.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RSA_PUB: &str = include_str!("../tests/fixtures/rsa2048.pub.pem");
    const ES_PUB: &str = include_str!("../tests/fixtures/es256.pub.pem");

    fn rsa() -> VerifyingKey {
        VerifyingKey::from_spki_pem(RSA_PUB).unwrap()
    }

    fn ec() -> VerifyingKey {
        VerifyingKey::from_spki_pem(ES_PUB).unwrap()
    }

    fn kid(s: &str) -> Kid {
        Kid::try_new(s.to_owned()).unwrap()
    }

    /// The JWK of `key` with `edit` applied to its members.
    fn jwk_with(key: &VerifyingKey, edit: impl FnOnce(&mut Map<String, Value>)) -> String {
        let mut value: Map<String, Value> = serde_json::from_str(&key.to_jwk()).unwrap();
        edit(&mut value);
        serde_json::to_string(&value).unwrap()
    }

    fn set_member(name: &'static str, value: Value) -> impl FnOnce(&mut Map<String, Value>) {
        move |m| {
            m.insert(name.to_owned(), value);
        }
    }

    fn from_jwk_err(json: &str) -> JoseError {
        VerifyingKey::from_jwk(json).unwrap_err()
    }

    #[test]
    fn output_format_and_order() {
        let key = rsa().with_kid(kid("k1"));
        let jwk = key.to_jwk();
        assert!(jwk.starts_with(r#"{"kty":"RSA","kid":"k1","use":"sig","alg":"RS256","n":""#));
        assert!(jwk.contains(r#"","e":"AQAB"}"#));
        let jwk = ec().to_jwk();
        assert!(jwk.starts_with(r#"{"kty":"EC","use":"sig","alg":"ES256","crv":"P-256","x":""#));
        assert!(jwk.contains(r#"","y":""#));
        let value: Value = serde_json::from_str(&jwk).unwrap();
        assert_eq!(value["x"].as_str().unwrap().len(), 43);
        assert_eq!(value["y"].as_str().unwrap().len(), 43);
        assert!(!jwk.contains("kid"));
    }

    #[test]
    fn round_trip() {
        for key in [
            rsa(),
            ec(),
            rsa().with_kid(kid("a")),
            ec().with_kid(kid("b")),
        ] {
            assert_eq!(VerifyingKey::from_jwk(&key.to_jwk()).unwrap(), key);
        }
    }

    #[test]
    fn ec_coordinates_are_padded_to_32_bytes() {
        // The x coordinate of this key starts with a 0x00 byte; it must stay 32 bytes.
        let key = VerifyingKey::from_spki_pem(include_str!("../tests/fixtures/es256-zero.pub.pem"))
            .unwrap();
        let value: Value = serde_json::from_str(&key.to_jwk()).unwrap();
        let x = b64::decode(value["x"].as_str().unwrap()).unwrap();
        assert_eq!(x.len(), 32);
        assert_eq!(x[0], 0);
        assert_eq!(b64::decode(value["y"].as_str().unwrap()).unwrap().len(), 32);
        assert_eq!(VerifyingKey::from_jwk(&key.to_jwk()).unwrap(), key);
    }

    #[test]
    fn serialize_matches_to_jwk() {
        let key = ec().with_kid(kid("k"));
        assert_eq!(serde_json::to_string(&key).unwrap(), key.to_jwk());
    }

    #[test]
    fn thumbprint_is_43_chars_and_ignores_kid() {
        for key in [rsa(), ec()] {
            let t = key.thumbprint();
            assert_eq!(t.len(), 43);
            assert_eq!(key.clone().with_kid(kid("x")).thumbprint(), t);
        }
        assert_ne!(rsa().thumbprint(), ec().thumbprint());
    }

    #[test]
    fn with_thumbprint_kid_sets_kid() {
        let key = SigningKey::from_pkcs8_pem(&ddd_toolkit::secret::Secret::new(
            include_str!("../tests/fixtures/es256.pem").to_owned(),
        ))
        .unwrap()
        .with_thumbprint_kid();
        let thumbprint = key.verifying_key().thumbprint();
        assert_eq!(key.kid().unwrap().as_inner(), &thumbprint);
        assert_eq!(key.verifying_key().kid().unwrap().as_inner(), &thumbprint);
    }

    #[test]
    fn ignores_unknown_members() {
        let json = jwk_with(&rsa(), |m| {
            m.insert("key_ops".into(), serde_json::json!(["verify"]));
            m.insert("x5t".into(), serde_json::json!("abc"));
            m.insert("x5c".into(), serde_json::json!([1]));
        });
        assert_eq!(VerifyingKey::from_jwk(&json).unwrap(), rsa());
    }

    #[test]
    fn alg_and_use_are_optional() {
        let json = jwk_with(&ec(), |m| {
            m.remove("alg");
            m.remove("use");
        });
        assert_eq!(
            VerifyingKey::from_jwk(&json).unwrap().algorithm(),
            Algorithm::Es256
        );
    }

    #[test]
    fn rejects_malformed_json() {
        assert_eq!(from_jwk_err("{"), JoseError::Malformed("jwk: syntax"));
        assert_eq!(
            from_jwk_err("[]"),
            JoseError::Malformed("jwk: not an object")
        );
        assert_eq!(
            from_jwk_err(r#"{"kty":"EC","kty":"EC"}"#),
            JoseError::Malformed("jwk: duplicate key")
        );
    }

    #[test]
    fn rejects_non_string_members() {
        for name in ["kty", "crv", "use", "alg", "kid"] {
            let json = jwk_with(&ec(), set_member(name, Value::from(1)));
            assert_eq!(from_jwk_err(&json), JoseError::InvalidKey(name), "{name}");
        }
    }

    #[test]
    fn rejects_bad_kty_and_crv() {
        let missing = jwk_with(&ec(), |m| {
            m.remove("kty");
        });
        assert_eq!(from_jwk_err(&missing), JoseError::InvalidKey("kty"));
        let oct = jwk_with(&ec(), set_member("kty", "oct".into()));
        assert_eq!(
            from_jwk_err(&oct),
            JoseError::InvalidKey("unsupported key type")
        );
        let no_crv = jwk_with(&ec(), |m| {
            m.remove("crv");
        });
        assert_eq!(from_jwk_err(&no_crv), JoseError::InvalidKey("crv"));
        let p384 = jwk_with(&ec(), set_member("crv", "P-384".into()));
        assert_eq!(
            from_jwk_err(&p384),
            JoseError::InvalidKey("unsupported key type")
        );
    }

    #[test]
    fn rejects_private_key_parameters() {
        for name in ["d", "p", "q", "dp", "dq", "qi", "oth"] {
            let json = jwk_with(&rsa(), set_member(name, "AQAB".into()));
            assert_eq!(
                from_jwk_err(&json),
                JoseError::InvalidKey("private key parameters")
            );
        }
        let json = jwk_with(&ec(), set_member("d", "AQAB".into()));
        assert_eq!(
            from_jwk_err(&json),
            JoseError::InvalidKey("private key parameters")
        );
    }

    #[test]
    fn rejects_bad_use_and_alg() {
        let json = jwk_with(&ec(), set_member("use", "enc".into()));
        assert_eq!(from_jwk_err(&json), JoseError::InvalidKey("use"));
        let json = jwk_with(&ec(), set_member("alg", "RS256".into()));
        assert_eq!(from_jwk_err(&json), JoseError::InvalidKey("alg"));
        let json = jwk_with(&rsa(), set_member("alg", "ES256".into()));
        assert_eq!(from_jwk_err(&json), JoseError::InvalidKey("alg"));
        for alg in ["none", "HS256", "rs256"] {
            let json = jwk_with(&rsa(), set_member("alg", alg.into()));
            assert_eq!(
                from_jwk_err(&json),
                JoseError::UnsupportedAlgorithm,
                "{alg}"
            );
        }
    }

    #[test]
    fn rejects_bad_kid() {
        for kid in ["", "a b", &"a".repeat(257)] {
            let json = jwk_with(&ec(), set_member("kid", kid.into()));
            assert_eq!(from_jwk_err(&json), JoseError::InvalidKey("kid"));
        }
    }

    #[test]
    fn rejects_bad_rsa_parameters() {
        let n = |v: &str| jwk_with(&rsa(), set_member("n", v.into()));
        let e = |v: &str| jwk_with(&rsa(), set_member("e", v.into()));
        assert_eq!(from_jwk_err(&n("")), JoseError::InvalidKey("rsa n"));
        assert_eq!(from_jwk_err(&n("AAEB")), JoseError::InvalidKey("rsa n"));
        assert_eq!(from_jwk_err(&e("")), JoseError::InvalidKey("rsa e"));
        assert_eq!(from_jwk_err(&e("AAEAAQ")), JoseError::InvalidKey("rsa e"));
        assert_eq!(from_jwk_err(&n("*")), JoseError::InvalidKey("base64url"));
        assert_eq!(
            from_jwk_err(&n("AQAB=")),
            JoseError::InvalidKey("base64url")
        );
        // Modulus size: 1 byte, and 513 bytes.
        assert_eq!(
            from_jwk_err(&n("AQ")),
            JoseError::InvalidKey("rsa modulus size")
        );
        let big = b64::encode([0xFFu8; 513]);
        assert_eq!(
            from_jwk_err(&n(&big)),
            JoseError::InvalidKey("rsa modulus size")
        );
        // Exponent: 1, 2, 4, and 2^33.
        for bad in ["AQ", "Ag", "BA", "AgAAAAA"] {
            assert_eq!(
                from_jwk_err(&e(bad)),
                JoseError::InvalidKey("rsa e"),
                "{bad}"
            );
        }
        // Even modulus of a valid size is rejected by the rsa crate.
        let even = b64::encode(
            [0xFFu8; 256]
                .iter()
                .take(255)
                .chain([0xFE].iter())
                .copied()
                .collect::<Vec<_>>(),
        );
        assert_eq!(from_jwk_err(&n(&even)), JoseError::InvalidKey("rsa n"));
        let missing = jwk_with(&rsa(), |m| {
            m.remove("n");
        });
        assert_eq!(from_jwk_err(&missing), JoseError::InvalidKey("rsa n"));
    }

    #[test]
    fn rejects_bad_ec_points() {
        let x = |v: &str| jwk_with(&ec(), set_member("x", v.into()));
        let y = |v: &str| jwk_with(&ec(), set_member("y", v.into()));
        assert_eq!(from_jwk_err(&x("AQAB")), JoseError::InvalidKey("ec point"));
        assert_eq!(from_jwk_err(&y("")), JoseError::InvalidKey("ec point"));
        let thirty_three = b64::encode([1u8; 33]);
        assert_eq!(
            from_jwk_err(&x(&thirty_three)),
            JoseError::InvalidKey("ec point")
        );
        // 32-byte coordinates that are not on the curve.
        let off_curve = b64::encode([1u8; 32]);
        assert_eq!(
            from_jwk_err(&x(&off_curve)),
            JoseError::InvalidKey("ec point")
        );
        let missing = jwk_with(&ec(), |m| {
            m.remove("y");
        });
        assert_eq!(from_jwk_err(&missing), JoseError::InvalidKey("ec point"));
        assert_eq!(from_jwk_err(&x("*")), JoseError::InvalidKey("base64url"));
    }

    #[test]
    fn set_new_rejects_duplicate_kid() {
        let a = rsa().with_kid(kid("k"));
        let b = ec().with_kid(kid("k"));
        assert_eq!(
            JwkSet::new(vec![a.clone(), b]).unwrap_err(),
            JoseError::InvalidKey("duplicate kid")
        );
        // Several keys without a kid are fine.
        let set = JwkSet::new(vec![rsa(), rsa(), a.clone()]).unwrap();
        assert_eq!(set.keys().len(), 3);
        assert_eq!(set.find(&kid("k")), Some(&a));
        assert_eq!(set.find(&kid("other")), None);
        assert!(JwkSet::default().keys().is_empty());
    }

    #[test]
    fn set_round_trip_and_order() {
        let set = JwkSet::new(vec![
            ec().with_kid(kid("b")),
            rsa().with_kid(kid("a")),
            rsa(),
        ])
        .unwrap();
        let json = set.to_json();
        assert!(json.starts_with(r#"{"keys":[{"kty":"EC","kid":"b""#));
        assert_eq!(JwkSet::from_json(&json).unwrap(), set);
        assert_eq!(serde_json::to_string(&set).unwrap(), json);
        assert_eq!(JwkSet::default().to_json(), r#"{"keys":[]}"#);
    }

    fn set_json(members: &[String]) -> String {
        format!(r#"{{"keys":[{}]}}"#, members.join(","))
    }

    #[test]
    fn set_rejects_malformed_documents() {
        for (json, reason) in [
            ("{", "jwks: syntax"),
            ("[]", "jwks: not an object"),
            (r#"{"keys":[],"keys":[]}"#, "jwks: duplicate key"),
            ("{}", "jwks: keys"),
            (r#"{"keys":{}}"#, "jwks: keys"),
            (r#"{"keys":[1]}"#, "jwks: keys"),
            (r#"{"keys":[[]]}"#, "jwks: keys"),
        ] {
            assert_eq!(
                JwkSet::from_json(json).unwrap_err(),
                JoseError::Malformed(reason),
                "{json}"
            );
        }
        // A duplicate key nested inside a member.
        assert_eq!(
            JwkSet::from_json(r#"{"keys":[{"kty":"EC","x":"a","x":"b"}]}"#).unwrap_err(),
            JoseError::Malformed("jwks: duplicate key")
        );
    }

    #[test]
    fn set_member_rules() {
        let skipped = [
            r#"{"kty":"oct","k":"AA"}"#.to_owned(),
            jwk_with(&ec(), set_member("crv", "P-384".into())),
            jwk_with(&ec(), set_member("use", "enc".into())),
            jwk_with(&rsa(), set_member("use", "enc".into())),
            jwk_with(&rsa(), set_member("alg", "RS512".into())),
            jwk_with(&rsa(), set_member("alg", "none".into())),
        ];
        assert!(
            JwkSet::from_json(&set_json(&skipped))
                .unwrap()
                .keys()
                .is_empty()
        );
        assert!(
            JwkSet::from_json(r#"{"keys":[]}"#)
                .unwrap()
                .keys()
                .is_empty()
        );

        let failing = [
            (r#"{"x":1}"#.to_owned(), "kty"),
            (r#"{"kty":1}"#.to_owned(), "kty"),
            (jwk_with(&ec(), set_member("crv", 1.into())), "crv"),
            (jwk_with(&ec(), set_member("use", 1.into())), "use"),
            (jwk_with(&ec(), set_member("alg", 1.into())), "alg"),
            (jwk_with(&rsa(), set_member("alg", "ES256".into())), "alg"),
            (jwk_with(&ec(), set_member("alg", "RS256".into())), "alg"),
            (
                jwk_with(&rsa(), set_member("d", "AQAB".into())),
                "private key parameters",
            ),
            (jwk_with(&ec(), set_member("kid", "a b".into())), "kid"),
            (
                jwk_with(&ec(), |m| {
                    m.remove("crv");
                }),
                "crv",
            ),
        ];
        for (member, name) in failing {
            assert_eq!(
                JwkSet::from_json(&set_json(std::slice::from_ref(&member))).unwrap_err(),
                JoseError::InvalidKey(name),
                "{member}"
            );
        }
        // Good keys survive next to skipped ones.
        let mixed = set_json(&[skipped[0].clone(), rsa().with_kid(kid("a")).to_jwk()]);
        assert_eq!(JwkSet::from_json(&mixed).unwrap().keys().len(), 1);
    }

    #[test]
    fn set_rejects_duplicate_kid_in_json() {
        let json = set_json(&[
            rsa().with_kid(kid("k")).to_jwk(),
            ec().with_kid(kid("k")).to_jwk(),
        ]);
        assert_eq!(
            JwkSet::from_json(&json).unwrap_err(),
            JoseError::InvalidKey("duplicate kid")
        );
    }
}
