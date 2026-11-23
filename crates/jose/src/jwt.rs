//! JSON Web Token (RFC 7519): claims, validation, `encode` and `decode`.

use std::time::Duration;

use serde::de::{DeserializeOwned, IgnoredAny};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};
use time::OffsetDateTime;

use crate::error::JoseError;
use crate::json::{self, Kind};
use crate::jws::{self, DEFAULT_MAX_TOKEN_LEN, Header, SignOptions, VerifyOptions};
use crate::key::{SigningKey, VerifyingKey};

/// The default clock skew allowance: 60 seconds.
pub const DEFAULT_LEEWAY: Duration = Duration::from_secs(60);
/// The largest clock skew allowance: 3600 seconds.
pub const MAX_LEEWAY: Duration = Duration::from_secs(3600);

const REGISTERED: [&str; 7] = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"];

/// The `aud` claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Audience {
    /// A JSON string.
    One(String),
    /// A JSON array of strings.
    Many(Vec<String>),
}

impl Audience {
    /// Whether `aud` is the audience or one of the audiences.
    pub fn contains(&self, aud: &str) -> bool {
        match self {
            Self::One(one) => one == aud,
            Self::Many(many) => many.iter().any(|a| a == aud),
        }
    }
}

/// The registered claims. Times have second precision (sub-second parts are dropped on encode).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegisteredClaims {
    /// `iss`.
    pub iss: Option<String>,
    /// `sub`.
    pub sub: Option<String>,
    /// `aud`.
    pub aud: Option<Audience>,
    /// `exp`.
    pub exp: Option<OffsetDateTime>,
    /// `nbf`.
    pub nbf: Option<OffsetDateTime>,
    /// `iat`.
    pub iat: Option<OffsetDateTime>,
    /// `jti`.
    pub jti: Option<String>,
}

/// No custom claims. Serializes as `{}`; deserializing ignores anything.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoCustomClaims;

impl Serialize for NoCustomClaims {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_map(Some(0))?.end()
    }
}

impl<'de> Deserialize<'de> for NoCustomClaims {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        IgnoredAny::deserialize(deserializer)?;
        Ok(Self)
    }
}

/// Registered claims and custom claims.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Claims<T = NoCustomClaims> {
    /// The registered claims.
    pub registered: RegisteredClaims,
    /// The custom claims.
    pub custom: T,
}

/// What [`decode`] checks.
#[derive(Debug, Clone)]
pub struct Validation {
    issuer: String,
    audience: String,
    leeway: Duration,
    typ: Option<String>,
    max_token_len: usize,
}

impl Validation {
    /// Requires `iss` and `aud` to match. Leeway is [`DEFAULT_LEEWAY`], no `typ` is required and
    /// the token length limit is [`DEFAULT_MAX_TOKEN_LEN`].
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            leeway: DEFAULT_LEEWAY,
            typ: None,
            max_token_len: DEFAULT_MAX_TOKEN_LEN,
        }
    }

    /// Sets the clock skew allowance. Sub-second parts are dropped; more than [`MAX_LEEWAY`]
    /// is clamped to it.
    pub fn leeway(mut self, leeway: Duration) -> Self {
        self.leeway = Duration::from_secs(leeway.as_secs()).min(MAX_LEEWAY);
        self
    }

    /// Requires the header `typ` (see [`VerifyOptions::require_typ`]).
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

/// A verified token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded<T> {
    /// The JWS header.
    pub header: Header,
    /// The claims.
    pub claims: Claims<T>,
}

/// Serializes `claims` and signs them as a JWS Compact string.
///
/// Required claims are not enforced here; [`decode`] checks them.
pub fn encode<T: Serialize>(
    claims: &Claims<T>,
    key: &SigningKey,
    options: &SignOptions,
) -> Result<String, JoseError> {
    let custom = match serde_json::to_value(&claims.custom)
        .map_err(|_| JoseError::Encoding("custom claims"))?
    {
        Value::Object(map) => map,
        _ => return Err(JoseError::Encoding("custom claims must be an object")),
    };
    if let Some(name) = REGISTERED.iter().find(|name| custom.contains_key(**name)) {
        return Err(JoseError::DuplicateClaim(name));
    }
    let json = serde_json::to_vec(&ClaimsOut {
        registered: &claims.registered,
        custom: &custom,
    })
    .map_err(|_| JoseError::Encoding("claims"))?;
    jws::sign(&json, key, options)
}

struct ClaimsOut<'a> {
    registered: &'a RegisteredClaims,
    custom: &'a Map<String, Value>,
}

struct AudienceOut<'a>(&'a Audience);

impl Serialize for AudienceOut<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            Audience::One(one) => serializer.serialize_str(one),
            Audience::Many(many) => many.serialize(serializer),
        }
    }
}

impl Serialize for ClaimsOut<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let r = self.registered;
        let mut map = serializer.serialize_map(None)?;
        if let Some(iss) = &r.iss {
            map.serialize_entry("iss", iss)?;
        }
        if let Some(sub) = &r.sub {
            map.serialize_entry("sub", sub)?;
        }
        if let Some(aud) = &r.aud {
            map.serialize_entry("aud", &AudienceOut(aud))?;
        }
        for (name, time) in [("exp", r.exp), ("nbf", r.nbf), ("iat", r.iat)] {
            if let Some(time) = time {
                map.serialize_entry(name, &time.unix_timestamp())?;
            }
        }
        if let Some(jti) = &r.jti {
            map.serialize_entry("jti", jti)?;
        }
        for (name, value) in self.custom {
            map.serialize_entry(name, value)?;
        }
        map.end()
    }
}

fn string_claim(
    map: &mut Map<String, Value>,
    name: &'static str,
) -> Result<Option<String>, JoseError> {
    match map.remove(name) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(JoseError::InvalidClaim(name)),
    }
}

fn time_claim(
    map: &mut Map<String, Value>,
    name: &'static str,
) -> Result<Option<OffsetDateTime>, JoseError> {
    match map.remove(name) {
        None => Ok(None),
        Some(Value::Number(n)) => n
            .as_i64()
            .and_then(|s| OffsetDateTime::from_unix_timestamp(s).ok())
            .map(Some)
            .ok_or(JoseError::InvalidClaim(name)),
        Some(_) => Err(JoseError::InvalidClaim(name)),
    }
}

fn audience_claim(map: &mut Map<String, Value>) -> Result<Option<Audience>, JoseError> {
    match map.remove("aud") {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(Audience::One(s))),
        Some(Value::Array(items)) => items
            .into_iter()
            .map(|item| match item {
                Value::String(s) => Ok(s),
                _ => Err(JoseError::InvalidClaim("aud")),
            })
            .collect::<Result<Vec<_>, _>>()
            .map(|v| Some(Audience::Many(v))),
        Some(_) => Err(JoseError::InvalidClaim("aud")),
    }
}

/// Verifies a JWT and checks its claims against `validation` at `now`.
pub fn decode<T: DeserializeOwned>(
    token: &str,
    keys: &[VerifyingKey],
    validation: &Validation,
    now: OffsetDateTime,
) -> Result<Decoded<T>, JoseError> {
    let mut options = VerifyOptions::new().max_token_len(validation.max_token_len);
    if let Some(typ) = &validation.typ {
        options = options.require_typ(typ.clone());
    }
    let verified = jws::verify(token, keys, &options)?;
    if verified.header.cty().is_some() {
        return Err(JoseError::UnsupportedHeader("cty"));
    }
    let mut map = json::parse_object(&verified.payload, Kind::Claims)?;

    let registered = RegisteredClaims {
        iss: string_claim(&mut map, "iss")?,
        sub: string_claim(&mut map, "sub")?,
        aud: audience_claim(&mut map)?,
        exp: time_claim(&mut map, "exp")?,
        nbf: time_claim(&mut map, "nbf")?,
        iat: time_claim(&mut map, "iat")?,
        jti: string_claim(&mut map, "jti")?,
    };
    let custom =
        T::deserialize(Value::Object(map)).map_err(|_| JoseError::InvalidClaim("custom claims"))?;

    let now_s = now.unix_timestamp();
    let leeway_s = i64::try_from(validation.leeway.as_secs()).unwrap_or(i64::MAX);

    match &registered.iss {
        None => return Err(JoseError::MissingClaim("iss")),
        Some(iss) if *iss != validation.issuer => return Err(JoseError::InvalidIssuer),
        Some(_) => {}
    }
    match &registered.aud {
        None => return Err(JoseError::MissingClaim("aud")),
        Some(aud) if !aud.contains(&validation.audience) => return Err(JoseError::InvalidAudience),
        Some(_) => {}
    }
    let Some(exp) = registered.exp else {
        return Err(JoseError::MissingClaim("exp"));
    };
    if now_s >= exp.unix_timestamp().saturating_add(leeway_s) {
        return Err(JoseError::Expired);
    }
    if let Some(nbf) = registered.nbf
        && now_s < nbf.unix_timestamp().saturating_sub(leeway_s)
    {
        return Err(JoseError::NotYetValid);
    }
    if let Some(iat) = registered.iat
        && iat.unix_timestamp() > now_s.saturating_add(leeway_s)
    {
        return Err(JoseError::InvalidClaim("iat"));
    }
    Ok(Decoded {
        header: verified.header,
        claims: Claims { registered, custom },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::b64;
    use crate::error::JoseError as E;
    use ddd_toolkit::secret::Secret;
    use serde_json::json;

    const ES_PEM: &str = include_str!("../tests/fixtures/es256.pem");
    const T: i64 = 1_700_000_000;

    fn key() -> SigningKey {
        SigningKey::from_pkcs8_pem(&Secret::new(ES_PEM.to_owned())).unwrap()
    }

    fn at(secs: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(secs).unwrap()
    }

    fn registered() -> RegisteredClaims {
        RegisteredClaims {
            iss: Some("https://as.example".into()),
            sub: Some("user".into()),
            aud: Some(Audience::One("api".into())),
            exp: Some(at(T)),
            nbf: Some(at(T - 100)),
            iat: Some(at(T - 200)),
            jti: Some("id1".into()),
        }
    }

    fn validation() -> Validation {
        Validation::new("https://as.example", "api")
    }

    /// A token with a hand-written payload.
    fn token(payload: &str) -> String {
        jws::sign(payload.as_bytes(), &key(), &SignOptions::new()).unwrap()
    }

    fn decode_now(token: &str, now: i64) -> Result<Decoded<NoCustomClaims>, JoseError> {
        decode(token, &[key().verifying_key()], &validation(), at(now))
    }

    fn payload_of(token: &str) -> String {
        String::from_utf8(b64::decode(token.split('.').nth(1).unwrap()).unwrap()).unwrap()
    }

    #[test]
    fn encode_output_order() {
        let mut registered = registered();
        registered.aud = Some(Audience::Many(vec!["a".into(), "b".into()]));
        let claims = Claims {
            registered,
            custom: json!({"zeta": 1, "alpha": [true]}),
        };
        let t = encode(&claims, &key(), &SignOptions::new()).unwrap();
        assert_eq!(
            payload_of(&t),
            format!(
                r#"{{"iss":"https://as.example","sub":"user","aud":["a","b"],"exp":{},"nbf":{},"iat":{},"jti":"id1","alpha":[true],"zeta":1}}"#,
                T,
                T - 100,
                T - 200
            )
        );
        let one = Claims {
            registered: registered_with_one_aud(),
            custom: NoCustomClaims,
        };
        let t = encode(&one, &key(), &SignOptions::new()).unwrap();
        assert!(payload_of(&t).contains(r#""aud":"api""#));
        let empty = Claims::<NoCustomClaims>::default();
        assert_eq!(
            payload_of(&encode(&empty, &key(), &SignOptions::new()).unwrap()),
            "{}"
        );
    }

    fn registered_with_one_aud() -> RegisteredClaims {
        registered()
    }

    #[test]
    fn encode_drops_sub_second_precision() {
        let mut registered = registered();
        registered.exp = Some(at(T) + time::Duration::milliseconds(999));
        let t = encode(
            &Claims {
                registered,
                custom: NoCustomClaims,
            },
            &key(),
            &SignOptions::new(),
        )
        .unwrap();
        assert!(payload_of(&t).contains(&format!(r#""exp":{T},"#)));
    }

    #[test]
    fn encode_rejects_registered_names_in_custom() {
        for name in REGISTERED {
            let claims = Claims {
                registered: RegisteredClaims::default(),
                custom: json!({ name: 1 }),
            };
            assert_eq!(
                encode(&claims, &key(), &SignOptions::new()).unwrap_err(),
                E::DuplicateClaim(name)
            );
        }
    }

    #[test]
    fn encode_rejects_non_object_custom() {
        for custom in [json!(1), json!([1]), json!("x"), json!(null)] {
            let claims = Claims {
                registered: RegisteredClaims::default(),
                custom,
            };
            assert_eq!(
                encode(&claims, &key(), &SignOptions::new()).unwrap_err(),
                E::Encoding("custom claims must be an object")
            );
        }
    }

    #[test]
    fn encode_reports_serialization_failure() {
        struct Fails;
        impl Serialize for Fails {
            fn serialize<S: Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("no"))
            }
        }
        let claims = Claims {
            registered: RegisteredClaims::default(),
            custom: Fails,
        };
        assert_eq!(
            encode(&claims, &key(), &SignOptions::new()).unwrap_err(),
            E::Encoding("custom claims")
        );
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Custom {
        scope: String,
        n: Vec<u32>,
        opt: Option<bool>,
    }

    #[test]
    fn custom_claims_round_trip() {
        let custom = Custom {
            scope: "a b".into(),
            n: vec![1, 2],
            opt: None,
        };
        let claims = Claims {
            registered: registered(),
            custom,
        };
        let t = encode(&claims, &key(), &SignOptions::new().typ("at+jwt")).unwrap();
        let decoded: Decoded<Custom> = decode(
            &t,
            &[key().verifying_key()],
            &validation().require_typ("at+jwt"),
            at(T - 10),
        )
        .unwrap();
        assert_eq!(decoded.claims, claims);
        assert_eq!(decoded.header.typ(), Some("at+jwt"));
    }

    #[test]
    fn custom_claims_type_mismatch() {
        let t = token(&format!(
            r#"{{"iss":"https://as.example","aud":"api","exp":{T},"scope":1,"n":[],"opt":null}}"#
        ));
        let err =
            decode::<Custom>(&t, &[key().verifying_key()], &validation(), at(T - 1)).unwrap_err();
        assert_eq!(err, E::InvalidClaim("custom claims"));
        // Registered names never reach T.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Strict {}
        let t = token(&format!(
            r#"{{"iss":"https://as.example","aud":"api","exp":{T}}}"#
        ));
        assert!(decode::<Strict>(&t, &[key().verifying_key()], &validation(), at(T - 1)).is_ok());
    }

    #[test]
    fn decode_returns_registered_claims() {
        let claims = Claims {
            registered: registered(),
            custom: NoCustomClaims,
        };
        let t = encode(&claims, &key(), &SignOptions::new()).unwrap();
        assert_eq!(decode_now(&t, T - 10).unwrap().claims, claims);
    }

    #[test]
    fn missing_claims_in_order() {
        let now = T - 1;
        let exp = format!(r#""exp":{T}"#);
        let cases = [
            ("{}".to_owned(), "iss"),
            (format!(r#"{{"aud":"api",{exp}}}"#), "iss"),
            (format!(r#"{{"iss":"https://as.example",{exp}}}"#), "aud"),
            (
                r#"{"iss":"https://as.example","aud":"api"}"#.to_owned(),
                "exp",
            ),
        ];
        for (payload, name) in cases {
            assert_eq!(
                decode_now(&token(&payload), now).unwrap_err(),
                E::MissingClaim(name),
                "{payload}"
            );
        }
    }

    #[test]
    fn issuer_and_audience_checks() {
        let good = |iss: &str, aud: &str| format!(r#"{{"iss":{iss},"aud":{aud},"exp":{T}}}"#);
        let now = T - 1;
        assert!(decode_now(&token(&good(r#""https://as.example""#, r#""api""#)), now).is_ok());
        assert!(
            decode_now(
                &token(&good(r#""https://as.example""#, r#"["x","api"]"#)),
                now
            )
            .is_ok()
        );
        for iss in [
            r#""https://as.example/""#,
            r#""HTTPS://AS.EXAMPLE""#,
            r#""""#,
        ] {
            assert_eq!(
                decode_now(&token(&good(iss, r#""api""#)), now).unwrap_err(),
                E::InvalidIssuer,
                "{iss}"
            );
        }
        for aud in [r#""other""#, r#"["x","y"]"#, "[]", r#""API""#] {
            assert_eq!(
                decode_now(&token(&good(r#""https://as.example""#, aud)), now).unwrap_err(),
                E::InvalidAudience,
                "{aud}"
            );
        }
    }

    #[test]
    fn issuer_is_checked_before_audience_before_time() {
        let t = token(r#"{"iss":"x","aud":"y","exp":1}"#);
        assert_eq!(decode_now(&t, T).unwrap_err(), E::InvalidIssuer);
        let t = token(r#"{"iss":"https://as.example","aud":"y","exp":1}"#);
        assert_eq!(decode_now(&t, T).unwrap_err(), E::InvalidAudience);
        let t = token(r#"{"iss":"https://as.example","aud":"api","exp":1}"#);
        assert_eq!(decode_now(&t, T).unwrap_err(), E::Expired);
    }

    #[test]
    fn claim_type_errors() {
        let base = |extra: &str| {
            format!(r#"{{"iss":"https://as.example","aud":"api","exp":{T},{extra}}}"#)
        };
        for (extra, name) in [
            (r#""sub":1"#, "sub"),
            (r#""jti":[]"#, "jti"),
            (r#""nbf":"1""#, "nbf"),
            (r#""nbf":1.5"#, "nbf"),
            (r#""nbf":1e3"#, "nbf"),
            (r#""nbf":1.0"#, "nbf"),
            (r#""nbf":null"#, "nbf"),
            (r#""iat":true"#, "iat"),
            (r#""iat":9223372036854775807"#, "iat"),
            (r#""iat":18446744073709551615"#, "iat"),
            (r#""nbf":-99999999999999999"#, "nbf"),
        ] {
            assert_eq!(
                decode_now(&token(&base(extra)), T - 1).unwrap_err(),
                E::InvalidClaim(name),
                "{extra}"
            );
        }
        for (payload, name) in [
            (r#"{"iss":1,"aud":"api","exp":1}"#, "iss"),
            (r#"{"iss":"i","aud":1,"exp":1}"#, "aud"),
            (r#"{"iss":"i","aud":["a",1],"exp":1}"#, "aud"),
            (r#"{"iss":"i","aud":null,"exp":1}"#, "aud"),
            (r#"{"iss":"i","aud":"a","exp":"1"}"#, "exp"),
            (r#"{"iss":"i","aud":"a","exp":1.5}"#, "exp"),
        ] {
            assert_eq!(
                decode_now(&token(payload), T).unwrap_err(),
                E::InvalidClaim(name),
                "{payload}"
            );
        }
    }

    #[test]
    fn claims_json_errors() {
        for (payload, reason) in [
            ("{", "claims: syntax"),
            ("[]", "claims: not an object"),
            (r#"{"a":1,"a":2}"#, "claims: duplicate key"),
            (r#"{"iss":"a","iss":"a"}"#, "claims: duplicate key"),
            (r#"{"x":{"y":1,"y":2}}"#, "claims: duplicate key"),
            ("", "claims: syntax"),
        ] {
            assert_eq!(
                decode_now(&token(payload), T).unwrap_err(),
                E::Malformed(reason),
                "{payload}"
            );
        }
        let t = jws::sign(&[0xFF], &key(), &SignOptions::new()).unwrap();
        assert_eq!(
            decode_now(&t, T).unwrap_err(),
            E::Malformed("claims: utf-8")
        );
    }

    #[test]
    fn exp_leeway_boundary() {
        let t = token(&format!(
            r#"{{"iss":"https://as.example","aud":"api","exp":{T}}}"#
        ));
        assert!(decode_now(&t, T).is_ok());
        assert!(decode_now(&t, T + 59).is_ok());
        assert_eq!(decode_now(&t, T + 60).unwrap_err(), E::Expired);
        assert_eq!(decode_now(&t, T + 61).unwrap_err(), E::Expired);
    }

    #[test]
    fn nbf_leeway_boundary() {
        let t = token(&format!(
            r#"{{"iss":"https://as.example","aud":"api","exp":{},"nbf":{T}}}"#,
            T + 1000
        ));
        assert_eq!(decode_now(&t, T - 61).unwrap_err(), E::NotYetValid);
        assert!(decode_now(&t, T - 60).is_ok());
        assert!(decode_now(&t, T).is_ok());
    }

    #[test]
    fn iat_in_the_future() {
        let t = token(&format!(
            r#"{{"iss":"https://as.example","aud":"api","exp":{},"iat":{T}}}"#,
            T + 1000
        ));
        assert!(decode_now(&t, T - 60).is_ok());
        assert_eq!(decode_now(&t, T - 61).unwrap_err(), E::InvalidClaim("iat"));
    }

    #[test]
    fn leeway_options() {
        let t = token(&format!(
            r#"{{"iss":"https://as.example","aud":"api","exp":{T}}}"#
        ));
        let keys = [key().verifying_key()];
        let dec = |v: Validation, now: i64| decode::<NoCustomClaims>(&t, &keys, &v, at(now));
        assert_eq!(
            dec(validation().leeway(Duration::ZERO), T).unwrap_err(),
            E::Expired
        );
        assert!(dec(validation().leeway(Duration::ZERO), T - 1).is_ok());
        // Sub-second parts are dropped.
        assert_eq!(
            dec(validation().leeway(Duration::from_millis(999)), T).unwrap_err(),
            E::Expired
        );
        // Clamped to 3600 seconds.
        let big = validation().leeway(Duration::from_secs(3601));
        assert!(dec(big.clone(), T + 3599).is_ok());
        assert_eq!(dec(big, T + 3600).unwrap_err(), E::Expired);
        let huge = validation().leeway(Duration::MAX);
        assert_eq!(dec(huge, T + 3600).unwrap_err(), E::Expired);
    }

    #[test]
    fn time_arithmetic_saturates() {
        // exp at the representable maximum plus leeway must not overflow.
        let max = 253_402_300_799_i64;
        let t = token(&format!(
            r#"{{"iss":"https://as.example","aud":"api","exp":{max}}}"#
        ));
        assert!(decode_now(&t, T).is_ok());
        assert!(decode_now(&t, max).is_ok());
        // nbf and iat at the representable minimum must not underflow.
        let min = -62_135_596_800_i64;
        let t = token(&format!(
            r#"{{"iss":"https://as.example","aud":"api","exp":{},"nbf":{min},"iat":{min}}}"#,
            T + 100
        ));
        assert!(decode_now(&t, T).is_ok());
        // exp at the minimum is long expired.
        let t = token(&format!(
            r#"{{"iss":"https://as.example","aud":"api","exp":{min}}}"#
        ));
        assert_eq!(decode_now(&t, T).unwrap_err(), E::Expired);
    }

    #[test]
    fn typ_is_required_when_set() {
        let t = token(&format!(
            r#"{{"iss":"https://as.example","aud":"api","exp":{T}}}"#
        ));
        let keys = [key().verifying_key()];
        assert_eq!(
            decode::<NoCustomClaims>(&t, &keys, &validation().require_typ("at+jwt"), at(T - 1))
                .unwrap_err(),
            E::InvalidTyp
        );
    }

    #[test]
    fn cty_is_rejected() {
        use crate::b64::encode;
        let payload = format!(r#"{{"iss":"https://as.example","aud":"api","exp":{T}}}"#);
        let input = format!(
            "{}.{}",
            encode(r#"{"alg":"ES256","cty":"JWT"}"#),
            encode(&payload)
        );
        let sig = key().sign_raw(input.as_bytes()).unwrap();
        let t = format!("{input}.{}", encode(sig));
        assert_eq!(
            decode_now(&t, T - 1).unwrap_err(),
            E::UnsupportedHeader("cty")
        );
    }

    #[test]
    fn token_length_limit() {
        let t = token(&format!(
            r#"{{"iss":"https://as.example","aud":"api","exp":{T}}}"#
        ));
        let keys = [key().verifying_key()];
        let v = validation().max_token_len(t.len() - 1);
        assert_eq!(
            decode::<NoCustomClaims>(&t, &keys, &v, at(T - 1)).unwrap_err(),
            E::Malformed("token too long")
        );
        let v = validation().max_token_len(t.len());
        assert!(decode::<NoCustomClaims>(&t, &keys, &v, at(T - 1)).is_ok());
    }

    #[test]
    fn signature_errors_pass_through() {
        let other = SigningKey::from_pkcs8_pem(&Secret::new(
            include_str!("../tests/fixtures/es256b.pem").to_owned(),
        ))
        .unwrap();
        let t = jws::sign(b"{}", &other, &SignOptions::new()).unwrap();
        assert_eq!(decode_now(&t, T).unwrap_err(), E::InvalidSignature);
        assert_eq!(
            decode("a.b", &[], &validation(), at(T))
                .map(|_: Decoded<NoCustomClaims>| ())
                .unwrap_err(),
            E::Malformed("segments")
        );
    }

    #[test]
    fn audience_contains() {
        assert!(Audience::One("a".into()).contains("a"));
        assert!(!Audience::One("a".into()).contains("b"));
        assert!(Audience::Many(vec!["a".into(), "b".into()]).contains("b"));
        assert!(!Audience::Many(vec![]).contains("a"));
    }
}
