//! Interoperability with `jsonwebtoken` 12, both directions, RS256 and ES256.

use jsonwebtoken::{Algorithm as JwtAlg, DecodingKey, EncodingKey, Header, Validation};
use komainu_jose::jws::SignOptions;
use komainu_jose::jwt::{self, Audience, Claims, RegisteredClaims};
use komainu_jose::{Secret, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

const RSA_PEM: &str = include_str!("fixtures/rsa2048.pem");
const RSA_PUB_PEM: &str = include_str!("fixtures/rsa2048.pub.pem");
const EC_PEM: &str = include_str!("fixtures/es256.pem");
const EC_PUB_PEM: &str = include_str!("fixtures/es256.pub.pem");

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Wire {
    iss: String,
    aud: String,
    exp: i64,
    scope: String,
}

fn now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

fn validation(alg: JwtAlg) -> Validation {
    let mut v = Validation::new(alg);
    v.set_issuer(&["https://as.example"]);
    v.set_audience(&["api"]);
    v.set_required_spec_claims(&["exp", "iss", "aud"]);
    v
}

fn ours_to_theirs(pem: &str, public_pem: &str, alg: JwtAlg) {
    let key = SigningKey::from_pkcs8_pem(&Secret::new(pem.to_owned())).unwrap();
    let claims = Claims {
        registered: RegisteredClaims {
            iss: Some("https://as.example".into()),
            aud: Some(Audience::One("api".into())),
            exp: Some(OffsetDateTime::now_utc() + time::Duration::hours(1)),
            ..Default::default()
        },
        custom: serde_json::json!({"scope": "read"}),
    };
    let token = jwt::encode(&claims, &key, &SignOptions::new().typ("JWT")).unwrap();
    let decoding = match alg {
        JwtAlg::RS256 => DecodingKey::from_rsa_pem(public_pem.as_bytes()),
        _ => DecodingKey::from_ec_pem(public_pem.as_bytes()),
    }
    .unwrap();
    let data = jsonwebtoken::decode::<Wire>(&token, &decoding, &validation(alg)).unwrap();
    assert_eq!(data.claims.scope, "read");
    assert_eq!(data.claims.iss, "https://as.example");
}

fn theirs_to_ours(pem: &str, public_pem: &str, alg: JwtAlg) {
    let encoding = match alg {
        JwtAlg::RS256 => EncodingKey::from_rsa_pem(pem.as_bytes()),
        _ => EncodingKey::from_ec_pem(pem.as_bytes()),
    }
    .unwrap();
    let claims = Wire {
        iss: "https://as.example".into(),
        aud: "api".into(),
        exp: now() + 3600,
        scope: "write".into(),
    };
    let token = jsonwebtoken::encode(&Header::new(alg), &claims, &encoding).unwrap();
    let keys = [VerifyingKey::from_spki_pem(public_pem).unwrap()];
    let validation = jwt::Validation::new("https://as.example", "api");
    let decoded: jwt::Decoded<serde_json::Value> =
        jwt::decode(&token, &keys, &validation, OffsetDateTime::now_utc()).unwrap();
    assert_eq!(decoded.claims.custom["scope"], "write");
    assert_eq!(decoded.header.typ(), Some("JWT"));
}

#[test]
fn rs256_ours_to_theirs() {
    ours_to_theirs(RSA_PEM, RSA_PUB_PEM, JwtAlg::RS256);
}

#[test]
fn rs256_theirs_to_ours() {
    theirs_to_ours(RSA_PEM, RSA_PUB_PEM, JwtAlg::RS256);
}

#[test]
fn es256_ours_to_theirs() {
    ours_to_theirs(EC_PEM, EC_PUB_PEM, JwtAlg::ES256);
}

#[test]
fn es256_theirs_to_ours() {
    theirs_to_ours(EC_PEM, EC_PUB_PEM, JwtAlg::ES256);
}
