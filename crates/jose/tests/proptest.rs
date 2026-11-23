//! N1: arbitrary input never panics; issued claims survive a round trip.

use komainu_jose::jws::{self, SignOptions, VerifyOptions};
use komainu_jose::jwt::{self, Claims, RegisteredClaims, Validation};
use komainu_jose::{JwkSet, Secret, SigningKey, VerifyingKey};
use proptest::prelude::*;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

const EC_PEM: &str = include_str!("fixtures/es256.pem");

fn key() -> SigningKey {
    SigningKey::from_pkcs8_pem(&Secret::new(EC_PEM.to_owned())).unwrap()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Custom {
    name: String,
    numbers: Vec<i64>,
    flag: Option<bool>,
}

proptest! {
    #[test]
    fn verify_never_panics_on_strings(token in any::<String>()) {
        let keys = [key().verifying_key()];
        let _ = jws::verify(&token, &keys, &VerifyOptions::new());
        let _ = jwt::decode::<serde_json::Value>(
            &token, &keys, &Validation::new("i", "a"), OffsetDateTime::UNIX_EPOCH);
    }

    #[test]
    fn verify_never_panics_on_token_shaped_input(
        h in "[A-Za-z0-9_=-]{0,80}", p in "[A-Za-z0-9_=-]{0,80}", s in "[A-Za-z0-9_=-]{0,120}",
    ) {
        let keys = [key().verifying_key()];
        let token = format!("{h}.{p}.{s}");
        let _ = jws::verify(&token, &keys, &VerifyOptions::new());
        let _ = jwt::decode::<serde_json::Value>(
            &token, &keys, &Validation::new("i", "a"), OffsetDateTime::UNIX_EPOCH);
    }

    #[test]
    fn jwk_parsers_never_panic(input in any::<String>(), bytes in any::<Vec<u8>>()) {
        let _ = VerifyingKey::from_jwk(&input);
        let _ = JwkSet::from_json(&input);
        let lossy = String::from_utf8_lossy(&bytes);
        let _ = VerifyingKey::from_jwk(&lossy);
        let _ = JwkSet::from_json(&lossy);
    }

    #[test]
    fn jwk_parsers_never_panic_on_json_shaped_input(
        kty in prop_oneof!["RSA", "EC", "oct", "[a-z]{0,4}"],
        n in "[A-Za-z0-9_-]{0,400}",
        e in "[A-Za-z0-9_-]{0,12}",
    ) {
        let json = format!(r#"{{"kty":"{kty}","n":"{n}","e":"{e}","crv":"P-256","x":"{n}","y":"{e}"}}"#);
        let _ = VerifyingKey::from_jwk(&json);
        let _ = JwkSet::from_json(&format!(r#"{{"keys":[{json}]}}"#));
    }

    #[test]
    fn signed_garbage_payloads_never_panic(payload in any::<Vec<u8>>()) {
        let key = key();
        let token = jws::sign(&payload, &key, &SignOptions::new()).unwrap();
        let _ = jwt::decode::<serde_json::Value>(
            &token, &[key.verifying_key()], &Validation::new("i", "a"), OffsetDateTime::UNIX_EPOCH);
    }

    #[test]
    fn custom_claims_round_trip(
        name in any::<String>(),
        numbers in proptest::collection::vec(any::<i64>(), 0..8),
        flag in proptest::option::of(any::<bool>()),
        exp in 0i64..4_000_000_000,
    ) {
        let key = key();
        let custom = Custom { name, numbers, flag };
        let claims = Claims {
            registered: RegisteredClaims {
                iss: Some("i".into()),
                aud: Some(jwt::Audience::One("a".into())),
                exp: Some(OffsetDateTime::from_unix_timestamp(exp).unwrap()),
                ..Default::default()
            },
            custom,
        };
        let token = jwt::encode(&claims, &key, &SignOptions::new()).unwrap();
        let decoded: jwt::Decoded<Custom> = jwt::decode(
            &token, &[key.verifying_key()], &Validation::new("i", "a"),
            OffsetDateTime::from_unix_timestamp(exp - 1).unwrap(),
        ).unwrap();
        prop_assert_eq!(decoded.claims, claims);
    }
}
