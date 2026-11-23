#![no_main]

use komainu_jose::VerifyingKey;
use komainu_jose::jwt::{self, Validation};
use libfuzzer_sys::fuzz_target;
use time::OffsetDateTime;

const EC_PUB: &str = include_str!("../../tests/fixtures/es256.pub.pem");

fuzz_target!(|data: &[u8]| {
    let Ok(token) = std::str::from_utf8(data) else {
        return;
    };
    let keys = [VerifyingKey::from_spki_pem(EC_PUB).unwrap()];
    let validation = Validation::new("https://as.example", "api");
    let _ = jwt::decode::<serde_json::Value>(token, &keys, &validation, OffsetDateTime::UNIX_EPOCH);
});
