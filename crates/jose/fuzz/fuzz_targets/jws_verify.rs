#![no_main]

use komainu_jose::jws::{self, VerifyOptions};
use komainu_jose::VerifyingKey;
use libfuzzer_sys::fuzz_target;

const EC_PUB: &str = include_str!("../../tests/fixtures/es256.pub.pem");
const RSA_PUB: &str = include_str!("../../tests/fixtures/rsa2048.pub.pem");

fuzz_target!(|data: &[u8]| {
    let Ok(token) = std::str::from_utf8(data) else {
        return;
    };
    let keys = [
        VerifyingKey::from_spki_pem(EC_PUB).unwrap(),
        VerifyingKey::from_spki_pem(RSA_PUB).unwrap(),
    ];
    let _ = jws::verify(token, &keys, &VerifyOptions::new());
    let _ = jws::verify(token, &keys, &VerifyOptions::new().require_typ("at+jwt"));
});
