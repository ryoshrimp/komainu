#![no_main]

use komainu_jose::{JwkSet, VerifyingKey};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(json) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(key) = VerifyingKey::from_jwk(json) {
        let _ = VerifyingKey::from_jwk(&key.to_jwk()).unwrap();
    }
    let _ = JwkSet::from_json(json);
});
