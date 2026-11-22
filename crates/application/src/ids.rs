use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use komainu_domain::{OpaqueToken, Secret};

use crate::port::{Clock, SecureRandom};

/// UUIDv7 from clock.now() (unix millis) and 10 random bytes.
pub fn new_uuid_v7(clock: &dyn Clock, random: &dyn SecureRandom) -> uuid::Uuid {
    // A clock before the epoch cannot be represented; clamp to 0.
    let millis = u64::try_from(clock.now().unix_timestamp_nanos() / 1_000_000).unwrap_or(0);
    let mut bytes = [0u8; 10];
    random.fill_bytes(&mut bytes);
    uuid::Builder::from_unix_timestamp_millis(millis, &bytes).into_uuid()
}

/// 32 random bytes, base64url without padding (43 chars). N-1.
pub fn new_opaque_token(random: &dyn SecureRandom) -> OpaqueToken {
    let mut bytes = [0u8; 32];
    random.fill_bytes(&mut bytes);
    OpaqueToken::try_new(Secret::new(URL_SAFE_NO_PAD.encode(bytes)))
        .expect("43 base64url characters are a valid opaque token")
}
