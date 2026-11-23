//! base64url without padding; only canonical encodings are accepted.

use base64::Engine;
use base64::alphabet::URL_SAFE;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};

const ENGINE: GeneralPurpose = GeneralPurpose::new(
    &URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::RequireNone)
        .with_decode_allow_trailing_bits(false),
);

pub(crate) fn encode(input: impl AsRef<[u8]>) -> String {
    ENGINE.encode(input)
}

/// Decodes `input`; `None` for padding, non-URL-safe characters or non-canonical trailing bits.
pub(crate) fn decode(input: &str) -> Option<Vec<u8>> {
    ENGINE.decode(input).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_without_padding() {
        assert_eq!(encode(b"f"), "Zg");
        assert_eq!(encode(b"fo"), "Zm8");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(encode(b""), "");
        for input in [&b""[..], b"f", b"fo", b"foo", &[0xfb, 0xff, 0xfe]] {
            assert_eq!(decode(&encode(input)).as_deref(), Some(input));
        }
        assert_eq!(encode([0xfb, 0xff, 0xfe]), "-__-");
    }

    #[test]
    fn rejects_padding() {
        assert_eq!(decode("Zg=="), None);
        assert_eq!(decode("Zm8="), None);
    }

    #[test]
    fn rejects_non_canonical_trailing_bits() {
        // "Zg" is canonical for "f"; "Zh" decodes to the same byte with non-zero trailing bits.
        assert_eq!(decode("Zg").as_deref(), Some(&b"f"[..]));
        assert_eq!(decode("Zh"), None);
        assert_eq!(decode("Zm9"), None);
    }

    #[test]
    fn rejects_standard_alphabet_and_garbage() {
        assert_eq!(decode("+/+/"), None);
        assert_eq!(decode("Zm 9v"), None);
        assert_eq!(decode("Zm9v\n"), None);
        assert_eq!(decode("Z"), None);
    }
}
