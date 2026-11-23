//! Key IDs.

use core::fmt;

use ddd_toolkit::ValueObject;

use crate::error::JoseError;

/// A key ID: 1 to 256 bytes, each a printable ASCII character other than space
/// (`0x21..=0x7E`). Compared byte for byte, case-sensitively.
#[derive(ValueObject)]
#[value_object(validate = validate_kid, error = JoseError)]
pub struct Kid(String);

fn validate_kid(value: &Kid) -> Result<(), JoseError> {
    let s = &value.0;
    if s.is_empty() || s.len() > 256 {
        return Err(JoseError::InvalidValue {
            field: "kid",
            reason: "length must be 1 to 256",
        });
    }
    if !s.bytes().all(|b| (0x21..=0x7E).contains(&b)) {
        return Err(JoseError::InvalidValue {
            field: "kid",
            reason: "invalid character",
        });
    }
    Ok(())
}

impl fmt::Display for Kid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kid(s: &str) -> Result<Kid, JoseError> {
        Kid::try_new(s.to_owned())
    }

    #[test]
    fn length_boundaries() {
        assert!(kid("").is_err());
        assert!(kid("a").is_ok());
        assert!(kid(&"a".repeat(256)).is_ok());
        assert_eq!(
            kid(&"a".repeat(257)),
            Err(JoseError::InvalidValue {
                field: "kid",
                reason: "length must be 1 to 256"
            })
        );
    }

    #[test]
    fn rejects_space_control_and_non_ascii() {
        for s in ["a b", " a", "a\t", "a\n", "a\u{7f}", "あ", "é"] {
            assert_eq!(
                kid(s),
                Err(JoseError::InvalidValue {
                    field: "kid",
                    reason: "invalid character"
                }),
                "{s:?}"
            );
        }
        assert!(kid("!~").is_ok());
        assert!(kid("bilbo.baggins@hobbiton.example").is_ok());
    }

    #[test]
    fn display_and_comparison() {
        let k = kid("Key-1").unwrap();
        assert_eq!(k.to_string(), "Key-1");
        assert_eq!(k.as_inner(), "Key-1");
        assert_ne!(k, kid("key-1").unwrap());
        assert_eq!(k, kid("Key-1").unwrap());
    }
}
