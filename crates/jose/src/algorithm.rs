//! Signature algorithms.

use core::fmt;
use core::str::FromStr;

use crate::error::JoseError;

/// A supported JWS signature algorithm.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// RSASSA-PKCS1-v1_5 using SHA-256.
    Rs256,
    /// ECDSA using P-256 and SHA-256.
    Es256,
}

impl Algorithm {
    /// The JOSE name: `"RS256"` or `"ES256"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Es256 => "ES256",
        }
    }
}

impl FromStr for Algorithm {
    type Err = JoseError;

    /// Parses a JOSE name. The match is case-sensitive; `"none"` and every other
    /// value is [`JoseError::UnsupportedAlgorithm`].
    fn from_str(s: &str) -> Result<Self, JoseError> {
        match s {
            "RS256" => Ok(Self::Rs256),
            "ES256" => Ok(Self::Es256),
            _ => Err(JoseError::UnsupportedAlgorithm),
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        for alg in [Algorithm::Rs256, Algorithm::Es256] {
            assert_eq!(alg.as_str().parse::<Algorithm>(), Ok(alg));
            assert_eq!(alg.to_string(), alg.as_str());
        }
    }

    #[test]
    fn rejects_everything_else() {
        for s in [
            "none", "None", "rs256", "es256", "HS256", "PS256", "", "RS256 ",
        ] {
            assert_eq!(s.parse::<Algorithm>(), Err(JoseError::UnsupportedAlgorithm));
        }
    }
}
