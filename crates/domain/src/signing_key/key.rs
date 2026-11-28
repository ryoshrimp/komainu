use std::fmt;
use std::str::FromStr;

use ddd_toolkit::ValueObject;
use time::{Duration, OffsetDateTime};

use crate::error::DomainError;

/// The JWS algorithm of an AS signing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SigningAlgorithm {
    Es256,
    Rs256,
}

impl SigningAlgorithm {
    /// "ES256" / "RS256"
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::Rs256 => "RS256",
        }
    }
}

impl FromStr for SigningAlgorithm {
    type Err = DomainError;
    fn from_str(s: &str) -> Result<Self, DomainError> {
        match s {
            "ES256" => Ok(Self::Es256),
            "RS256" => Ok(Self::Rs256),
            _ => Err(DomainError::invalid("signing_algorithm", "unknown value")),
        }
    }
}

/// kid: RFC 7638 thumbprint. 1..=64 chars of `[A-Za-z0-9_-]`.
#[derive(ValueObject, PartialOrd, Ord)]
#[value_object(validate = validate_signing_key_id, error = DomainError)]
pub struct SigningKeyId(String);

fn validate_signing_key_id(value: &SigningKeyId) -> Result<(), DomainError> {
    let s = &value.0;
    if s.is_empty() || s.len() > 64 {
        return Err(DomainError::invalid(
            "signing_key_id",
            "length must be 1 to 64 bytes",
        ));
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(DomainError::invalid("signing_key_id", "invalid character"));
    }
    Ok(())
}

/// Sealed (encrypted) private key bytes. 1..=16384 bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedPrivateKey(Vec<u8>);

impl SealedPrivateKey {
    pub fn new(bytes: Vec<u8>) -> Result<Self, DomainError> {
        if bytes.is_empty() || bytes.len() > 16384 {
            return Err(DomainError::invalid(
                "sealed_private_key",
                "length must be 1 to 16384 bytes",
            ));
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SealedPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SealedPrivateKey(<{} bytes>)", self.0.len())
    }
}

/// Public key as a JWK JSON object string. 1..=8192 bytes, starts with '{'.
///
/// Only the length and the first character are checked here; the application
/// guarantees that it is a valid JWK.
#[derive(ValueObject)]
#[value_object(validate = validate_public_jwk, error = DomainError)]
pub struct PublicJwk(String);

fn validate_public_jwk(value: &PublicJwk) -> Result<(), DomainError> {
    let s = &value.0;
    if s.is_empty() || s.len() > 8192 {
        return Err(DomainError::invalid(
            "public_jwk",
            "length must be 1 to 8192 bytes",
        ));
    }
    if !s.starts_with('{') {
        return Err(DomainError::invalid("public_jwk", "must be a JSON object"));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStatus {
    Pending,
    Active,
    Retired,
    Expired,
}

/// Persistence form of [`ServerSigningKey`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSigningKeyRecord {
    pub kid: SigningKeyId,
    pub algorithm: SigningAlgorithm,
    pub sealed_private_key: SealedPrivateKey,
    pub public_jwk: PublicJwk,
    pub created_at: OffsetDateTime,
    pub activates_at: OffsetDateTime,
    pub retires_at: OffsetDateTime,
    pub deletes_at: OffsetDateTime,
}

/// A signing key of the authorization server. Its status follows from the clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSigningKey {
    record: ServerSigningKeyRecord,
}

impl ServerSigningKey {
    /// Fails unless `created_at <= activates_at <= retires_at <= deletes_at`.
    pub fn new(record: ServerSigningKeyRecord) -> Result<Self, DomainError> {
        if !(record.created_at <= record.activates_at
            && record.activates_at <= record.retires_at
            && record.retires_at <= record.deletes_at)
        {
            return Err(DomainError::invalid(
                "server_signing_key",
                "times must satisfy created_at <= activates_at <= retires_at <= deletes_at",
            ));
        }
        Ok(Self { record })
    }

    /// Restores from persistence without validation.
    pub fn from_record(record: ServerSigningKeyRecord) -> Self {
        Self { record }
    }

    pub fn to_record(&self) -> ServerSigningKeyRecord {
        self.record.clone()
    }

    pub fn kid(&self) -> &SigningKeyId {
        &self.record.kid
    }

    pub fn algorithm(&self) -> SigningAlgorithm {
        self.record.algorithm
    }

    pub fn sealed_private_key(&self) -> &SealedPrivateKey {
        &self.record.sealed_private_key
    }

    pub fn public_jwk(&self) -> &PublicJwk {
        &self.record.public_jwk
    }

    pub fn created_at(&self) -> OffsetDateTime {
        self.record.created_at
    }

    pub fn activates_at(&self) -> OffsetDateTime {
        self.record.activates_at
    }

    pub fn retires_at(&self) -> OffsetDateTime {
        self.record.retires_at
    }

    pub fn deletes_at(&self) -> OffsetDateTime {
        self.record.deletes_at
    }

    /// Status at `now`: Pending if `now < activates_at`; Active if
    /// `activates_at <= now < retires_at`; Retired if `retires_at <= now < deletes_at`;
    /// Expired if `deletes_at <= now`.
    pub fn status_at(&self, now: OffsetDateTime) -> KeyStatus {
        if now < self.record.activates_at {
            KeyStatus::Pending
        } else if now < self.record.retires_at {
            KeyStatus::Active
        } else if now < self.record.deletes_at {
            KeyStatus::Retired
        } else {
            KeyStatus::Expired
        }
    }

    /// Whether the key belongs in the JWKS (Pending, Active and Retired).
    pub fn is_published_at(&self, now: OffsetDateTime) -> bool {
        self.status_at(now) != KeyStatus::Expired
    }

    /// Retires the key now: `retires_at = min(retires_at, now)` and
    /// `deletes_at = min(deletes_at, updated retires_at + overlap)`.
    /// A Pending key is covered too; its `activates_at` is moved to `now` to keep the
    /// time order. Does nothing (returns `false`) for Retired / Expired keys.
    pub fn retire(&mut self, now: OffsetDateTime, overlap: Duration) -> bool {
        match self.status_at(now) {
            KeyStatus::Retired | KeyStatus::Expired => false,
            status => {
                if status == KeyStatus::Pending {
                    self.record.activates_at = now;
                }
                self.record.retires_at = self.record.retires_at.min(now);
                self.record.deletes_at =
                    self.record.deletes_at.min(self.record.retires_at + overlap);
                true
            }
        }
    }

    /// Activates a Pending key now. Does nothing (returns `false`) otherwise.
    pub fn activate_now(&mut self, now: OffsetDateTime) -> bool {
        if self.status_at(now) != KeyStatus::Pending {
            return false;
        }
        self.record.activates_at = now;
        true
    }
}

/// The key to sign with: the Active key of `algorithm` with the latest `activates_at`
/// (ties broken by the greatest kid).
pub fn current_key(
    keys: &[ServerSigningKey],
    algorithm: SigningAlgorithm,
    now: OffsetDateTime,
) -> Option<&ServerSigningKey> {
    keys.iter()
        .filter(|k| k.algorithm() == algorithm && k.status_at(now) == KeyStatus::Active)
        .max_by(|a, b| {
            a.activates_at()
                .cmp(&b.activates_at())
                .then_with(|| a.kid().cmp(b.kid()))
        })
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    pub fn t(secs: i64) -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH + Duration::seconds(secs)
    }

    /// Key with activates_at = `a`, retires_at = `r`, deletes_at = `d` (seconds).
    pub fn key(kid: &str, alg: SigningAlgorithm, a: i64, r: i64, d: i64) -> ServerSigningKey {
        ServerSigningKey::new(ServerSigningKeyRecord {
            kid: SigningKeyId::try_new(kid.to_owned()).unwrap(),
            algorithm: alg,
            sealed_private_key: SealedPrivateKey::new(vec![1, 2, 3]).unwrap(),
            public_jwk: PublicJwk::try_new("{}".to_owned()).unwrap(),
            created_at: t(0),
            activates_at: t(a),
            retires_at: t(r),
            deletes_at: t(d),
        })
        .unwrap()
    }

    const E: SigningAlgorithm = SigningAlgorithm::Es256;

    #[test]
    fn algorithm_parse() {
        assert_eq!("ES256".parse(), Ok(SigningAlgorithm::Es256));
        assert_eq!("RS256".parse(), Ok(SigningAlgorithm::Rs256));
        assert!("es256".parse::<SigningAlgorithm>().is_err());
        assert!("HS256".parse::<SigningAlgorithm>().is_err());
        assert_eq!(SigningAlgorithm::Rs256.as_str(), "RS256");
    }

    #[test]
    fn value_object_rules() {
        assert!(SigningKeyId::try_new("a-B_9".to_owned()).is_ok());
        assert!(SigningKeyId::try_new(String::new()).is_err());
        assert!(SigningKeyId::try_new("a".repeat(65)).is_err());
        assert!(SigningKeyId::try_new("a.b".to_owned()).is_err());
        assert!(SealedPrivateKey::new(vec![]).is_err());
        assert!(SealedPrivateKey::new(vec![0; 16385]).is_err());
        assert!(SealedPrivateKey::new(vec![0; 16384]).is_ok());
        assert!(PublicJwk::try_new("[]".to_owned()).is_err());
        assert!(PublicJwk::try_new(String::new()).is_err());
        assert!(PublicJwk::try_new(format!("{{{}", "a".repeat(8192))).is_err());
    }

    #[test]
    fn sealed_debug_hides_bytes() {
        let s = SealedPrivateKey::new(vec![0xAB, 0xCD, 0xEF]).unwrap();
        assert_eq!(format!("{s:?}"), "SealedPrivateKey(<3 bytes>)");
    }

    #[test]
    fn new_rejects_disordered_times() {
        let mut r = key("k", E, 10, 20, 30).to_record();
        assert!(ServerSigningKey::new(r.clone()).is_ok());
        r.retires_at = t(5);
        assert!(ServerSigningKey::new(r.clone()).is_err());
        r.retires_at = t(20);
        r.deletes_at = t(19);
        assert!(ServerSigningKey::new(r.clone()).is_err());
        r.deletes_at = t(30);
        r.created_at = t(11);
        assert!(ServerSigningKey::new(r).is_err());
    }

    #[test]
    fn status_boundaries() {
        let k = key("k", E, 10, 20, 30);
        assert_eq!(k.status_at(t(9)), KeyStatus::Pending);
        assert_eq!(k.status_at(t(10)), KeyStatus::Active);
        assert_eq!(k.status_at(t(19)), KeyStatus::Active);
        assert_eq!(k.status_at(t(20)), KeyStatus::Retired);
        assert_eq!(k.status_at(t(29)), KeyStatus::Retired);
        assert_eq!(k.status_at(t(30)), KeyStatus::Expired);
        assert!(k.is_published_at(t(29)));
        assert!(!k.is_published_at(t(30)));
        assert_eq!(ServerSigningKey::from_record(k.to_record()), k);
    }

    #[test]
    fn current_key_selection() {
        let keys = [
            key("a", E, 0, 100, 200),
            key("b", E, 50, 150, 250),
            key("c", SigningAlgorithm::Rs256, 90, 150, 250),
            key("d", E, 120, 300, 400),
        ];
        assert_eq!(
            current_key(&keys, E, t(60))
                .unwrap()
                .kid()
                .as_inner()
                .as_str(),
            "b"
        );
        assert_eq!(
            current_key(&keys, E, t(10))
                .unwrap()
                .kid()
                .as_inner()
                .as_str(),
            "a"
        );
        assert_eq!(
            current_key(&keys, SigningAlgorithm::Rs256, t(60)).map(|k| k.kid().as_inner().as_str()),
            None
        );
        assert_eq!(
            current_key(&keys, E, t(120))
                .unwrap()
                .kid()
                .as_inner()
                .as_str(),
            "d"
        );
        assert!(current_key(&keys, E, t(500)).is_none());
    }

    #[test]
    fn activate_now_rules() {
        let mut k = key("k", E, 10, 20, 30);
        assert!(k.activate_now(t(5)));
        assert_eq!(k.activates_at(), t(5));
        assert_eq!(k.status_at(t(5)), KeyStatus::Active);
        assert!(!k.activate_now(t(6)));
    }

    #[test]
    fn retire_rules() {
        let o = Duration::seconds(7);
        let mut k = key("k", E, 10, 100, 107);
        assert!(k.retire(t(50), o));
        assert_eq!((k.retires_at(), k.deletes_at()), (t(50), t(57)));
        assert_eq!(k.status_at(t(50)), KeyStatus::Retired);
        let before = k.clone();
        assert!(!k.retire(t(51), o));
        assert_eq!(k, before);

        let mut p = key("p", E, 100, 200, 207);
        assert!(p.retire(t(50), o));
        assert_eq!(p.activates_at(), t(50));
        assert_eq!(p.retires_at(), t(50));
        assert_eq!(p.deletes_at(), t(57));

        let mut m = key("m", E, 10, 100, 102);
        assert!(m.retire(t(99), o));
        assert_eq!((m.retires_at(), m.deletes_at()), (t(99), t(102)));

        let mut e = key("e", E, 1, 2, 3);
        assert!(!e.retire(t(10), o));
    }
}
