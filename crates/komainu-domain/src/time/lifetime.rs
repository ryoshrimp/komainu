use crate::{
    error::DomainError,
    time::{DurationMillis, Timestamp},
};

fn validate_lifetime(lifetime: &Lifetime) -> Result<(), DomainError> {
    if lifetime.issued_at() >= lifetime.expires_at() {
        return Err(DomainError::TimeOrder);
    }
    Ok(())
}

/// **English:**<br>
/// A non-empty validity interval `[issued_at, expires_at)`.
///
/// Construction and deserialization reject `issued_at >= expires_at` with
/// [`DomainError::TimeOrder`]. Serde uses an object with `issued_at` and
/// `expires_at` fields containing Unix-epoch milliseconds. [`Self::check`] uses
/// the caller-supplied time; it does not read a system clock.
///
/// **日本語:**<br>
/// 空でない有効期間 `[issued_at, expires_at)` を表します。
///
/// 生成時とデシリアライズ時に `issued_at >= expires_at` を拒否し、
/// [`DomainError::TimeOrder`] を返します。Serdeは `issued_at` と `expires_at` に
/// Unix epochからの経過ミリ秒を格納するオブジェクトを用います。[`Self::check`] は
/// 呼び出し側が渡した時刻を使い、システム時計は参照しません。
///
/// # Example / 使用例
/// ```rust
/// use komainu_domain::{error::DomainError, time::{DurationMillis, Lifetime, Timestamp}};
///
/// let issued_at = Timestamp::try_new(1_000).unwrap();
/// let lifetime = Lifetime::from_duration(issued_at, DurationMillis::try_new(500).unwrap()).unwrap();
/// assert_eq!(*lifetime.issued_at(), issued_at);
/// assert_eq!(*lifetime.expires_at(), Timestamp::try_new(1_500).unwrap());
/// assert_eq!(lifetime.check(Timestamp::try_new(999).unwrap()), Err(DomainError::NotYetValid));
/// assert_eq!(lifetime.check(issued_at), Ok(()));
/// assert_eq!(lifetime.check(*lifetime.expires_at()), Err(DomainError::Expired));
/// ```
#[derive(ddd_toolkit::ValueObject)]
#[value_object(validate = validate_lifetime, error = DomainError, serde)]
pub struct Lifetime {
    issued_at: crate::time::Timestamp,
    expires_at: crate::time::Timestamp,
}

impl Lifetime {
    /// **English:**<br>
    /// Creates an interval starting at `issued_at` with the given positive TTL.
    /// Returns [`DomainError::ArithmeticOverflow`] if the end exceeds [`i64::MAX`].
    ///
    /// **日本語:**<br>
    /// `issued_at` から指定された正のTTLだけ続く有効期間を生成します。
    /// 終了時刻が [`i64::MAX`] を超える場合は [`DomainError::ArithmeticOverflow`] を返します。
    pub fn from_duration(issued_at: Timestamp, ttl: DurationMillis) -> Result<Self, DomainError> {
        let expires_at = issued_at.checked_add(ttl)?;
        Lifetime::try_new(issued_at, expires_at)
    }

    /// **English:**<br>
    /// Accepts `now` inside `[issued_at, expires_at)`.
    /// Returns [`DomainError::NotYetValid`] before the start and
    /// [`DomainError::Expired`] at or after the end.
    ///
    /// **日本語:**<br>
    /// `now` が `[issued_at, expires_at)` 内なら成功します。
    /// 開始前は [`DomainError::NotYetValid`]、終了時刻以降は
    /// [`DomainError::Expired`] を返します。
    pub fn check(&self, now: Timestamp) -> Result<(), DomainError> {
        if now < self.issued_at {
            Err(DomainError::NotYetValid)
        } else if now >= self.expires_at {
            Err(DomainError::Expired)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timestamp(millis: i64) -> Timestamp {
        Timestamp::try_new(millis).unwrap()
    }

    #[test]
    fn construction_rejects_empty_and_reversed_intervals() {
        for end in [9, 10] {
            assert_eq!(
                Lifetime::try_new(timestamp(10), timestamp(end)).unwrap_err(),
                DomainError::TimeOrder
            );
        }
    }

    #[test]
    fn check_uses_a_half_open_interval() {
        let lifetime = Lifetime::try_new(timestamp(10), timestamp(20)).unwrap();
        for (now, expected) in [
            (9, Err(DomainError::NotYetValid)),
            (10, Ok(())),
            (19, Ok(())),
            (20, Err(DomainError::Expired)),
            (21, Err(DomainError::Expired)),
        ] {
            assert_eq!(lifetime.check(timestamp(now)), expected);
        }
    }

    #[test]
    fn from_duration_preserves_start_and_calculates_end() {
        let lifetime =
            Lifetime::from_duration(timestamp(10), DurationMillis::try_new(1).unwrap()).unwrap();
        assert_eq!(*lifetime.issued_at(), timestamp(10));
        assert_eq!(*lifetime.expires_at(), timestamp(11));
    }

    #[test]
    fn from_duration_checks_overflow() {
        let ttl = DurationMillis::try_new(1).unwrap();
        let lifetime = Lifetime::from_duration(timestamp(i64::MAX - 1), ttl).unwrap();
        assert_eq!(*lifetime.expires_at(), timestamp(i64::MAX));
        assert_eq!(
            Lifetime::from_duration(timestamp(i64::MAX), ttl).unwrap_err(),
            DomainError::ArithmeticOverflow
        );
    }

    #[test]
    fn serde_round_trip_preserves_interval() {
        let lifetime = Lifetime::try_new(timestamp(10), timestamp(20)).unwrap();
        let json = serde_json::to_string(&lifetime).unwrap();
        assert_eq!(serde_json::from_str::<Lifetime>(&json).unwrap(), lifetime);
    }

    #[test]
    fn deserialize_rejects_invalid_intervals() {
        for json in [
            r#"{"issued_at":10,"expires_at":10}"#,
            r#"{"issued_at":10,"expires_at":9}"#,
            r#"{"issued_at":-1,"expires_at":10}"#,
            r#"{"issued_at":0,"expires_at":-1}"#,
        ] {
            assert!(serde_json::from_str::<Lifetime>(json).is_err(), "{json}");
        }
    }
}
