use crate::{error::DomainError, time::DurationMillis};

fn validate_timestamp(millis: &i64) -> Result<(), DomainError> {
    if *millis < 0 {
        return Err(DomainError::OutOfRange);
    }

    Ok(())
}

/// **English:**<br>
/// Milliseconds since the Unix epoch (1970-01-01 00:00:00 UTC).
///
/// The supported range is `0..=i64::MAX`; pre-epoch values are rejected with
/// [`DomainError::OutOfRange`]. Serde uses an integer in milliseconds and validates
/// deserialized input. Values in seconds must be converted to milliseconds first.
///
/// **日本語:**<br>
/// Unix epoch（1970-01-01 00:00:00 UTC）からの経過ミリ秒を表します。
///
/// 許容範囲は `0..=i64::MAX` です。epochより前の値は
/// [`DomainError::OutOfRange`] で拒否します。Serdeはミリ秒単位の整数を用い、
/// デシリアライズ時に検証します。秒単位の値は事前にミリ秒へ変換してください。
///
/// # Example / 使用例
/// ```rust
/// use komainu_domain::time::{DurationMillis, Timestamp};
///
/// let epoch = Timestamp::try_new(0).unwrap();
/// let one_second = DurationMillis::try_new(1_000).unwrap();
/// assert_eq!(*epoch.checked_add(one_second).unwrap().as_inner(), 1_000);
/// ```
#[derive(ddd_toolkit::ValueObject, Copy, PartialOrd, Ord)]
#[value_object(validate = validate_timestamp, error = DomainError, serde)]
pub struct Timestamp(i64);

impl Timestamp {
    /// **English:**<br>
    /// Adds a positive duration in milliseconds.
    /// Returns [`DomainError::ArithmeticOverflow`] if the sum exceeds [`i64::MAX`].
    ///
    /// **日本語:**<br>
    /// 正のミリ秒単位の期間を加算します。
    /// 合計が [`i64::MAX`] を超える場合は [`DomainError::ArithmeticOverflow`] を返します。
    pub fn checked_add(&self, duration: DurationMillis) -> Result<Self, DomainError> {
        let millis = self
            .into_inner()
            .checked_add(duration.into_inner() as i64)
            .ok_or(DomainError::ArithmeticOverflow)?;
        let timestamp = Timestamp::try_new(millis)?;
        Ok(timestamp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construction_accepts_bounds_and_rejects_negative_values() {
        for millis in [0, i64::MAX] {
            assert_eq!(*Timestamp::try_new(millis).unwrap().as_inner(), millis);
        }
        for millis in [i64::MIN, -1] {
            assert_eq!(
                Timestamp::try_new(millis).unwrap_err(),
                DomainError::OutOfRange
            );
        }
    }

    #[test]
    fn checked_add_accepts_exact_upper_bound() {
        for (start, duration) in [(0, i64::MAX as u64), (i64::MAX - 1, 1)] {
            let result = Timestamp::try_new(start)
                .unwrap()
                .checked_add(DurationMillis::try_new(duration).unwrap())
                .unwrap();
            assert_eq!(*result.as_inner(), i64::MAX);
        }
    }

    #[test]
    fn checked_add_rejects_overflow() {
        for (start, duration) in [(i64::MAX, 1), (1, i64::MAX as u64)] {
            assert_eq!(
                Timestamp::try_new(start)
                    .unwrap()
                    .checked_add(DurationMillis::try_new(duration).unwrap())
                    .unwrap_err(),
                DomainError::ArithmeticOverflow
            );
        }
    }

    #[test]
    fn serde_round_trip_preserves_bounds() {
        for millis in [0, i64::MAX] {
            let timestamp = Timestamp::try_new(millis).unwrap();
            let json = serde_json::to_string(&timestamp).unwrap();
            assert_eq!(json, millis.to_string());
            assert_eq!(serde_json::from_str::<Timestamp>(&json).unwrap(), timestamp);
        }
    }

    #[test]
    fn deserialize_rejects_out_of_range_values() {
        for json in [
            i64::MIN.to_string(),
            "-1".to_owned(),
            (i64::MAX as u64 + 1).to_string(),
        ] {
            assert!(serde_json::from_str::<Timestamp>(&json).is_err(), "{json}");
        }
    }
}
