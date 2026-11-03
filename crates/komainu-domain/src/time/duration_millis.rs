use crate::{error::DomainError, shared::validate_less_than_or_equal};

fn validate_duration_millis(millis: &u64) -> Result<(), DomainError> {
    if *millis == 0 {
        return Err(DomainError::InvalidDuration);
    }
    validate_less_than_or_equal(*millis, i64::MAX as u64)
}

/// **English:**<br>
/// A positive duration in milliseconds, bounded by [`i64::MAX`].
///
/// [`Self::try_new`] returns [`DomainError::InvalidDuration`] for zero and
/// [`DomainError::OutOfRange`] for values greater than [`i64::MAX`].
/// Serde represents the duration as an integer and validates deserialized input.
///
/// **日本語:**<br>
/// [`i64::MAX`] 以下の正のミリ秒単位の期間を表します。
///
/// [`Self::try_new`] はゼロに対して [`DomainError::InvalidDuration`]、
/// [`i64::MAX`] を超える値に対して [`DomainError::OutOfRange`] を返します。
/// Serde は期間を整数として表現し、デシリアライズ時に入力を検証します。
///
/// # Example / 使用例
///
/// ```rust
/// use komainu_domain::time::DurationMillis;
///
/// let duration = DurationMillis::try_new(1_000).unwrap();
/// assert_eq!(*duration.as_inner(), 1_000);
/// ```
#[derive(ddd_toolkit::ValueObject, Copy, PartialOrd, Ord)]
#[value_object(validate = validate_duration_millis, error = DomainError, serde)]
pub struct DurationMillis(u64);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_new_rejects_zero() {
        assert_eq!(
            DurationMillis::try_new(0).unwrap_err(),
            DomainError::InvalidDuration
        );
    }

    #[test]
    fn try_new_accepts_bounds() {
        for millis in [1, i64::MAX as u64] {
            assert_eq!(*DurationMillis::try_new(millis).unwrap().as_inner(), millis);
        }
    }

    #[test]
    fn try_new_rejects_values_above_maximum() {
        for millis in [i64::MAX as u64 + 1, u64::MAX] {
            assert_eq!(
                DurationMillis::try_new(millis).unwrap_err(),
                DomainError::OutOfRange
            );
        }
    }

    #[test]
    fn serde_round_trip_preserves_bounds() {
        for millis in [1, i64::MAX as u64] {
            let duration = DurationMillis::try_new(millis).unwrap();
            let json = serde_json::to_string(&duration).unwrap();
            assert_eq!(json, millis.to_string());
            assert_eq!(
                serde_json::from_str::<DurationMillis>(&json).unwrap(),
                duration
            );
        }
    }

    #[test]
    fn deserialize_rejects_invalid_durations() {
        for millis in [0, i64::MAX as u64 + 1, u64::MAX] {
            assert!(serde_json::from_str::<DurationMillis>(&millis.to_string()).is_err());
        }
    }
}
