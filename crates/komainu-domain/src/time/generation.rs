use crate::error::DomainError;

/// **English:**<br>
/// A generation counter in `0..=u32::MAX`, serialized as an integer.
///
/// [`Self::new`] accepts any `u32`, including zero. [`Self::next`] returns a new
/// counter without changing the original; it does not wrap at the upper bound.
///
/// **日本語:**<br>
/// `0..=u32::MAX` の世代カウンターです。整数としてシリアライズします。
///
/// [`Self::new`] はゼロを含むすべての `u32` を受理します。[`Self::next`] は
/// 元の値を変更せずに新しいカウンターを返し、上限でゼロに戻ることはありません。
///
/// # Example / 使用例
/// ```rust
/// use komainu_domain::{error::DomainError, time::Generation};
///
/// let initial = Generation::new(0);
/// assert_eq!(initial.next().unwrap(), Generation::new(1));
/// assert_eq!(*initial.as_inner(), 0);
/// assert_eq!(Generation::new(u32::MAX).next(), Err(DomainError::ArithmeticOverflow));
/// ```
#[derive(ddd_toolkit::ValueObject, Copy, PartialOrd, Ord)]
#[value_object(serde)]
pub struct Generation(u32);

impl Generation {
    /// **English:**<br>
    /// Returns the next generation without changing this counter.
    /// Returns [`DomainError::ArithmeticOverflow`] at [`u32::MAX`].
    ///
    /// **日本語:**<br>
    /// このカウンターを変更せずに次の世代を返します。
    /// [`u32::MAX`] では [`DomainError::ArithmeticOverflow`] を返します。
    pub fn next(&self) -> Result<Self, DomainError> {
        let value = self
            .into_inner()
            .checked_add(1)
            .ok_or(DomainError::ArithmeticOverflow)?;

        Ok(Generation::new(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_increments_without_changing_original() {
        for value in [0, u32::MAX - 1] {
            let generation = Generation::new(value);
            assert_eq!(generation.next().unwrap(), Generation::new(value + 1));
            assert_eq!(*generation.as_inner(), value);
        }
    }

    #[test]
    fn next_rejects_overflow() {
        assert_eq!(
            Generation::new(u32::MAX).next().unwrap_err(),
            DomainError::ArithmeticOverflow
        );
    }
}
