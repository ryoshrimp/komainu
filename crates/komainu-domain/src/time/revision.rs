use crate::error::DomainError;

/// **English:**<br>
/// A revision counter in `0..=u64::MAX`, serialized as an integer.
///
/// [`Self::new`] accepts any `u64`, including zero. [`Self::next`] produces a
/// separate revision value; callers decide whether to replace their stored revision.
///
/// **日本語:**<br>
/// `0..=u64::MAX` のリビジョンカウンターです。整数としてシリアライズします。
///
/// [`Self::new`] はゼロを含むすべての `u64` を受理します。[`Self::next`] は
/// 別のリビジョン値を生成し、保持している値を置き換えるかどうかは呼び出し側が決めます。
///
/// # Example / 使用例
/// ```rust
/// use komainu_domain::{error::DomainError, time::Revision};
///
/// let revision = Revision::new(41);
/// assert_eq!(revision.next().unwrap(), Revision::new(42));
/// assert_eq!(*revision.as_inner(), 41);
/// assert_eq!(Revision::new(u64::MAX).next(), Err(DomainError::ArithmeticOverflow));
/// ```
#[derive(ddd_toolkit::ValueObject, Copy, PartialOrd, Ord)]
#[value_object(serde)]
pub struct Revision(u64);

impl Revision {
    /// **English:**<br>
    /// Adds one to this revision and returns the result without modifying `self`.
    /// Returns [`DomainError::ArithmeticOverflow`] at [`u64::MAX`] rather than wrapping.
    ///
    /// **日本語:**<br>
    /// このリビジョンに1を加え、`self` を変更せずに結果を返します。
    /// [`u64::MAX`] ではゼロに戻らず [`DomainError::ArithmeticOverflow`] を返します。
    pub fn next(&self) -> Result<Self, DomainError> {
        let value = self
            .into_inner()
            .checked_add(1)
            .ok_or(DomainError::ArithmeticOverflow)?;

        Ok(Revision::new(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_increments_without_changing_original() {
        for value in [0, u64::MAX - 1] {
            let revision = Revision::new(value);
            assert_eq!(revision.next().unwrap(), Revision::new(value + 1));
            assert_eq!(*revision.as_inner(), value);
        }
    }

    #[test]
    fn next_rejects_overflow() {
        assert_eq!(
            Revision::new(u64::MAX).next().unwrap_err(),
            DomainError::ArithmeticOverflow
        );
    }
}
