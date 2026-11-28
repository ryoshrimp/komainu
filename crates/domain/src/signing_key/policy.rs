use time::Duration;

use crate::error::DomainError;

/// Lifetimes of AS signing keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigningPolicy {
    active_period: Duration,
    prepublish: Duration,
    retire_overlap: Duration,
}

impl SigningPolicy {
    /// Creates a policy.
    ///
    /// `prepublish` must be at least one hour, `active_period` must be longer than
    /// `prepublish`, and `retire_overlap` must not be negative.
    pub fn new(
        active_period: Duration,
        prepublish: Duration,
        retire_overlap: Duration,
    ) -> Result<Self, DomainError> {
        if prepublish < Duration::hours(1) {
            return Err(DomainError::invalid(
                "signing_policy",
                "prepublish must be at least 1 hour",
            ));
        }
        if active_period <= prepublish {
            return Err(DomainError::invalid(
                "signing_policy",
                "active_period must be longer than prepublish",
            ));
        }
        if retire_overlap.is_negative() {
            return Err(DomainError::invalid(
                "signing_policy",
                "retire_overlap must not be negative",
            ));
        }
        Ok(Self {
            active_period,
            prepublish,
            retire_overlap,
        })
    }

    /// How long a key signs (default 90 days).
    pub fn active_period(&self) -> Duration {
        self.active_period
    }

    /// How long before expiry the next key is created (default 7 days).
    pub fn prepublish(&self) -> Duration {
        self.prepublish
    }

    /// How long a retired key stays in the JWKS (default 7 days).
    pub fn retire_overlap(&self) -> Duration {
        self.retire_overlap
    }
}

impl Default for SigningPolicy {
    fn default() -> Self {
        Self {
            active_period: Duration::days(90),
            prepublish: Duration::days(7),
            retire_overlap: Duration::days(7),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_rules() {
        let d = Duration::days;
        assert!(SigningPolicy::new(d(90), d(7), d(7)).is_ok());
        assert!(SigningPolicy::new(d(90), Duration::minutes(59), d(7)).is_err());
        assert!(SigningPolicy::new(d(90), Duration::hours(1), d(0)).is_ok());
        assert!(SigningPolicy::new(d(7), d(7), d(7)).is_err());
        assert!(SigningPolicy::new(d(90), d(7), Duration::seconds(-1)).is_err());
        let p = SigningPolicy::default();
        assert_eq!(
            SigningPolicy::new(p.active_period(), p.prepublish(), p.retire_overlap()),
            Ok(p)
        );
    }
}
