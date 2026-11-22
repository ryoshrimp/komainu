use std::collections::BTreeSet;
use std::fmt;

use ddd_toolkit::ValueObject;

use crate::error::DomainError;

/// A single scope token (RFC 6749 §3.3: one or more NQCHAR characters).
#[derive(ValueObject, PartialOrd, Ord)]
#[value_object(validate = validate_scope_token, error = DomainError)]
pub struct ScopeToken(String);

fn validate_scope_token(value: &ScopeToken) -> Result<(), DomainError> {
    let s = &value.0;
    if s.is_empty() {
        return Err(DomainError::invalid("scope_token", "must not be empty"));
    }
    if !s
        .chars()
        .all(|c| matches!(c, '\u{21}' | '\u{23}'..='\u{5b}' | '\u{5d}'..='\u{7e}'))
    {
        return Err(DomainError::invalid("scope_token", "invalid character"));
    }
    Ok(())
}

impl ScopeToken {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A set of scope tokens.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ScopeSet(BTreeSet<ScopeToken>);

impl ScopeSet {
    /// Parses a space-delimited scope string (RFC 6749 §3.3).
    /// Errors on empty input, leading/trailing/consecutive spaces, or invalid characters.
    /// Duplicate tokens are merged.
    pub fn parse(s: &str) -> Result<ScopeSet, DomainError> {
        if s.is_empty() {
            return Err(DomainError::invalid("scope", "must not be empty"));
        }
        let tokens = s
            .split(' ')
            .map(|t| {
                ScopeToken::try_new(t.to_owned())
                    .map_err(|_| DomainError::invalid("scope", "invalid scope token"))
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        Ok(ScopeSet(tokens))
    }

    pub fn empty() -> ScopeSet {
        ScopeSet(BTreeSet::new())
    }

    pub fn from_tokens(tokens: impl IntoIterator<Item = ScopeToken>) -> ScopeSet {
        ScopeSet(tokens.into_iter().collect())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn is_subset(&self, other: &ScopeSet) -> bool {
        self.0.is_subset(&other.0)
    }

    pub fn union(&self, other: &ScopeSet) -> ScopeSet {
        ScopeSet(self.0.union(&other.0).cloned().collect())
    }

    pub fn iter(&self) -> impl Iterator<Item = &ScopeToken> {
        self.0.iter()
    }
}

impl fmt::Display for ScopeSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, token) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            f.write_str(token.as_str())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_merges_duplicates_and_displays_sorted() {
        let set = ScopeSet::parse("write read read").unwrap();
        assert_eq!(set.iter().count(), 2);
        assert_eq!(set.to_string(), "read write");
    }

    #[test]
    fn parse_rejects_malformed_input() {
        for bad in ["", " read", "read ", "read  write", "re\"ad", "re\\ad"] {
            assert!(ScopeSet::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn set_operations() {
        let a = ScopeSet::parse("read").unwrap();
        let b = ScopeSet::parse("read write").unwrap();
        assert!(a.is_subset(&b));
        assert!(!b.is_subset(&a));
        assert_eq!(a.union(&b), b);
        assert!(ScopeSet::empty().is_empty());
        assert_eq!(ScopeSet::empty().to_string(), "");
    }
}
