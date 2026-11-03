use std::collections::BTreeSet;

use crate::{error::DomainError, scope::Scope};

/// **English:**<br>
/// A possibly empty set of distinct scope tokens ordered by their original strings.
///
/// Construction removes duplicates. Iteration and [`Self::to_wire`] use the same
/// case-sensitive lexical order. Serde represents the set as a sequence of strings,
/// validates each [`Scope`] on input, and removes duplicates; it does not use the wire string format.
///
/// **日本語:**<br>
/// 元の文字列順に並ぶ、重複しないスコープトークンの集合です。空集合も表せます。
///
/// 構築時に重複を除去します。走査と [`Self::to_wire`] は同じ、
/// 大文字小文字を区別する辞書順を使います。Serde は文字列の列として表現し、
/// 入力時に各 [`Scope`] を検証して重複を除去します。通信形式の単一文字列は使いません。
///
/// # Example / 使用例
/// ```rust
/// use komainu_domain::scope::ScopeSet;
///
/// let scopes = ScopeSet::parse("write read read").unwrap();
/// assert_eq!(scopes.to_wire(), "read write");
/// assert!(ScopeSet::parse("read").unwrap().is_subset(&scopes));
/// assert_eq!(scopes.difference(&ScopeSet::parse("read").unwrap()).to_wire(), "write");
/// ```
#[derive(ddd_toolkit::ValueObject)]
#[value_object(serde)]
pub struct ScopeSet(BTreeSet<Scope>);

impl ScopeSet {
    /// **English:**<br>
    /// Consumes validated `scopes`, removing duplicates; an empty vector produces an empty set.
    ///
    /// **日本語:**<br>
    /// 検証済みの `scopes` を消費し、重複を除去します。空のベクターからは空集合を作ります。
    pub fn from_scopes(scopes: Vec<Scope>) -> Self {
        let set: BTreeSet<Scope> = scopes.into_iter().collect();
        ScopeSet::new(set)
    }

    /// **English:**<br>
    /// Parses tokens separated by exactly one ASCII space and removes duplicates.
    ///
    /// Empty input, leading or trailing spaces, and repeated spaces produce empty tokens
    /// and return [`DomainError::EmptyText`]. Other token failures propagate from
    /// [`Scope::try_new`], including [`DomainError::InvalidScopeSyntax`].
    /// An empty set must be built with [`Self::from_scopes`], not parsed from an empty string.
    ///
    /// **日本語:**<br>
    /// ASCII スペース 1 個で区切られたトークンを解析し、重複を除去します。
    ///
    /// 空入力、先頭・末尾のスペース、連続スペースは空トークンを生むため
    /// [`DomainError::EmptyText`] を返します。その他のトークンの検証失敗は、
    /// [`DomainError::InvalidScopeSyntax`] を含め [`Scope::try_new`] から伝播します。
    /// 空集合は空文字列の解析ではなく [`Self::from_scopes`] で構築してください。
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        let scopes = value
            .split(' ')
            .map(|v| Scope::try_new(v.to_owned()))
            .collect::<Result<Vec<Scope>, DomainError>>()?;

        Ok(Self::from_scopes(scopes))
    }

    /// **English:**<br>
    /// Borrows the distinct tokens in case-sensitive lexical order.
    ///
    /// **日本語:**<br>
    /// 重複しないトークンを、大文字小文字を区別する辞書順で借用して走査します。
    pub fn iter(&self) -> impl Iterator<Item = &Scope> {
        self.0.iter()
    }

    /// **English:**<br>
    /// Returns whether the set contains no scope tokens.
    ///
    /// **日本語:**<br>
    /// 集合がスコープトークンを含まないかどうかを返します。
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// **English:**<br>
    /// Returns whether every token in this set occurs in `other`; returns `true` for an empty set.
    ///
    /// **日本語:**<br>
    /// この集合の全トークンが `other` に含まれるかを返します。空集合は常に部分集合です。
    pub fn is_subset(&self, other: &Self) -> bool {
        self.0.is_subset(other.as_inner())
    }

    /// **English:**<br>
    /// Clones tokens present in either set into a new set without modifying either input.
    ///
    /// **日本語:**<br>
    /// どちらかの集合に含まれるトークンを複製して新しい集合にし、入力は変更しません。
    pub fn union(&self, other: &Self) -> Self {
        ScopeSet::new(self.0.union(other.as_inner()).cloned().collect())
    }

    /// **English:**<br>
    /// Clones tokens in this set but not in `other` into a new set without modifying either input.
    ///
    /// **日本語:**<br>
    /// この集合に含まれ `other` には含まれないトークンを複製し、入力を変更せず新しい集合にします。
    pub fn difference(&self, other: &Self) -> Self {
        ScopeSet::new(self.0.difference(other.as_inner()).cloned().collect())
    }

    /// **English:**<br>
    /// Joins tokens in lexical order with single ASCII spaces; an empty set yields an empty string.
    /// Non-empty output can be read by [`Self::parse`], but empty output cannot.
    ///
    /// **日本語:**<br>
    /// 辞書順のトークンを ASCII スペース 1 個で連結し、空集合では空文字列を返します。
    /// 空でない出力は [`Self::parse`] で読み戻せますが、空の出力は読み戻せません。
    pub fn to_wire(&self) -> String {
        let vec: Vec<String> = self.0.iter().map(|v| v.as_inner().to_string()).collect();

        vec.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scopes(value: &str) -> ScopeSet {
        ScopeSet::parse(value).unwrap()
    }

    fn empty_scopes() -> ScopeSet {
        ScopeSet::from_scopes(vec![])
    }

    #[test]
    fn scope_set_parses_deduplicates_and_produces_stable_wire_output() {
        let set = scopes("write read read");
        assert_eq!(set.to_wire(), "read write");
        assert_eq!(set.iter().count(), 2);
        assert_eq!(scopes(&set.to_wire()), set);
        assert!(empty_scopes().is_empty());
        assert_eq!(empty_scopes().to_wire(), "");
    }

    #[test]
    fn scope_set_rejects_invalid_wire_syntax() {
        for value in [
            "",
            " read",
            "read ",
            "read  write",
            "read\twrite",
            "read\nwrite",
        ] {
            assert!(ScopeSet::parse(value).is_err(), "{value:?}");
        }
    }

    #[test]
    fn scope_set_operations_preserve_set_semantics() {
        let read = scopes("read");
        let both = scopes("read write");
        assert!(read.is_subset(&both));
        assert!(!both.is_subset(&read));
        assert!(empty_scopes().is_subset(&read));
        assert_eq!(read.union(&scopes("write")), both);
        assert_eq!(both.difference(&read), scopes("write"));
        assert!(read.difference(&both).is_empty());
    }

    #[test]
    fn serde_round_trip_preserves_values() {
        for value in [scopes("read write"), empty_scopes()] {
            let json = serde_json::to_string(&value).unwrap();
            assert_eq!(serde_json::from_str::<ScopeSet>(&json).unwrap(), value);
        }
    }

    #[test]
    fn serde_rejects_invalid_scope_values() {
        for value in ["", "read write", "read\twrite", "日本語", "\"", "\\"] {
            let json = serde_json::to_string(&[value]).unwrap();
            assert!(
                serde_json::from_str::<ScopeSet>(&json).is_err(),
                "{value:?}"
            );
        }
    }
}
