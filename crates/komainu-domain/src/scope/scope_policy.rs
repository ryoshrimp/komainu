use crate::{
    error::DomainError,
    scope::{ScopeRequest, ScopeSet},
};

/// **English:**<br>
/// Resolves requested scopes against registered tokens and per-client allowed and default sets.
///
/// [`Self::resolve`] validates client configuration before inspecting the request;
/// it returns a cloned set, leaving an explicit request unchanged rather than adding defaults.
///
/// **日本語:**<br>
/// 登録済みトークンとクライアントごとの許可集合・既定集合に基づき、要求スコープを解決します。
///
/// [`Self::resolve`] は要求の確認前にクライアント設定を検証します。
/// 集合を複製して返し、明示的な要求に既定値を追加することはありません。
///
/// # Example / 使用例
/// ```rust
/// use komainu_domain::scope::{ScopePolicy, ScopeRequest, ScopeSet};
///
/// let policy = ScopePolicy::new(ScopeSet::parse("read write").unwrap());
/// let allowed = ScopeSet::parse("read write").unwrap();
/// let defaults = ScopeSet::parse("read").unwrap();
/// assert_eq!(policy.resolve(&ScopeRequest::Omitted, &allowed, &defaults).unwrap(), defaults);
/// let request = ScopeRequest::Explicit(ScopeSet::parse("write").unwrap());
/// assert_eq!(policy.resolve(&request, &allowed, &defaults).unwrap().to_wire(), "write");
/// ```
#[derive(Debug)]
pub struct ScopePolicy {
    registered: ScopeSet,
}

impl ScopePolicy {
    /// **English:**<br>
    /// Stores `registered` as the set of known scopes, allowing an empty registry.
    /// Client configuration is checked later by [`Self::resolve`].
    ///
    /// **日本語:**<br>
    /// `registered` を既知のスコープ集合として保持します。空の登録集合も許可します。
    /// クライアント設定は後で [`Self::resolve`] が検証します。
    pub fn new(registered: ScopeSet) -> Self {
        ScopePolicy { registered }
    }

    /// **English:**<br>
    /// Borrows the known scope set without changing the policy.
    ///
    /// **日本語:**<br>
    /// ポリシーを変更せず、既知のスコープ集合を借用します。
    pub fn registered(&self) -> &ScopeSet {
        &self.registered
    }

    /// **English:**<br>
    /// Returns defaults for omission or the supplied explicit set after validation.
    ///
    /// Errors are checked in this order:
    /// - [`DomainError::InvalidClientConfig`] if `defaults` is not a subset of `allowed`
    ///   or `allowed` is not a subset of the registered scopes, regardless of `request`.
    /// - For omission, [`DomainError::MissingDefaultScope`] if `defaults` is empty.
    /// - For an explicit set, [`DomainError::EmptyScopeSet`] if empty,
    ///   [`DomainError::UnknownScope`] if any token is unregistered, then
    ///   [`DomainError::ScopeNotAllowed`] if any token is outside `allowed`.
    ///
    /// Empty defaults are valid for an explicit request. Inputs are not modified.
    ///
    /// **日本語:**<br>
    /// 省略時には既定集合を、明示時には指定集合を検証して返します。
    ///
    /// エラーは次の順で検査します。
    /// - `defaults` が `allowed` の部分集合でない、または `allowed` が登録集合の
    ///   部分集合でない場合は、`request` に関係なく [`DomainError::InvalidClientConfig`]。
    /// - 省略時に `defaults` が空なら [`DomainError::MissingDefaultScope`]。
    /// - 明示集合が空なら [`DomainError::EmptyScopeSet`]、未登録トークンを含めば
    ///   [`DomainError::UnknownScope`]、その後 `allowed` 外のトークンを含めば
    ///   [`DomainError::ScopeNotAllowed`]。
    ///
    /// 明示的な要求では空の既定集合も有効です。入力は変更しません。
    pub fn resolve(
        &self,
        request: &ScopeRequest,
        allowed: &ScopeSet,
        defaults: &ScopeSet,
    ) -> Result<ScopeSet, DomainError> {
        if !defaults.is_subset(allowed) || !allowed.is_subset(&self.registered) {
            return Err(DomainError::InvalidClientConfig);
        }

        match request {
            ScopeRequest::Omitted => {
                if defaults.is_empty() {
                    return Err(DomainError::MissingDefaultScope);
                }

                Ok(defaults.clone())
            }
            ScopeRequest::Explicit(scopes) => {
                if scopes.is_empty() {
                    return Err(DomainError::EmptyScopeSet);
                }
                if !scopes.is_subset(&self.registered) {
                    return Err(DomainError::UnknownScope);
                }
                if !scopes.is_subset(allowed) {
                    return Err(DomainError::ScopeNotAllowed);
                }

                Ok(scopes.clone())
            }
        }
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
    fn scope_policy_resolves_explicit_and_default_scopes() {
        let policy = ScopePolicy::new(scopes("read write admin"));
        let allowed = scopes("read write");
        let defaults = scopes("read");
        assert_eq!(policy.registered(), &scopes("read write admin"));
        assert_eq!(
            policy.resolve(&ScopeRequest::Omitted, &allowed, &defaults),
            Ok(defaults.clone())
        );
        assert_eq!(
            policy.resolve(
                &ScopeRequest::Explicit(scopes("write")),
                &allowed,
                &defaults
            ),
            Ok(scopes("write"))
        );
        assert_eq!(
            policy.resolve(
                &ScopeRequest::Explicit(scopes("read")),
                &allowed,
                &empty_scopes()
            ),
            Ok(scopes("read"))
        );
    }

    #[test]
    fn scope_policy_distinguishes_missing_empty_unknown_and_disallowed_scopes() {
        let policy = ScopePolicy::new(scopes("read write"));
        let allowed = scopes("read");
        for (request, expected) in [
            (ScopeRequest::Omitted, DomainError::MissingDefaultScope),
            (
                ScopeRequest::Explicit(empty_scopes()),
                DomainError::EmptyScopeSet,
            ),
            (
                ScopeRequest::Explicit(scopes("unknown")),
                DomainError::UnknownScope,
            ),
            (
                ScopeRequest::Explicit(scopes("write")),
                DomainError::ScopeNotAllowed,
            ),
            (
                ScopeRequest::Explicit(scopes("write unknown")),
                DomainError::UnknownScope,
            ),
        ] {
            assert_eq!(
                policy.resolve(&request, &allowed, &empty_scopes()),
                Err(expected)
            );
        }
    }

    #[test]
    fn scope_policy_checks_configuration_before_request_errors() {
        let policy = ScopePolicy::new(scopes("read write"));
        for (allowed, defaults) in [
            (scopes("read"), scopes("write")),
            (scopes("unknown"), empty_scopes()),
            (empty_scopes(), scopes("read")),
        ] {
            for request in [
                ScopeRequest::Omitted,
                ScopeRequest::Explicit(empty_scopes()),
                ScopeRequest::Explicit(scopes("unknown")),
                ScopeRequest::Explicit(scopes("read")),
            ] {
                assert_eq!(
                    policy.resolve(&request, &allowed, &defaults),
                    Err(DomainError::InvalidClientConfig)
                );
            }
        }
    }
}
