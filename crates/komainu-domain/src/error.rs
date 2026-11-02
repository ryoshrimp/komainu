/// **English:**<br>
/// Identifies a domain validation failure or an operation rejected by domain rules.
///
/// Each variant carries no additional data. Its [`std::fmt::Display`] implementation
/// provides an English message describing the failure; match on the variant to
/// distinguish error kinds without parsing that message.
///
/// **日本語:**<br>
/// ドメインの検証失敗、またはドメインルールによる操作の拒否を表します。
///
/// 各バリアントは追加データを保持しません。[`std::fmt::Display`] 実装は
/// 失敗の内容を英語で表示します。エラーの種類はメッセージを解析せず、
/// バリアントとのパターンマッチで判別します。
///
/// # Example / 使用例
///
/// Match an error kind independently of its display message.
/// 表示メッセージに依存せず、エラーの種類を判別します。
///
/// ```rust
/// use komainu_domain::error::DomainError;
///
/// let error = DomainError::Expired;
/// assert!(matches!(error, DomainError::Expired));
/// ```
#[derive(thiserror::Error, Debug)]
pub enum DomainError {
    /// **English:**<br>
    /// Text is empty where a non-empty value is required.
    ///
    /// **日本語:**<br>
    /// 空でない値が必要な箇所に、空のテキストが指定されています。
    #[error("text must not be empty")]
    EmptyText,
    /// **English:**<br>
    /// Text contains a prohibited control character.
    ///
    /// **日本語:**<br>
    /// テキストに禁止された制御文字が含まれています。
    #[error("text must not contain control characters")]
    ControlCharacter,
    /// **English:**<br>
    /// A scope value does not satisfy the required syntax.
    ///
    /// **日本語:**<br>
    /// スコープの値が必要な構文を満たしていません。
    #[error("scope syntax is invalid")]
    InvalidScopeSyntax,
    /// **English:**<br>
    /// A scope set contains no scopes where at least one is required.
    ///
    /// **日本語:**<br>
    /// 1つ以上のスコープが必要なスコープ集合が空です。
    #[error("scope set must not be empty")]
    EmptyScopeSet,
    /// **English:**<br>
    /// A scope is not recognized.
    ///
    /// **日本語:**<br>
    /// スコープが認識されていません。
    #[error("scope is unknown")]
    UnknownScope,
    /// **English:**<br>
    /// A recognized scope is not permitted for the operation.
    ///
    /// **日本語:**<br>
    /// 認識されたスコープが、この操作では許可されていません。
    #[error("scope is not allowed")]
    ScopeNotAllowed,
    /// **English:**<br>
    /// A required default scope is absent.
    ///
    /// **日本語:**<br>
    /// 必要なデフォルトスコープがありません。
    #[error("default scope is missing")]
    MissingDefaultScope,
    /// **English:**<br>
    /// A redirect URI does not satisfy validation requirements.
    ///
    /// **日本語:**<br>
    /// リダイレクトURIが検証条件を満たしていません。
    #[error("redirect URI is invalid")]
    InvalidRedirectUri,
    /// **English:**<br>
    /// A redirect URI differs from the registered URI.
    ///
    /// **日本語:**<br>
    /// リダイレクトURIが登録済みのURIと一致しません。
    #[error("redirect URI does not match the registered URI")]
    RedirectMismatch,
    /// **English:**<br>
    /// A redirect URI is absent or cannot be selected unambiguously.
    ///
    /// **日本語:**<br>
    /// リダイレクトURIがないか、一意に選択できません。
    #[error("redirect URI is missing or cannot be determined unambiguously")]
    MissingOrAmbiguousRedirect,
    /// **English:**<br>
    /// The `state` parameter value does not satisfy validation requirements.
    ///
    /// **日本語:**<br>
    /// `state` パラメーターの値が検証条件を満たしていません。
    #[error("state parameter value is invalid")]
    InvalidStateValue,
    /// **English:**<br>
    /// A secret has a different kind from the one required.
    ///
    /// **日本語:**<br>
    /// シークレットの種類が必要な種類と一致しません。
    #[error("secret kind does not match the expected kind")]
    WrongSecretKind,
    /// **English:**<br>
    /// A client configuration does not satisfy validation requirements.
    ///
    /// **日本語:**<br>
    /// クライアント設定が検証条件を満たしていません。
    #[error("client configuration is invalid")]
    InvalidClientConfig,
    /// **English:**<br>
    /// A required credential was not provided.
    ///
    /// **日本語:**<br>
    /// 必要な認証情報が指定されていません。
    #[error("required credential is missing")]
    MissingCredential,
    /// **English:**<br>
    /// A credential was provided where none was expected.
    ///
    /// **日本語:**<br>
    /// 認証情報を想定しない箇所に認証情報が指定されています。
    #[error("credential was provided when none was expected")]
    UnexpectedCredential,
    /// **English:**<br>
    /// The client is disabled.
    ///
    /// **日本語:**<br>
    /// クライアントが無効化されています。
    #[error("client is disabled")]
    ClientDisabled,
    /// **English:**<br>
    /// The grant type is not supported.
    ///
    /// **日本語:**<br>
    /// グラント種別がサポートされていません。
    #[error("grant type is not supported")]
    UnsupportedGrant,
    /// **English:**<br>
    /// The subject is disabled.
    ///
    /// **日本語:**<br>
    /// 主体が無効化されています。
    #[error("subject is disabled")]
    SubjectDisabled,
    /// **English:**<br>
    /// Previously given consent has been withdrawn.
    ///
    /// **日本語:**<br>
    /// 過去に与えられた同意が撤回されています。
    #[error("consent has been withdrawn")]
    ConsentWithdrawn,
    /// **English:**<br>
    /// Consent does not include all requested scopes.
    ///
    /// **日本語:**<br>
    /// 同意の範囲に、要求されたすべてのスコープが含まれていません。
    #[error("consent does not cover the requested scopes")]
    ConsentDoesNotCover,
    /// **English:**<br>
    /// The grant has been revoked.
    ///
    /// **日本語:**<br>
    /// グラントが失効されています。
    #[error("grant has been revoked")]
    GrantRevoked,
    /// **English:**<br>
    /// The token has been revoked.
    ///
    /// **日本語:**<br>
    /// トークンが失効されています。
    #[error("token has been revoked")]
    TokenRevoked,
    /// **English:**<br>
    /// The token family has been revoked.
    ///
    /// **日本語:**<br>
    /// トークンファミリーが失効されています。
    #[error("token family has been revoked")]
    FamilyRevoked,
    /// **English:**<br>
    /// A binding differs from the expected binding.
    ///
    /// **日本語:**<br>
    /// バインディングが期待するバインディングと一致しません。
    #[error("binding does not match the expected binding")]
    BindingMismatch,
    /// **English:**<br>
    /// A required relation is absent.
    ///
    /// **日本語:**<br>
    /// 必要な関連がありません。
    #[error("required relation is missing")]
    MissingRelation,
    /// **English:**<br>
    /// A relation exists where none was expected.
    ///
    /// **日本語:**<br>
    /// 関連を想定しない箇所に関連が存在します。
    #[error("relation was provided when none was expected")]
    UnexpectedRelation,
    /// **English:**<br>
    /// The validity period has not started.
    ///
    /// **日本語:**<br>
    /// 有効期間がまだ始まっていません。
    #[error("validity period has not started yet")]
    NotYetValid,
    /// **English:**<br>
    /// The validity period has ended.
    ///
    /// **日本語:**<br>
    /// 有効期間が終了しています。
    #[error("validity period has expired")]
    Expired,
    /// **English:**<br>
    /// A resource intended for one-time use has already been used.
    ///
    /// **日本語:**<br>
    /// 一度だけ使用できるリソースが、すでに使用されています。
    #[error("resource has already been used")]
    AlreadyUsed,
    /// **English:**<br>
    /// The current domain state does not permit the operation.
    ///
    /// **日本語:**<br>
    /// 現在のドメイン状態では操作が許可されていません。
    #[error("operation is not allowed in the current state")]
    InvalidState,
    /// **English:**<br>
    /// A revision differs from the expected revision.
    ///
    /// **日本語:**<br>
    /// リビジョンが期待するリビジョンと一致しません。
    #[error("revision does not match the expected revision")]
    RevisionMismatch,
    /// **English:**<br>
    /// A generation differs from the expected generation.
    ///
    /// **日本語:**<br>
    /// 世代が期待する世代と一致しません。
    #[error("generation does not match the expected generation")]
    GenerationMismatch,
    /// **English:**<br>
    /// Timestamps violate the required chronological order.
    ///
    /// **日本語:**<br>
    /// タイムスタンプが必要な時系列順を満たしていません。
    #[error("timestamps are not in the required chronological order")]
    TimeOrder,
    /// **English:**<br>
    /// An arithmetic operation exceeded the representable range.
    ///
    /// **日本語:**<br>
    /// 算術演算の結果が表現可能な範囲を超えました。
    #[error("arithmetic operation overflowed")]
    ArithmeticOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_describes_the_error() {
        assert_eq!(
            DomainError::Expired.to_string(),
            "validity period has expired"
        );
    }
}
