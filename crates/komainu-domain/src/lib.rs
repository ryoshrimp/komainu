//! **English:**<br>
//! Validated domain identifiers, time values, and OAuth request values and policies.
//!
//! See [`ids`] for string identifiers, [`time`] for durations, [`scope`] for scope and
//! redirect resolution, and [`error::DomainError`] for validation and operation failures.
//!
//! **日本語:**<br>
//! 検証済みのドメイン識別子、時間値、OAuth リクエストの値とポリシーを提供します。
//!
//! 文字列識別子は [`ids`]、期間は [`time`]、スコープとリダイレクトの解決は [`scope`]、
//! 検証失敗や操作の拒否は [`error::DomainError`] を参照してください。

/// **English:**<br>
/// Domain failures represented by [`error::DomainError`].
///
/// **日本語:**<br>
/// [`error::DomainError`] で表すドメインのエラーです。
pub mod error;
/// **English:**<br>
/// String identifiers for audits, clients, consents, correlations, families, grants, and subjects.
///
/// Each type accepts non-empty strings without whitespace or control characters.
/// Construction and Serde deserialization validate the input without normalization;
/// serialization produces a string. See each type for validation errors and examples.
///
/// **日本語:**<br>
/// 監査、クライアント、同意、相関、ファミリー、グラント、主体の文字列識別子です。
///
/// 各型は空白文字と制御文字を含まない、空でない文字列を受理します。
/// 構築時と Serde のデシリアライズ時に正規化せず検証し、
/// シリアライズ時には文字列を出力します。検証エラーと使用例は各型を参照してください。
pub mod ids;
/// **English:**<br>
/// Validated time values, including positive millisecond durations.
///
/// **日本語:**<br>
/// 正のミリ秒単位の期間など、検証済みの時間値を提供します。
pub mod time;

/// **English:**<br>
/// OAuth scope resolution, redirect URI matching, and state syntax validation.
///
/// [`scope::ScopePolicy`] checks registered, allowed, and default scope sets.
/// [`scope::RedirectUriSet`] selects an exact-string URI match, and [`scope::ResolvedRedirect`]
/// checks its use at the token endpoint. [`scope::OAuthState`] validates state syntax only;
/// callers remain responsible for generating and correlating state values.
///
/// **日本語:**<br>
/// OAuth スコープの解決、リダイレクト URI の照合、state の構文検証を提供します。
///
/// [`scope::ScopePolicy`] は登録集合・許可集合・既定集合を検証します。
/// [`scope::RedirectUriSet`] は文字列の完全一致で URI を選択し、[`scope::ResolvedRedirect`] は
/// トークンエンドポイントでの使用を検証します。[`scope::OAuthState`] は構文のみを検証し、
/// state 値の生成と対応関係の確認は呼び出し元が行う必要があります。
pub mod scope;

mod shared;
