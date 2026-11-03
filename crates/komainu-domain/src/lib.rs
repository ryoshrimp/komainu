//! **English:**<br>
//! Validated domain identifiers and errors for validation failures and rejected operations.
//!
//! See [`ids`] for string identifier types and [`error::DomainError`] for error kinds.
//!
//! **日本語:**<br>
//! 検証済みのドメイン識別子と、検証失敗や操作の拒否を報告するエラー型を提供します。
//!
//! 文字列識別子は [`ids`]、エラーの種類は [`error::DomainError`] を参照してください。

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
mod shared;
