use crate::{
    error::DomainError,
    secret::{Digest, SecretKind},
    shared::validate_digest_kind,
};

fn validate_code_digest(_digest: &Digest) -> Result<(), DomainError> {
    validate_digest_kind(&_digest.kind(), &SecretKind::AuthorizationCode)
}

/// **English:**<br>
/// Carries an authorization-code digest tagged [`SecretKind::AuthorizationCode`].
///
/// [`Self::try_new`] returns [`DomainError::WrongSecretKind`] unless the tag matches,
/// preserving accepted bytes. [`Self::as_inner`] borrows the underlying [`Digest`].
/// Serde uses that digest's `_kind` and `_bytes` fields directly; deserialization checks
/// the category and rejects invalid input with a deserializer error. No code exchange,
/// expiry check, or digest computation is performed by this wrapper.
///
/// **日本語:**<br>
/// [`SecretKind::AuthorizationCode`] の種別を持つ認可コードのダイジェストを保持します。
///
/// [`Self::try_new`] は種別が一致しなければ [`DomainError::WrongSecretKind`] を返し、
/// 受理したバイト列は変更しません。[`Self::as_inner`] は内部の [`Digest`] を借用します。
/// Serde はその `_kind` と `_bytes` を直接使用します。デシリアライズ時には種別を検証し、
/// 不正な入力をデシリアライザーのエラーとして拒否します。
/// このラッパーはコード交換、有効期限の確認、ダイジェスト計算を行いません。
///
/// # Example / 使用例
/// ```rust
/// use komainu_domain::{error::DomainError, secret::{CodeDigest, Digest, SecretKind}};
///
/// let code = CodeDigest::try_new(Digest::new(SecretKind::AuthorizationCode, [7; 32])).unwrap();
/// assert_eq!(code.as_inner().kind(), SecretKind::AuthorizationCode);
/// assert_eq!(CodeDigest::try_new(Digest::new(SecretKind::AccessToken, [7; 32])),
///            Err(DomainError::WrongSecretKind));
/// let json = serde_json::to_string(&code).unwrap();
/// assert_eq!(serde_json::from_str::<CodeDigest>(&json).unwrap(), code);
/// ```
#[derive(ddd_toolkit::ValueObject)]
#[value_object(validate = validate_code_digest, error = DomainError, serde)]
pub struct CodeDigest {
    _digest: Digest,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construction_preserves_digest() {
        let digest = Digest::new(SecretKind::AuthorizationCode, [0xa5; 32]);
        let value = CodeDigest::try_new(digest.clone()).unwrap();
        assert_eq!(value.as_inner(), &digest);
    }

    #[test]
    fn construction_and_deserialization_reject_other_kinds() {
        for kind in [
            SecretKind::AccessToken,
            SecretKind::RefreshToken,
            SecretKind::ClientSecret,
            SecretKind::InteractionHandle,
            SecretKind::BrowserBinding,
        ] {
            let digest = Digest::new(kind, [0xa5; 32]);
            let json = serde_json::to_string(&digest).unwrap();
            assert_eq!(
                CodeDigest::try_new(digest).unwrap_err(),
                DomainError::WrongSecretKind,
                "{kind:?}"
            );
            assert!(serde_json::from_str::<CodeDigest>(&json).is_err(), "{json}");
        }
    }

    #[test]
    fn serde_round_trip_preserves_digest() {
        let value =
            CodeDigest::try_new(Digest::new(SecretKind::AuthorizationCode, [0xa5; 32])).unwrap();
        let json = serde_json::to_string(&value).unwrap();
        assert_eq!(serde_json::from_str::<CodeDigest>(&json).unwrap(), value);
    }

    #[test]
    fn deserialization_rejects_invalid_byte_lengths() {
        for len in [0, 31, 33] {
            let json = serde_json::json!({
                "_kind": "AuthorizationCode",
                "_bytes": vec![0xa5_u8; len],
            });
            assert!(
                serde_json::from_value::<CodeDigest>(json).is_err(),
                "length {len}"
            );
        }
    }
}
