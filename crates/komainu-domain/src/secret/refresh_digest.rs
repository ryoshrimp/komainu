use crate::{
    error::DomainError,
    secret::{Digest, SecretKind},
    shared::validate_digest_kind,
};

fn validate_refresh_digest(_digest: &Digest) -> Result<(), DomainError> {
    validate_digest_kind(&_digest.kind(), &SecretKind::RefreshToken)
}

/// **English:**<br>
/// Keeps a refresh-token digest restricted to [`SecretKind::RefreshToken`].
///
/// [`Self::try_new`] retains the supplied [`Digest`] when its tag matches and returns
/// [`DomainError::WrongSecretKind`] otherwise. [`Self::as_inner`] borrows the stored value.
/// Serde writes the digest's `_kind` and `_bytes` fields directly and validates the tag
/// when reading them; invalid input yields a deserializer error. This type does not
/// rotate tokens, check revocation, or compute their digests.
///
/// **日本語:**<br>
/// リフレッシュトークンのダイジェストを [`SecretKind::RefreshToken`] に制限して保持します。
///
/// [`Self::try_new`] は種別が一致する [`Digest`] を保持し、不一致なら
/// [`DomainError::WrongSecretKind`] を返します。[`Self::as_inner`] は保持した値を借用します。
/// Serde はダイジェストの `_kind` と `_bytes` を直接出力し、読み込み時に種別を検証します。
/// 不正な入力はデシリアライザーのエラーになります。この型はトークンのローテーション、
/// 失効確認、ダイジェストの計算を行いません。
///
/// # Example / 使用例
/// ```rust
/// use komainu_domain::{error::DomainError, secret::{RefreshDigest, Digest, SecretKind}};
///
/// let token = RefreshDigest::try_new(Digest::new(SecretKind::RefreshToken, [7; 32])).unwrap();
/// assert_eq!(token.as_inner().kind(), SecretKind::RefreshToken);
/// assert_eq!(RefreshDigest::try_new(Digest::new(SecretKind::AccessToken, [7; 32])),
///            Err(DomainError::WrongSecretKind));
/// let json = serde_json::to_string(&token).unwrap();
/// assert_eq!(serde_json::from_str::<RefreshDigest>(&json).unwrap(), token);
/// ```
#[derive(ddd_toolkit::ValueObject)]
#[value_object(validate = validate_refresh_digest, error = DomainError, serde)]
pub struct RefreshDigest {
    _digest: Digest,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construction_preserves_digest() {
        let digest = Digest::new(SecretKind::RefreshToken, [0xa5; 32]);
        let value = RefreshDigest::try_new(digest.clone()).unwrap();
        assert_eq!(value.as_inner(), &digest);
    }

    #[test]
    fn construction_and_deserialization_reject_other_kinds() {
        for kind in [
            SecretKind::AuthorizationCode,
            SecretKind::AccessToken,
            SecretKind::ClientSecret,
            SecretKind::InteractionHandle,
            SecretKind::BrowserBinding,
        ] {
            let digest = Digest::new(kind, [0xa5; 32]);
            let json = serde_json::to_string(&digest).unwrap();
            assert_eq!(
                RefreshDigest::try_new(digest).unwrap_err(),
                DomainError::WrongSecretKind,
                "{kind:?}"
            );
            assert!(
                serde_json::from_str::<RefreshDigest>(&json).is_err(),
                "{json}"
            );
        }
    }

    #[test]
    fn serde_round_trip_preserves_digest() {
        let value =
            RefreshDigest::try_new(Digest::new(SecretKind::RefreshToken, [0xa5; 32])).unwrap();
        let json = serde_json::to_string(&value).unwrap();
        assert_eq!(serde_json::from_str::<RefreshDigest>(&json).unwrap(), value);
    }

    #[test]
    fn deserialization_rejects_invalid_byte_lengths() {
        for len in [0, 31, 33] {
            let json = serde_json::json!({
                "_kind": "RefreshToken",
                "_bytes": vec![0xa5_u8; len],
            });
            assert!(
                serde_json::from_value::<RefreshDigest>(json).is_err(),
                "length {len}"
            );
        }
    }
}
