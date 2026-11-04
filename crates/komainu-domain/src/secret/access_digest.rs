use crate::{
    error::DomainError,
    secret::{Digest, SecretKind},
    shared::validate_digest_kind,
};

fn validate_access_digest(_digest: &Digest) -> Result<(), DomainError> {
    validate_digest_kind(&_digest.kind(), &SecretKind::AccessToken)
}

/// **English:**<br>
/// Restricts a [`Digest`] to the access-token category [`SecretKind::AccessToken`].
///
/// [`Self::try_new`] preserves the digest or returns [`DomainError::WrongSecretKind`]
/// for any other category. [`Self::as_inner`] borrows the accepted digest.
/// Serde uses the inner digest's `_kind` and `_bytes` fields without a wrapper field,
/// validates the category on deserialization, and reports invalid input through the
/// deserializer's error type. This checks the tag, not the digest algorithm or origin.
///
/// **日本語:**<br>
/// [`Digest`] をアクセストークン種別 [`SecretKind::AccessToken`] に制限します。
///
/// [`Self::try_new`] はダイジェストを保持し、他の種別には
/// [`DomainError::WrongSecretKind`] を返します。[`Self::as_inner`] は受理した値を借用します。
/// Serde はラッパーのフィールドを追加せず、内部ダイジェストの `_kind` と `_bytes` を使用し、
/// デシリアライズ時に種別を検証します。不正な入力はデシリアライザー固有のエラーになります。
/// 検証対象は種別であり、ダイジェストのアルゴリズムや出所ではありません。
///
/// # Example / 使用例
/// ```rust
/// use komainu_domain::{error::DomainError, secret::{AccessDigest, Digest, SecretKind}};
///
/// let value = AccessDigest::try_new(Digest::new(SecretKind::AccessToken, [7; 32])).unwrap();
/// assert_eq!(value.as_inner().kind(), SecretKind::AccessToken);
/// assert_eq!(AccessDigest::try_new(Digest::new(SecretKind::RefreshToken, [7; 32])),
///            Err(DomainError::WrongSecretKind));
/// let json = serde_json::to_string(&value).unwrap();
/// assert_eq!(serde_json::from_str::<AccessDigest>(&json).unwrap(), value);
/// ```
#[derive(ddd_toolkit::ValueObject)]
#[value_object(validate = validate_access_digest, error = DomainError, serde)]
pub struct AccessDigest {
    _digest: Digest,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construction_preserves_digest() {
        let digest = Digest::new(SecretKind::AccessToken, [0xa5; 32]);
        let value = AccessDigest::try_new(digest.clone()).unwrap();
        assert_eq!(value.as_inner(), &digest);
    }

    #[test]
    fn construction_and_deserialization_reject_other_kinds() {
        for kind in [
            SecretKind::AuthorizationCode,
            SecretKind::RefreshToken,
            SecretKind::ClientSecret,
            SecretKind::InteractionHandle,
            SecretKind::BrowserBinding,
        ] {
            let digest = Digest::new(kind, [0xa5; 32]);
            let json = serde_json::to_string(&digest).unwrap();
            assert_eq!(
                AccessDigest::try_new(digest).unwrap_err(),
                DomainError::WrongSecretKind,
                "{kind:?}"
            );
            assert!(
                serde_json::from_str::<AccessDigest>(&json).is_err(),
                "{json}"
            );
        }
    }

    #[test]
    fn serde_round_trip_preserves_digest() {
        let value =
            AccessDigest::try_new(Digest::new(SecretKind::AccessToken, [0xa5; 32])).unwrap();
        let json = serde_json::to_string(&value).unwrap();
        assert_eq!(serde_json::from_str::<AccessDigest>(&json).unwrap(), value);
    }

    #[test]
    fn deserialization_rejects_invalid_byte_lengths() {
        for len in [0, 31, 33] {
            let json = serde_json::json!({
                "_kind": "AccessToken",
                "_bytes": vec![0xa5_u8; len],
            });
            assert!(
                serde_json::from_value::<AccessDigest>(json).is_err(),
                "length {len}"
            );
        }
    }
}
