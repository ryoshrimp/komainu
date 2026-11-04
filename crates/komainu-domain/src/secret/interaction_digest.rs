use crate::{
    error::DomainError,
    secret::{Digest, SecretKind},
    shared::validate_digest_kind,
};

fn validate_interaction_digest(_digest: &Digest) -> Result<(), DomainError> {
    validate_digest_kind(&_digest.kind(), &SecretKind::InteractionHandle)
}

/// **English:**<br>
/// Stores an interaction-handle digest tagged [`SecretKind::InteractionHandle`].
///
/// [`Self::try_new`] accepts only that category, returning [`DomainError::WrongSecretKind`]
/// otherwise. [`Self::as_inner`] borrows the unchanged [`Digest`]. Serde serializes
/// the inner `_kind` and `_bytes` fields without nesting and validates the category
/// on deserialization. Malformed input becomes a deserializer error.
/// The wrapper does not look up an interaction or validate its lifetime.
///
/// **日本語:**<br>
/// [`SecretKind::InteractionHandle`] の種別を持つ対話ハンドルのダイジェストを格納します。
///
/// [`Self::try_new`] はこの種別のみ受理し、それ以外には
/// [`DomainError::WrongSecretKind`] を返します。[`Self::as_inner`] は変更せず保持した
/// [`Digest`] を借用します。Serde は内部の `_kind` と `_bytes` をネストせずシリアライズし、
/// デシリアライズ時に種別を検証します。不正な入力はデシリアライザーのエラーになります。
/// このラッパーは対話の検索や、その有効期間の検証を行いません。
///
/// # Example / 使用例
/// ```rust
/// use komainu_domain::{error::DomainError, secret::{InteractionDigest, Digest, SecretKind}};
///
/// let handle = InteractionDigest::try_new(Digest::new(SecretKind::InteractionHandle, [7; 32])).unwrap();
/// assert_eq!(handle.as_inner().kind(), SecretKind::InteractionHandle);
/// assert_eq!(InteractionDigest::try_new(Digest::new(SecretKind::BrowserBinding, [7; 32])),
///            Err(DomainError::WrongSecretKind));
/// let json = serde_json::to_string(&handle).unwrap();
/// assert_eq!(serde_json::from_str::<InteractionDigest>(&json).unwrap(), handle);
/// ```
#[derive(ddd_toolkit::ValueObject)]
#[value_object(validate = validate_interaction_digest, error = DomainError, serde)]
pub struct InteractionDigest {
    _digest: Digest,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construction_preserves_digest() {
        let digest = Digest::new(SecretKind::InteractionHandle, [0xa5; 32]);
        let value = InteractionDigest::try_new(digest.clone()).unwrap();
        assert_eq!(value.as_inner(), &digest);
    }

    #[test]
    fn construction_and_deserialization_reject_other_kinds() {
        for kind in [
            SecretKind::AuthorizationCode,
            SecretKind::AccessToken,
            SecretKind::RefreshToken,
            SecretKind::ClientSecret,
            SecretKind::BrowserBinding,
        ] {
            let digest = Digest::new(kind, [0xa5; 32]);
            let json = serde_json::to_string(&digest).unwrap();
            assert_eq!(
                InteractionDigest::try_new(digest).unwrap_err(),
                DomainError::WrongSecretKind,
                "{kind:?}"
            );
            assert!(
                serde_json::from_str::<InteractionDigest>(&json).is_err(),
                "{json}"
            );
        }
    }

    #[test]
    fn serde_round_trip_preserves_digest() {
        let value =
            InteractionDigest::try_new(Digest::new(SecretKind::InteractionHandle, [0xa5; 32]))
                .unwrap();
        let json = serde_json::to_string(&value).unwrap();
        assert_eq!(
            serde_json::from_str::<InteractionDigest>(&json).unwrap(),
            value
        );
    }

    #[test]
    fn deserialization_rejects_invalid_byte_lengths() {
        for len in [0, 31, 33] {
            let json = serde_json::json!({
                "_kind": "InteractionHandle",
                "_bytes": vec![0xa5_u8; len],
            });
            assert!(
                serde_json::from_value::<InteractionDigest>(json).is_err(),
                "length {len}"
            );
        }
    }
}
