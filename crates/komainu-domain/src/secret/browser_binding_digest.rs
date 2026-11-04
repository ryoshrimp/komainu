use crate::{
    error::DomainError,
    secret::{Digest, SecretKind},
    shared::validate_digest_kind,
};

fn validate_browser_binding_digest(_digest: &Digest) -> Result<(), DomainError> {
    validate_digest_kind(&_digest.kind(), &SecretKind::BrowserBinding)
}

/// **English:**<br>
/// Holds a browser-binding digest tagged [`SecretKind::BrowserBinding`].
///
/// [`Self::try_new`] returns [`DomainError::WrongSecretKind`] for a different tag;
/// otherwise it stores the supplied [`Digest`] unchanged. [`Self::as_inner`] borrows it.
/// Serde serializes the inner `_kind` and `_bytes` fields directly and checks the tag
/// during deserialization. Invalid tags or malformed digests produce deserializer errors.
/// This value alone does not verify a browser binding or compute a digest.
///
/// **日本語:**<br>
/// [`SecretKind::BrowserBinding`] の種別を持つブラウザーバインディングのダイジェストです。
///
/// [`Self::try_new`] は種別が異なれば [`DomainError::WrongSecretKind`] を返し、
/// 一致すれば渡された [`Digest`] をそのまま保持します。[`Self::as_inner`] は内部値を借用します。
/// Serde は内部の `_kind` と `_bytes` を直接シリアライズし、デシリアライズ時に種別を検証します。
/// 不正な種別や形式のダイジェストはデシリアライザーのエラーになります。
/// この値だけではブラウザーとの結び付きを検証せず、ダイジェストも計算しません。
///
/// # Example / 使用例
/// ```rust
/// use komainu_domain::{error::DomainError, secret::{BrowserBindingDigest, Digest, SecretKind}};
///
/// let digest = Digest::new(SecretKind::BrowserBinding, [7; 32]);
/// let binding = BrowserBindingDigest::try_new(digest.clone()).unwrap();
/// assert_eq!(binding.as_inner(), &digest);
/// assert_eq!(BrowserBindingDigest::try_new(Digest::new(SecretKind::InteractionHandle, [7; 32])),
///            Err(DomainError::WrongSecretKind));
/// let json = serde_json::to_string(&binding).unwrap();
/// assert_eq!(serde_json::from_str::<BrowserBindingDigest>(&json).unwrap(), binding);
/// ```
#[derive(ddd_toolkit::ValueObject)]
#[value_object(validate = validate_browser_binding_digest, error = DomainError, serde)]
pub struct BrowserBindingDigest {
    _digest: Digest,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construction_preserves_digest() {
        let digest = Digest::new(SecretKind::BrowserBinding, [0xa5; 32]);
        let value = BrowserBindingDigest::try_new(digest.clone()).unwrap();
        assert_eq!(value.as_inner(), &digest);
    }

    #[test]
    fn construction_and_deserialization_reject_other_kinds() {
        for kind in [
            SecretKind::AuthorizationCode,
            SecretKind::AccessToken,
            SecretKind::RefreshToken,
            SecretKind::ClientSecret,
            SecretKind::InteractionHandle,
        ] {
            let digest = Digest::new(kind, [0xa5; 32]);
            let json = serde_json::to_string(&digest).unwrap();
            assert_eq!(
                BrowserBindingDigest::try_new(digest).unwrap_err(),
                DomainError::WrongSecretKind,
                "{kind:?}"
            );
            assert!(
                serde_json::from_str::<BrowserBindingDigest>(&json).is_err(),
                "{json}"
            );
        }
    }

    #[test]
    fn serde_round_trip_preserves_digest() {
        let value =
            BrowserBindingDigest::try_new(Digest::new(SecretKind::BrowserBinding, [0xa5; 32]))
                .unwrap();
        let json = serde_json::to_string(&value).unwrap();
        assert_eq!(
            serde_json::from_str::<BrowserBindingDigest>(&json).unwrap(),
            value
        );
    }

    #[test]
    fn deserialization_rejects_invalid_byte_lengths() {
        for len in [0, 31, 33] {
            let json = serde_json::json!({
                "_kind": "BrowserBinding",
                "_bytes": vec![0xa5_u8; len],
            });
            assert!(
                serde_json::from_value::<BrowserBindingDigest>(json).is_err(),
                "length {len}"
            );
        }
    }
}
