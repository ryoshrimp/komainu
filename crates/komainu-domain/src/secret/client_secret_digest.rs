use crate::{
    error::DomainError,
    secret::{Digest, SecretKind},
    shared::validate_digest_kind,
};

fn validate_client_secret_digest(_digest: &Digest) -> Result<(), DomainError> {
    validate_digest_kind(&_digest.kind(), &SecretKind::ClientSecret)
}

/// **English:**<br>
/// Represents a client-secret digest with the tag [`SecretKind::ClientSecret`].
///
/// [`Self::try_new`] rejects all other tags with [`DomainError::WrongSecretKind`]
/// and otherwise retains the [`Digest`] unchanged. [`Self::as_inner`] borrows that digest.
/// Serde exposes the inner `_kind` and `_bytes` fields and revalidates the tag when
/// deserializing; invalid input becomes a deserializer error. Construction does not
/// authenticate a client or check how the digest was computed.
///
/// **日本語:**<br>
/// [`SecretKind::ClientSecret`] を付けたクライアント秘密値のダイジェストを表します。
///
/// [`Self::try_new`] は他の種別を [`DomainError::WrongSecretKind`] で拒否し、
/// 一致する [`Digest`] をそのまま保持します。[`Self::as_inner`] はその値を借用します。
/// Serde は内部の `_kind` と `_bytes` を出力し、デシリアライズ時に種別を再検証します。
/// 不正な入力はデシリアライザーのエラーになります。構築によってクライアントを認証したり、
/// ダイジェストの計算方法を検証したりすることはありません。
///
/// # Example / 使用例
/// ```rust
/// use komainu_domain::{error::DomainError, secret::{ClientSecretDigest, Digest, SecretKind}};
///
/// let value = ClientSecretDigest::try_new(Digest::new(SecretKind::ClientSecret, [7; 32])).unwrap();
/// assert_eq!(value.as_inner().expose_bytes(), &[7; 32]);
/// assert_eq!(ClientSecretDigest::try_new(Digest::new(SecretKind::AccessToken, [7; 32])),
///            Err(DomainError::WrongSecretKind));
/// let json = serde_json::to_string(&value).unwrap();
/// assert_eq!(serde_json::from_str::<ClientSecretDigest>(&json).unwrap(), value);
/// ```
#[derive(ddd_toolkit::ValueObject)]
#[value_object(validate = validate_client_secret_digest, error = DomainError, serde)]
pub struct ClientSecretDigest {
    _digest: Digest,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construction_preserves_digest() {
        let digest = Digest::new(SecretKind::ClientSecret, [0xa5; 32]);
        let value = ClientSecretDigest::try_new(digest.clone()).unwrap();
        assert_eq!(value.as_inner(), &digest);
    }

    #[test]
    fn construction_and_deserialization_reject_other_kinds() {
        for kind in [
            SecretKind::AuthorizationCode,
            SecretKind::AccessToken,
            SecretKind::RefreshToken,
            SecretKind::InteractionHandle,
            SecretKind::BrowserBinding,
        ] {
            let digest = Digest::new(kind, [0xa5; 32]);
            let json = serde_json::to_string(&digest).unwrap();
            assert_eq!(
                ClientSecretDigest::try_new(digest).unwrap_err(),
                DomainError::WrongSecretKind,
                "{kind:?}"
            );
            assert!(
                serde_json::from_str::<ClientSecretDigest>(&json).is_err(),
                "{json}"
            );
        }
    }

    #[test]
    fn serde_round_trip_preserves_digest() {
        let value =
            ClientSecretDigest::try_new(Digest::new(SecretKind::ClientSecret, [0xa5; 32])).unwrap();
        let json = serde_json::to_string(&value).unwrap();
        assert_eq!(
            serde_json::from_str::<ClientSecretDigest>(&json).unwrap(),
            value
        );
    }

    #[test]
    fn deserialization_rejects_invalid_byte_lengths() {
        for len in [0, 31, 33] {
            let json = serde_json::json!({
                "_kind": "ClientSecret",
                "_bytes": vec![0xa5_u8; len],
            });
            assert!(
                serde_json::from_value::<ClientSecretDigest>(json).is_err(),
                "length {len}"
            );
        }
    }
}
