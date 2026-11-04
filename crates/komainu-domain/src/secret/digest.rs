use crate::secret::SecretKind;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

/// **English:**<br>
/// Stores a secret category and 32 caller-supplied digest bytes.
///
/// No hashing, randomness generation, or algorithm validation is performed.
/// Equality requires matching kinds and compares the bytes with
/// [`subtle::ConstantTimeEq`]; the kind comparison is not constant-time.
/// `Debug`, Serde serialization, and [`Self::expose_bytes`] reveal the digest bytes.
/// Serde uses fields `_kind` and `_bytes`; deserialization requires a known
/// [`SecretKind`] and exactly 32 bytes.
///
/// **日本語:**<br>
/// 秘密値の種別と、呼び出し元が渡した32バイトのダイジェストを保持します。
///
/// ハッシュ計算、乱数生成、アルゴリズムの検証は行いません。
/// 等値判定は種別の一致を要求し、バイト列を [`subtle::ConstantTimeEq`] で比較します。
/// 種別の比較は定数時間ではありません。
/// `Debug`、Serde のシリアライズ、[`Self::expose_bytes`] はダイジェストのバイト列を公開します。
/// Serde は `_kind` と `_bytes` フィールドを使用し、デシリアライズには既知の
/// [`SecretKind`] と正確に32バイトの列が必要です。
///
/// # Example / 使用例
/// ```rust
/// use komainu_domain::secret::{Digest, SecretKind};
///
/// let digest = Digest::new(SecretKind::AccessToken, [7; 32]);
/// assert_eq!(digest.kind(), SecretKind::AccessToken);
/// assert_eq!(digest.expose_bytes(), &[7; 32]);
/// assert_ne!(digest, Digest::new(SecretKind::RefreshToken, [7; 32]));
/// let json = serde_json::to_string(&digest).unwrap();
/// assert_eq!(serde_json::from_str::<Digest>(&json).unwrap(), digest);
/// ```
#[derive(ddd_toolkit::ValueObject, Clone, Debug, Eq, Hash, Serialize, Deserialize)]
#[value_object(trait_only)]
pub struct Digest {
    _kind: SecretKind,
    _bytes: [u8; 32],
}

impl Digest {
    /// **English:**<br>
    /// Stores `kind` and `bytes` unchanged, accepting every 32-byte array, including zeros.
    /// Does not compute a digest or verify how the bytes were produced.
    ///
    /// **日本語:**<br>
    /// `kind` と `bytes` を変更せず保持し、ゼロを含むすべての32バイト配列を受理します。
    /// ダイジェストの計算や、バイト列の生成方法の検証は行いません。
    pub fn new(kind: SecretKind, bytes: [u8; 32]) -> Self {
        Self {
            _kind: kind,
            _bytes: bytes,
        }
    }

    /// **English:**<br>
    /// Returns a copy of the category supplied at construction.
    ///
    /// **日本語:**<br>
    /// 構築時に指定された種別のコピーを返します。
    pub fn kind(&self) -> SecretKind {
        self._kind
    }

    /// **English:**<br>
    /// Borrows the stored digest bytes without copying or transforming them.
    /// The reference cannot outlive this digest; callers control any further disclosure.
    ///
    /// **日本語:**<br>
    /// 保持するダイジェストのバイト列をコピーや変換せず借用します。
    /// 参照の寿命はこの値を超えず、以後の公開範囲は呼び出し元が管理します。
    pub fn expose_bytes(&self) -> &[u8; 32] {
        &self._bytes
    }
}

impl PartialEq for Digest {
    fn eq(&self, other: &Self) -> bool {
        let bytes_equal = self._bytes.ct_eq(&other._bytes);

        self._kind == other._kind && bool::from(bytes_equal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KINDS: [SecretKind; 6] = [
        SecretKind::AuthorizationCode,
        SecretKind::AccessToken,
        SecretKind::RefreshToken,
        SecretKind::ClientSecret,
        SecretKind::InteractionHandle,
        SecretKind::BrowserBinding,
    ];

    #[test]
    fn construction_preserves_kind_and_bytes() {
        for kind in KINDS {
            for bytes in [[0; 32], [0xff; 32], std::array::from_fn(|i| i as u8)] {
                let digest = Digest::new(kind, bytes);
                assert_eq!(digest.kind(), kind);
                assert_eq!(digest.expose_bytes(), &bytes);
            }
        }
    }

    #[test]
    fn equality_accepts_same_kind_and_bytes() {
        for kind in KINDS {
            let left = Digest::new(kind, [0xa5; 32]);
            let right = Digest::new(kind, [0xa5; 32]);
            assert_eq!(left, right);
            assert_eq!(right, left);
        }
    }

    // Functional coverage only: these assertions do not prove constant-time execution.
    #[test]
    fn equality_rejects_a_difference_at_every_byte_position() {
        for kind in KINDS {
            let original = Digest::new(kind, [0xa5; 32]);
            for index in 0..32 {
                let mut bytes = [0xa5; 32];
                bytes[index] ^= 1;
                let different = Digest::new(kind, bytes);
                assert_ne!(original, different, "{kind:?}, byte {index}");
                assert_ne!(different, original, "{kind:?}, byte {index}");
            }
        }
    }

    #[test]
    fn equality_rejects_different_kinds_with_same_bytes() {
        for left in KINDS {
            for right in KINDS {
                assert_eq!(
                    Digest::new(left, [0xa5; 32]) == Digest::new(right, [0xa5; 32]),
                    left == right,
                    "{left:?}, {right:?}"
                );
            }
        }
    }

    #[test]
    fn serde_round_trip_preserves_kind_and_bytes() {
        for kind in KINDS {
            let bytes = std::array::from_fn(|i| i as u8);
            let digest = Digest::new(kind, bytes);
            let json = serde_json::to_value(&digest).unwrap();
            assert_eq!(json, serde_json::json!({ "_kind": kind, "_bytes": bytes }));
            let restored = serde_json::from_value::<Digest>(json).unwrap();
            assert_eq!(restored.kind(), kind);
            assert_eq!(restored.expose_bytes(), &bytes);
        }
    }

    #[test]
    fn deserialization_rejects_invalid_byte_lengths() {
        for kind in KINDS {
            for len in [0, 31, 33] {
                let json = serde_json::json!({
                    "_kind": kind,
                    "_bytes": vec![0xa5_u8; len],
                });
                assert!(
                    serde_json::from_value::<Digest>(json).is_err(),
                    "{kind:?}, length {len}"
                );
            }
        }
    }

    #[test]
    fn deserialization_rejects_missing_fields_and_invalid_values() {
        for json in [
            serde_json::json!({}),
            serde_json::json!({ "_kind": "AccessToken" }),
            serde_json::json!({ "_bytes": vec![0; 32] }),
            serde_json::json!({ "_kind": "Unknown", "_bytes": vec![0; 32] }),
            serde_json::json!({ "_kind": "AccessToken", "_bytes": vec![-1; 32] }),
            serde_json::json!({ "_kind": "AccessToken", "_bytes": vec![256; 32] }),
        ] {
            assert!(
                serde_json::from_value::<Digest>(json.clone()).is_err(),
                "{json}"
            );
        }
    }
}
