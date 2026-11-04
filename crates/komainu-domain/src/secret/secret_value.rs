use ddd_toolkit::Secret;

use crate::secret::SecretKind;

/// **English:**<br>
/// Holds a secret category and 32 raw secret bytes inside [`ddd_toolkit::Secret`].
///
/// This type stores supplied bytes; it does not generate randomness, hash them,
/// or enforce entropy requirements. [`Self::expose_bytes`] explicitly borrows the
/// plaintext bytes. Callers must protect copies they create and avoid logging them.
/// Unlike [`crate::secret::Digest`], this type does not implement Serde serialization.
///
/// **日本語:**<br>
/// 秘密値の種別と32バイトの生の秘密値を [`ddd_toolkit::Secret`] 内に保持します。
///
/// 渡されたバイト列を格納する型であり、乱数生成、ハッシュ計算、エントロピー要件の検証は
/// 行いません。[`Self::expose_bytes`] は平文のバイト列を明示的に借用します。
/// 呼び出し元は作成したコピーを保護し、ログへの出力を避ける必要があります。
/// [`crate::secret::Digest`] と異なり、Serde のシリアライズは実装していません。
///
/// # Example / 使用例
/// ```rust
/// use komainu_domain::secret::{SecretKind, SecretValue};
///
/// let secret = SecretValue::new(SecretKind::ClientSecret, [7; 32]);
/// assert_eq!(secret.kind(), SecretKind::ClientSecret);
/// assert_eq!(secret.expose_bytes(), &[7; 32]);
/// ```
#[derive(ddd_toolkit::ValueObject)]
#[value_object(trait_only)]
pub struct SecretValue {
    _kind: SecretKind,
    _bytes: Secret<[u8; 32]>,
}

impl SecretValue {
    /// **English:**<br>
    /// Wraps `bytes` in [`ddd_toolkit::Secret`] and retains `kind` without validation.
    /// Every 32-byte array is accepted; the caller must supply suitable secret material.
    ///
    /// The owned bytes are zeroized when the inner [`ddd_toolkit::Secret`] is dropped.
    /// Because `[u8; 32]` is [`Copy`], passing an array here does not erase the caller's
    /// original array. Neither pre-existing copies nor copies created later are zeroized
    /// by this wrapper; callers must manage their protection and any required zeroization.
    ///
    /// **日本語:**<br>
    /// `bytes` を [`ddd_toolkit::Secret`] で包み、`kind` を検証せず保持します。
    /// すべての32バイト配列を受理するため、適切な秘密値の用意は呼び出し元の責任です。
    ///
    /// 所有するバイト列は、内部の [`ddd_toolkit::Secret`] が破棄される際にゼロ化されます。
    /// `[u8; 32]` は [`Copy`] なので、配列をここへ渡しても呼び出し元の元の配列は消去されません。
    /// 構築前から存在するコピーも、後から作成したコピーも、このラッパーではゼロ化されません。
    /// それらの保護と、必要に応じたゼロ化は呼び出し元が管理する必要があります。
    pub fn new(kind: SecretKind, bytes: [u8; 32]) -> Self {
        SecretValue {
            _kind: kind,
            _bytes: Secret::new(bytes),
        }
    }

    /// **English:**<br>
    /// Copies the secret's category without exposing its bytes.
    ///
    /// **日本語:**<br>
    /// バイト列を公開せず、秘密値の種別をコピーして返します。
    pub fn kind(&self) -> SecretKind {
        self._kind
    }

    /// **English:**<br>
    /// Borrows the plaintext secret bytes for at most the lifetime of `self`.
    /// No copy is made here; any copies made by the caller need separate protection.
    ///
    /// **日本語:**<br>
    /// `self` の寿命を超えない参照で、平文の秘密値のバイト列を借用します。
    /// この操作ではコピーしません。呼び出し元が作成するコピーは別途保護が必要です。
    pub fn expose_bytes(&self) -> &[u8; 32] {
        self._bytes.as_inner()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construction_preserves_kind_and_exposes_original_bytes() {
        for kind in [
            SecretKind::AuthorizationCode,
            SecretKind::AccessToken,
            SecretKind::RefreshToken,
            SecretKind::ClientSecret,
            SecretKind::InteractionHandle,
            SecretKind::BrowserBinding,
        ] {
            for bytes in [[0; 32], [0xff; 32], std::array::from_fn(|i| i as u8)] {
                let value = SecretValue::new(kind, bytes);
                assert_eq!(value.kind(), kind);
                assert_eq!(value.expose_bytes(), &bytes);
            }
        }
    }
}
