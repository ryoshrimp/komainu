/// **English:**<br>
/// Tags raw secrets and digests with their intended protocol role.
///
/// Serde uses the exact variant names, such as `"AccessToken"`, and rejects
/// unknown names. A tag does not verify the origin or contents of the associated bytes.
///
/// **日本語:**<br>
/// 生の秘密値とダイジェストに、意図したプロトコル上の役割を付けます。
///
/// Serde は `"AccessToken"` などの正確なバリアント名を使用し、未知の名前を拒否します。
/// 種別自体は、対応するバイト列の出所や内容を検証しません。
///
/// # Example / 使用例
/// ```rust
/// use komainu_domain::secret::SecretKind;
///
/// let json = serde_json::to_string(&SecretKind::AccessToken).unwrap();
/// assert_eq!(json, r#""AccessToken""#);
/// assert!(serde_json::from_str::<SecretKind>(r#""access_token""#).is_err());
/// ```
#[derive(ddd_toolkit::ValueObject, Copy)]
#[value_object(serde)]
pub enum SecretKind {
    /// **English:**<br>
    /// Marks an authorization code exchanged at the token endpoint.
    ///
    /// **日本語:**<br>
    /// トークンエンドポイントで交換する認可コードを表します。
    AuthorizationCode,
    /// **English:**<br>
    /// Marks an access token used to authorize resource access.
    ///
    /// **日本語:**<br>
    /// リソースへのアクセスを認可するアクセストークンを表します。
    AccessToken,
    /// **English:**<br>
    /// Marks a refresh token used to request replacement tokens.
    ///
    /// **日本語:**<br>
    /// トークンの再発行を要求するリフレッシュトークンを表します。
    RefreshToken,
    /// **English:**<br>
    /// Marks a client's authentication secret.
    ///
    /// **日本語:**<br>
    /// クライアントの認証用秘密値を表します。
    ClientSecret,
    /// **English:**<br>
    /// Marks a handle identifying an interaction.
    ///
    /// **日本語:**<br>
    /// 対話を識別するハンドルを表します。
    InteractionHandle,
    /// **English:**<br>
    /// Marks secret material for binding an interaction to a browser.
    ///
    /// **日本語:**<br>
    /// 対話をブラウザーに結び付けるための秘密値を表します。
    BrowserBinding,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_round_trip_uses_variant_names() {
        for (kind, name) in [
            (SecretKind::AuthorizationCode, "AuthorizationCode"),
            (SecretKind::AccessToken, "AccessToken"),
            (SecretKind::RefreshToken, "RefreshToken"),
            (SecretKind::ClientSecret, "ClientSecret"),
            (SecretKind::InteractionHandle, "InteractionHandle"),
            (SecretKind::BrowserBinding, "BrowserBinding"),
        ] {
            let json = serde_json::to_value(kind).unwrap();
            assert_eq!(json, serde_json::json!(name));
            assert_eq!(serde_json::from_value::<SecretKind>(json).unwrap(), kind);
        }
    }

    #[test]
    fn deserialization_rejects_unknown_names_and_non_strings() {
        for json in [r#""Unknown""#, r#""access_token""#, "null", "0", "[]"] {
            assert!(serde_json::from_str::<SecretKind>(json).is_err(), "{json}");
        }
    }
}
