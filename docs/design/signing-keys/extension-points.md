# 拡張ポイント: グラント種別とクライアント認証方式

[README](README.md) に戻る。

## 責務・配置・関連要件

- 配置: 新規 `crates/application/src/token/grant.rs`、新規 `crates/application/src/token/auth.rs`、`crates/application/src/token/mod.rs`、`crates/application/src/capabilities.rs`、`crates/application/src/config.rs`、`crates/application/src/admin/{mod.rs,error.rs}`
- 責務: トークンエンドポイントの `grant_type` の振り分けと、`/token` `/revoke` のクライアント認証の振り分けを、ハンドラーの登録で行う。メタデータの supported 一覧を登録内容から作る。設定による無効化
- 関連要件: F-10、F-11、F-12、F-13
- 可視性: trait・レジストリ・ハンドラーはすべて `pub(crate)`。公開 API に増えるのは、`ApplicationConfig` の 2 フィールドと `with_disabled_grant_types` / `with_disabled_auth_methods`、`ApplicationConfigError` の 2 バリアント（型と `validate` 自体は T4 で作る）、`AdminError` の 2 バリアントだけ

## レジストリ

### 公開インターフェース（crate 内）

```rust
// token/grant.rs

/// One grant type of the token endpoint.
pub(crate) trait GrantHandler: Send + Sync {
    /// 担当するグラント種別。`grant_type.as_str()` が `grant_type` パラメーターの値。
    fn grant_type(&self) -> GrantType;
    /// この設定で使えるか（例: jwt-bearer は `config.issuer.is_some()`）。
    /// false なら一覧に出さず、リクエストには `unsupported_grant_type`（クライアント認証の前に判定）。
    fn is_available(&self, config: &ApplicationConfig) -> bool;
    /// クライアント認証と `client.supports_grant` の確認が済んだあとに呼ばれる。
    fn handle<'a>(
        &'a self,
        service: &'a TokenService,
        ctx: &'a RequestContext,
        uow: &'a mut dyn UnitOfWork,
        client: &'a Client,
        request: &'a TokenRequest,
    ) -> BoxFuture<'a, Result<Step, TokenError>>;
}

pub(crate) struct GrantRegistry { handlers: Vec<Box<dyn GrantHandler>> }

impl GrantRegistry {
    /// 組み込みのハンドラーを次の順で登録し、`config.disabled_grant_types` にあるものを除く:
    /// authorization_code, client_credentials, refresh_token, jwt-bearer
    pub(crate) fn builtin(config: &ApplicationConfig) -> Self;
    /// `grant_type` パラメーターの値で探す。登録が無い・is_available が false なら None。
    pub(crate) fn find(&self, grant_type: &str, config: &ApplicationConfig) -> Option<&dyn GrantHandler>;
    /// 登録が有り is_available が true のもの（登録順）。
    pub(crate) fn available(&self, config: &ApplicationConfig) -> Vec<GrantType>;
    /// 登録されているか（無効化されていないか）。is_available は見ない。
    pub(crate) fn is_registered(&self, grant_type: GrantType) -> bool;
}
```

```rust
// token/auth.rs

/// How the client presented its credentials, as one of the auth methods.
pub(crate) fn presented_method(auth: &ClientAuthentication) -> Option<TokenEndpointAuthMethod>;
// Basic → ClientSecretBasic, Post → ClientSecretPost, PublicId → None(=TokenEndpointAuthMethod::None),
// Assertion → PrivateKeyJwt, ClientAuthentication::None → None（Option の None）

/// One client authentication method of `/token` and `/revoke`.
pub(crate) trait ClientAuthMethod: Send + Sync {
    fn method(&self) -> TokenEndpointAuthMethod;
    /// 一覧に出すか（none は `config.allow_public_clients`、private_key_jwt は `config.issuer.is_some()`、
    /// basic・post は常に true）。認証の可否はこれではなく authenticate 内の従来の判定で決める（下記）。
    fn is_available(&self, config: &ApplicationConfig) -> bool;
    /// `*_auth_signing_alg_values_supported` に出す値。private_key_jwt は [Rs256, Es256]、他は []。
    fn signing_algs(&self) -> &'static [Algorithm];
    /// `presented_method(auth) == Some(self.method())` のときだけ呼ばれる。
    /// 成功ならリクエストの UoW と認証済みクライアント。失敗時の監査もここで行う（従来どおり）。
    fn authenticate<'a>(
        &'a self,
        service: &'a TokenService,
        ctx: &'a RequestContext,
        auth: &'a ClientAuthentication,
        endpoint: Endpoint,
    ) -> BoxFuture<'a, Result<(Box<dyn UnitOfWork>, Client), TokenError>>;
}

pub(crate) struct AuthMethodRegistry { methods: Vec<Box<dyn ClientAuthMethod>> }

impl AuthMethodRegistry {
    /// 組み込みを次の順で登録し、`config.disabled_auth_methods` にあるものを除く:
    /// client_secret_basic, client_secret_post, private_key_jwt, none
    pub(crate) fn builtin(config: &ApplicationConfig) -> Self;
    pub(crate) fn find(&self, method: TokenEndpointAuthMethod) -> Option<&dyn ClientAuthMethod>;
    /// 登録が有り is_available が true のもの（登録順）。
    pub(crate) fn available(&self, config: &ApplicationConfig) -> Vec<TokenEndpointAuthMethod>;
    /// available のものの signing_algs の和集合（Rs256, Es256 の順で重複なし）。
    pub(crate) fn signing_algs(&self, config: &ApplicationConfig) -> Vec<Algorithm>;
    pub(crate) fn is_registered(&self, method: TokenEndpointAuthMethod) -> bool;
}
```

- `Step`・`Endpoint` は今 `token/mod.rs` の private な型。`pub(crate)`（または `pub(super)`）に上げる。
- `TokenService` は `#[derive(Clone)]` のまま、`TokenService { deps, grants: Arc<GrantRegistry>, auth_methods: Arc<AuthMethodRegistry> }` とし、`new` で `Arc::new(GrantRegistry::builtin(&deps.config))` / `Arc::new(AuthMethodRegistry::builtin(&deps.config))` を作って持つ。
- T5 の時点の `builtin` は組み込みをすべて登録する（`disabled_*` のフィールドがまだ無い）。除外は T6 で足す。

### 振る舞い

`exchange`:

1. `duplicated` が空でない → `InvalidRequest`（従来どおり）。
2. `grant_type` が無い → `InvalidRequest`。`registry.find(grant_type, config)` が None → `UnsupportedGrantType`。
3. `authenticate_client`（下記）。
4. `!client.supports_grant(handler.grant_type())` → `UnauthorizedClient`（従来どおり）。
5. `handler.handle(..)` の `Step` を従来どおり処理する。

`authenticate_client(ctx, auth, endpoint)`:

1. `presented_method(auth)` が None（資格情報なし）→ 従来どおり method `"missing"` で監査して `InvalidClient { basic_attempted: false }`。
2. `registry.find(method)` が None（無効化されている）→ method `method.as_str()`、reason `"method_disabled"`、`client_id_presented` は提示された値（Assertion なら body の `client_id`、無ければ `null`）で監査し、`InvalidClient { basic_attempted: method == ClientSecretBasic }`。
3. それ以外 → `handler.authenticate(..)`。各ハンドラーの中身は今の `authenticate_client` / `authenticate_assertion` の該当部分そのもの（`none` の `client_type == Public && allow_public_clients` の確認、`private_key_jwt` の `not_configured` などもそのまま）。

ハンドラーの実装は既存の `TokenService` の private メソッド（`authorization_code`、`client_credentials`、`refresh_token`、`jwt_bearer`、`authenticate_assertion` など）を `pub(super)` にして呼ぶだけでよい。メソッド本体を別ファイルへ移す必要はない。

### 受け入れ条件（レジストリ）

- 既存のテスト（`crates/application/tests/`、`crates/http/tests/`、`crates/server/tests/`）が変更なしで通る。
- `GrantRegistry::builtin(&ApplicationConfig::default()).available(..)` が `[AuthorizationCode, ClientCredentials, RefreshToken]`、issuer ありで末尾に `JwtBearer`。
- `AuthMethodRegistry` の `available` が既定で `[ClientSecretBasic, ClientSecretPost]`、issuer ありで `PrivateKeyJwt` が 3 番目に入り、`allow_public_clients = true` で末尾に `None`。`signing_algs` が issuer ありで `[Rs256, Es256]`、無しで `[]`。

## ServerCapabilities

`ServerCapabilities::from_config(&ApplicationConfig)` のシグネチャは変えず、中で `GrantRegistry::builtin(config)` / `AuthMethodRegistry::builtin(config)` を作って次を埋める。

| フィールド | 中身 |
|------------|------|
| `grant_types` | `GrantRegistry::available` |
| `token_endpoint_auth_methods` | `AuthMethodRegistry::available` |
| `revocation_endpoint_auth_methods` | 同上（`/revoke` は `/token` と同じ認証を使う） |
| `token_endpoint_auth_signing_algs` | `AuthMethodRegistry::signing_algs` |
| `revocation_endpoint_auth_signing_algs` | 同上 |
| `response_types` ほか | 従来どおり |

`ServerCapabilities` の doc の「一覧を明示的に書いている」説明は「レジストリから作る」に直す。

## 無効化

### 設定（`crates/application/src/config.rs`）

```rust
pub struct ApplicationConfig {
    // …
    /// Grant types turned off. `AuthorizationCode` must not be included (`validate` で検出).
    pub disabled_grant_types: BTreeSet<GrantType>,
    /// Client authentication methods turned off.
    pub disabled_auth_methods: BTreeSet<TokenEndpointAuthMethod>,
}
impl ApplicationConfig {
    pub fn with_disabled_grant_types(mut self, value: BTreeSet<GrantType>) -> Self;
    pub fn with_disabled_auth_methods(mut self, value: BTreeSet<TokenEndpointAuthMethod>) -> Self;
    /// 組み合わせの検証。builder の build と server の設定検証から呼ぶ。
    pub fn validate(&self) -> Result<(), ApplicationConfigError>;
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ApplicationConfigError {
    #[error("authorization_code cannot be disabled")]
    AuthorizationCodeDisabled,
    #[error("at least one client authentication method must stay enabled")]
    NoAuthMethod,
    // T4 で作る（署名の設定。README §4「設定の検証」）
    #[error("signing retire overlap must be at least the access token lifetime")]
    RetireOverlapTooShort,
}
```

`validate` の規則: `disabled_grant_types` に `AuthorizationCode` → `AuthorizationCodeDisabled`。`AuthMethodRegistry::builtin(self).available(self)` が空 → `NoAuthMethod`。`signing` が Some で `policy.retire_overlap() < access_token_ttl` → `RetireOverlapTooShort`（T4）。検査はこの順で、最初の違反を返す。既定値は Ok。

### 振る舞い

- `/token` の `grant_type` が無効化された種別 → `unsupported_grant_type`（`GrantRegistry::find` が None になるため。クライアント認証より前）。
- `refresh_token` を無効化 → トークン発行（`issue_tokens`）でリフレッシュトークンを出さない。条件を `client.supports_grant(RefreshToken) && grants.is_registered(RefreshToken)` にする。
- 無効化された認証方式での `/token` `/revoke` → `invalid_client`（§レジストリの手順 2）。`/revoke` の `RevocationError` への変換は従来どおり。
- `AdminService`（クライアントの登録・更新）:
  - `auth_method` が `disabled_auth_methods` にある → `AdminError::AuthMethodDisabled(method)`。
  - `grant_types` に `disabled_grant_types` のものがある → `AdminError::GrantTypeDisabled(grant)`（最初に見つかったもの、`BTreeSet` の順）。
  - この 2 つの確認は既存の `PublicClientsDisabled` などの確認より前に行う。既存の確認は変えない。
  - 既存のクライアントは変更しない（起動時に一括で無効にしたりはしない）。

```rust
// crates/application/src/admin/error.rs
#[error("client authentication method is disabled: {}", .0.as_str())]
AuthMethodDisabled(TokenEndpointAuthMethod),
#[error("grant type is disabled: {}", .0.as_str())]
GrantTypeDisabled(GrantType),
```

CLI（`crates/server/src/cli/mod.rs` の `admin_exit`）は網羅的な `match` なので、このタスク（T6）で 2 つの変換を足す。`Invalid` と同じ `Exit::usage`（入力の誤り）にする。

### 受け入れ条件（無効化）

- `disabled_grant_types = {ClientCredentials}`: `server_capabilities().grant_types` に `ClientCredentials` が無い。client_credentials を許可されたクライアントの `grant_type=client_credentials` が `UnsupportedGrantType`。`grant_types` に `ClientCredentials` を含むクライアントの登録が `GrantTypeDisabled(ClientCredentials)`。
- `disabled_grant_types = {RefreshToken}`: 認可コード交換の応答に `refresh_token` が無い。`grant_type=refresh_token` が `UnsupportedGrantType`。
- `disabled_auth_methods = {ClientSecretPost}`: `token_endpoint_auth_methods` / `revocation_endpoint_auth_methods` に無い。post で認証する正しいクライアントの `/token` が `InvalidClient { basic_attempted: false }`、監査に `method = client_secret_post`・`reason = method_disabled`。`/revoke` も `invalid_client`。その方式でのクライアント登録が `AuthMethodDisabled(ClientSecretPost)`。
- `disabled_auth_methods = {ClientSecretBasic}`: basic での `/token` が `InvalidClient { basic_attempted: true }`（HTTP では 401 + `WWW-Authenticate`）。
- `validate`: `AuthorizationCode` を含む → `AuthorizationCodeDisabled`。basic と post を無効化し、issuer なし・public 不可 → `NoAuthMethod`。
