# komainu（ファサード crate）

- 責務: 各 crate の公開 API を feature ごとに再エクスポートし、部品を注入して `Komainu`（サービス群と `Router`）を組み立てる builder を提供する。ビジネスルール・HTTP の処理・永続化は持たない
- 配置: `crates/komainu`
- 関連要件: F-1〜F-5、N-3、N-5

## 公開インターフェース

### Cargo.toml

```toml
[package]
name = "komainu"
description = "An embeddable OAuth 2.0 authorization server"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true

[features]
default = ["http", "postgres", "std"]
http = ["dep:komainu-http", "dep:axum"]
postgres = ["dep:komainu-adapter-postgres"]
std = ["dep:komainu-adapter-std"]

[dependencies]
komainu-domain.workspace = true
komainu-application.workspace = true
komainu-http = { workspace = true, optional = true }
axum = { workspace = true, optional = true }
komainu-adapter-postgres = { workspace = true, optional = true }
komainu-adapter-std = { workspace = true, optional = true }
thiserror.workspace = true

[[example]]
name = "minimal"
required-features = ["http", "postgres", "std"]

[[example]]
name = "custom_screens"
required-features = ["http", "std"]

[dev-dependencies]
komainu-testkit.workspace = true
tokio = { workspace = true, features = ["macros", "rt-multi-thread", "net"] }
tower.workspace = true
http-body-util.workspace = true
time.workspace = true        # FixedClock と ApplicationConfig の TTL に OffsetDateTime / Duration が要り、komainu は time を再エクスポートしないため
serde_json.workspace = true  # トークン応答の JSON を読むため
```

ルートの `Cargo.toml` の `members` と `[workspace.dependencies]` に `crates/komainu` を足す。

### 再エクスポート（`src/lib.rs`）

```rust
pub use komainu_domain as domain;
pub use komainu_application as application;
#[cfg(feature = "std")]
pub use komainu_adapter_std as adapter_std;
#[cfg(feature = "postgres")]
pub use komainu_adapter_postgres as adapter_postgres;
#[cfg(feature = "http")]
pub use komainu_http as http;

pub use builder::{BuildError, Komainu, KomainuBuilder};
```

crate ごとモジュールとして再エクスポートする（`pub use komainu_x as x`）。`*` での展開はしない（名前の衝突を避け、どの crate の型かを利用者が分かるようにするため）。利用者が `axum` を別に依存に入れなくて済むよう、`#[cfg(feature = "http")] pub use komainu_http::axum;` は**しない**（axum の版を利用者が選ぶとき衝突するため。利用者は axum 0.8 を自分で依存に入れる。rustdoc に版を明記する）。

### Komainu と KomainuBuilder（`src/builder.rs`）

```rust
/// The assembled use-case services (and, with the `http` feature, the router).
#[derive(Clone)]
pub struct Komainu { /* private */ }

impl Komainu {
    pub fn builder() -> KomainuBuilder;

    pub fn authorization(&self) -> &AuthorizationService;
    pub fn token(&self) -> &TokenService;
    pub fn admin(&self) -> &AdminService;
    pub fn maintenance(&self) -> &MaintenanceService;

    /// All OAuth endpoints and screens with the middleware stack. Mount at "/" or nest it
    /// under the path of `public_base_url`.
    #[cfg(feature = "http")]
    pub fn router(&self) -> axum::Router;
}

#[must_use]
pub struct KomainuBuilder { /* private */ }

impl KomainuBuilder {
    /// Required.
    pub fn store(self, store: impl UnitOfWorkFactory + 'static) -> Self;
    pub fn store_arc(self, store: Arc<dyn UnitOfWorkFactory>) -> Self;

    /// Default: `ApplicationConfig::default()`.
    pub fn application_config(self, config: ApplicationConfig) -> Self;

    /// Default with `std`: `SystemClock`. Required without `std`.
    pub fn clock(self, clock: Arc<dyn Clock>) -> Self;
    /// Default with `std`: `OsSecureRandom`. Required without `std`.
    pub fn random(self, random: Arc<dyn SecureRandom>) -> Self;
    /// Default with `std`: `Argon2PasswordHasher::new()`. Required without `std`.
    pub fn password_hasher(self, hasher: Arc<dyn PasswordHasher>) -> Self;
    /// Default: `BuiltinAuthenticator::new(<the password hasher>)`.
    pub fn authenticator(self, authenticator: Arc<dyn ResourceOwnerAuthenticator>) -> Self;

    /// Required with `http`.
    #[cfg(feature = "http")]
    pub fn http_config(self, config: HttpConfig) -> Self;
    /// Default: `DefaultScreens`.
    #[cfg(feature = "http")]
    pub fn screens(self, screens: Arc<dyn ScreenRenderer>) -> Self;

    pub fn build(self) -> Result<Komainu, BuildError>;
}

#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("a store is required; call KomainuBuilder::store")]
    MissingStore,
    #[error("{0} is required when the `std` feature is disabled")]
    MissingComponent(&'static str),      // "clock" | "random" | "password_hasher"
    #[error("an HTTP configuration is required; call KomainuBuilder::http_config")]
    MissingHttpConfig,
    #[error("failed to initialize the password hasher: {0}")]
    PasswordHasher(#[source] Box<dyn std::error::Error + Send + Sync>),
}
```

- 型名は各 crate のもの（`komainu_application::{UnitOfWorkFactory, Clock, ...}`、`komainu_http::{HttpConfig, ScreenRenderer}`）。
- 各 setter は同じものを 2 回呼ぶと後の値で上書きする。`store` と `store_arc` は同じ枠を共有する。
- `Komainu` は `Clone`（中身は `Arc` とサービスの clone）。
- `router()` は呼ぶたびに `komainu_http::router(state.clone())` を返す。

## データ

なし。

## 振る舞い

`build()` は次の順で決める。

1. store がなければ `MissingStore`。
2. `std` が無効で clock・random・password_hasher のどれかがなければ、最初に見つかった欠けを `MissingComponent("clock" | "random" | "password_hasher")` で返す（この順で調べる）。
3. password_hasher が未指定で `std` が有効なら `Argon2PasswordHasher::new()` を呼び、失敗は `PasswordHasher(Box::new(e))`。
4. authenticator が未指定なら `BuiltinAuthenticator::new(password_hasher.clone())`。指定されていても、password_hasher は `Dependencies::password_hasher`（管理操作でのパスワード設定に使う）として残す。
5. `Dependencies { store, clock, random, password_hasher, authenticator, config: Arc::new(application_config) }` を作り、4 つのサービスを `new(deps.clone())` で作る。
6. `http` が有効なとき: http_config がなければ `MissingHttpConfig`。あれば `csrf_cookie_ttl` を `application_config.authorization_request_ttl` で上書きしてから `AppState::new(..).with_screens(screens)` を作って持つ。CSRF Cookie の寿命は認可リクエストの寿命と同じでなければならない（今の server と同じ）ので、利用者が `HttpConfig::with_csrf_cookie_ttl` で入れた値は使わない。このことを `KomainuBuilder::http_config` と `HttpConfig::with_csrf_cookie_ttl` の両方の rustdoc に書く（`with_csrf_cookie_ttl` は komainu-http を直接使う利用者のために残す）。

`build()` は I/O をしない（DB 接続・マイグレーションは利用者が先に済ませる）。

## エラー

| 状況 | 返すもの | 呼び出し側の扱い |
|---|---|---|
| store の未指定 | `BuildError::MissingStore` | プログラムの誤り。起動を止める |
| `std` 無効で部品の未指定 | `BuildError::MissingComponent(name)` | 同上 |
| `http` 有効で http_config の未指定 | `BuildError::MissingHttpConfig` | 同上 |
| Argon2 の初期化失敗 | `BuildError::PasswordHasher` | 起動を止める |

## 設定

builder の引数がすべて。ファサード独自の設定はない。

## 例

`crates/komainu/examples/` に置く（T8）。

- `minimal.rs`: 次の順で動く。
  1. 環境変数 `DATABASE_URL` から `PgStoreConfig` を作り、`connect`・`migrate` する。
  2. `ApplicationConfig::default().with_scopes(vec![ScopeDefinition { name: ScopeToken::try_new("read".to_owned())?, description: "Read your data".to_owned() }])` と `HttpConfig::new_insecure("http://127.0.0.1:8080")?` で `Komainu::builder()...build()?` する。
  3. `admin().register_client` で confidential・`client_secret_basic`・redirect_uri `http://127.0.0.1:9000/cb`・grant_types `authorization_code` と `refresh_token`・allowed/default scope `ScopeSet::parse("read")?`・`skip_consent: false` のクライアント（名前 `Example`）を登録し、`client_id` と `client_secret` を標準出力に出す。クライアントは起動のたびに新しく登録する（再利用しない。出力された `client_id` を使う、という仕様）。
  4. `admin().create_user` でユーザー `alice`、パスワード `correct horse battery staple` を作る。`Err(AdminError::Conflict)`（既にある）は無視して続け、ほかのエラーは終了する。
  5. `127.0.0.1:8080` で `axum::serve(listener, komainu.router().into_make_service_with_connect_info::<SocketAddr>())` する（今の server と同じく、監査ログに client_ip を残すため）。
  `RequestContext` は今の server の `background_context()` と同じ作り方をする。
- `custom_screens.rs`: `DefaultScreens` に `consent`・`error`・`logged_out` を委譲し、`login` だけ日本語の独自 HTML にする renderer と、`ContentSecurityPolicy::custom("default-src 'none'; style-src 'unsafe-inline' https://cdn.example; img-src 'self'")` を使う例（委譲先の `DefaultScreens` はインラインの `<style>` を使うので `'unsafe-inline'` を残す。このことを例のコメントと `ContentSecurityPolicy::custom` の rustdoc に書く）。独自 `login` は `client_name`・`username` を例の中に書いた小さな `escape_html(&str) -> String`（`& < > " '` の 5 文字を置換）でエスケープする。komainu はエスケープ関数を公開しない（askama などのテンプレートエンジンを使うことを rustdoc で勧める）。store は `komainu_testkit::InMemoryUnitOfWorkFactory`（dev-dependency）を使い、DB なしで動く。起動時に minimal と同じクライアントとユーザーを登録し、ブラウザで開く `/authorize` の URL（`client_id` 入り）を標準出力に出し、`127.0.0.1:8080` で serve する。

## 受け入れ条件

- store を指定せずに `build()` すると `MissingStore` になる。
- `http` 有効で `http_config` を指定せずに `build()` すると `MissingHttpConfig` になる。
- `--no-default-features` のテストで、clock を指定せずに `build()` すると `MissingComponent("clock")`、clock・random・password_hasher をすべて指定すると `Ok` になる。
- `InMemoryUnitOfWorkFactory`・`FixedClock`・`SequenceRandom`・`PlainPasswordHasher` を渡して組み立てた `router()` で、クライアント登録 → `/authorize` → ログイン → 同意 → `/token` が通り、アクセストークンが `token().verify_access_token` で有効と判定される（F-3）。
- 常に `AuthenticationOutcome::Authenticated(subject)` を返す authenticator を渡したとき、存在しないユーザー名と任意のパスワードで `POST /login` が 302（`/authorize/resume` へ）になる（F-4）。
- `application_config(ApplicationConfig::default().with_authorization_request_ttl(Duration::seconds(120)))` で組み立てたとき、`GET /authorize` の `Set-Cookie: komainu_csrf=...` の `Max-Age` は `120` になる。
- `screens(Arc::new(独自))` を渡したとき、`GET /login` の本文がその renderer の戻り値になる（F-5 の一部。詳細は screens.md）。

## 実装メモ

- F-4 のテストの authenticator は、`authenticate` で常に `Ok(AuthenticationOutcome::Authenticated(Subject::try_new("ext-user".to_owned()).unwrap()))`、`is_active` で常に `Ok(true)` を返す（`GET /authorize/resume` が毎回 `is_active` を呼ぶため。`false` だと resume で失敗する）。
- `router` を使うテストと、`http_config` を前提にするテストは `#[cfg(feature = "http")]` を付ける（`cargo test -p komainu --no-default-features` で落ちないように）。`--no-default-features` の受け入れ条件のテストは `#[cfg(not(feature = "std"))]` を付ける。
- `std` を外したビルドでも `komainu-application` は `time` などを使うので、`--no-default-features` の `cargo check` で依存の feature 漏れがないかを確かめる。
- `examples/minimal.rs` は `tokio`（`rt-multi-thread`、`macros`、`net`）を使う（`[dev-dependencies]` に入れてある）。`axum` は `http` feature の通常依存なので例からも使える。
