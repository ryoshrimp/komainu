# komainu-http: 画面差し替えと CSP

- 責務: 画面の HTML 生成を `ScreenRenderer` に委譲し、プロトコル処理（CSRF、Cookie、リダイレクト、ステータス、セキュリティヘッダ）は今のままハンドラが行う。HTML 応答の CSP を設定から付ける。HTML の見た目・文言・翻訳は決めない（renderer の責務）
- 配置: `crates/http/src/{screens.rs,csp.rs,state.rs,security_headers.rs,authorize.rs,login.rs,consent.rs}`、`crates/http/templates/`
- 関連要件: F-5〜F-8、N-1、N-2

## 公開インターフェース

`komainu_http` のルートから次を公開する（`pub use`）。

### ScreenRenderer

```rust
/// Renders the HTML documents of the browser-facing screens.
///
/// komainu decides the status code, headers and cookies; an implementation only returns
/// the body. It must HTML-escape every string it takes from a context.
pub trait ScreenRenderer: Send + Sync + 'static {
    fn login(&self, screen: &LoginScreen<'_>) -> Result<String, RenderError>;
    fn consent(&self, screen: &ConsentScreen<'_>) -> Result<String, RenderError>;
    fn error(&self, screen: &ErrorScreen<'_>) -> Result<String, RenderError>;
    fn logged_out(&self, screen: &LoggedOutScreen<'_>) -> Result<String, RenderError>;
}
```

- 4 メソッドとも既定実装を持たない（どれか 1 つだけ差し替えたい利用者は、`DefaultScreens` に委譲するラッパーを書く。例は `crates/komainu/examples/custom_screens.rs`）。
- 戻り値の `String` は応答本文にそのまま入る。`Content-Type` は常に `text/html; charset=utf-8`。

### 画面コンテキスト

すべて `#[non_exhaustive]`、`#[derive(Debug, Clone, Copy)]`（`ConsentScreen` は `Copy` なし）、フィールドは `pub`。komainu だけが作り、renderer は読むだけ。

```rust
/// Facts about the request that every screen receives.
#[non_exhaustive]
pub struct ScreenRequest<'a> {
    /// Raw value of the `Accept-Language` header; `None` when absent or when
    /// `HeaderValue::to_str` fails.
    pub accept_language: Option<&'a str>,
    /// `HttpConfig::public_base_url`, without a trailing `/`.
    pub base_url: &'a str,
    /// The request id that komainu logs and returns in `x-request-id` (for support pages).
    pub request_id: &'a str,
}

/// A form the screen must render as-is.
#[non_exhaustive]
pub struct FormTarget<'a> {
    /// Absolute URL for the `action` attribute. Method is always `post`.
    pub action: &'a str,
    /// Hidden field `request_id` (name: `form_fields::REQUEST_ID`).
    pub authorization_request_id: &'a str,
    /// Hidden field `csrf_token` (name: `form_fields::CSRF_TOKEN`).
    pub csrf_token: &'a str,
}

#[non_exhaustive]
pub struct LoginScreen<'a> {
    pub request: ScreenRequest<'a>,
    pub form: FormTarget<'a>,            // action = "{base_url}/login"
    pub client_name: &'a str,
    /// Username to pre-fill; empty on the first display.
    pub username: &'a str,
    pub error: Option<LoginErrorKind>,
}

#[non_exhaustive]
pub struct ConsentScreen<'a> {
    pub request: ScreenRequest<'a>,
    pub form: FormTarget<'a>,            // action = "{base_url}/authorize/decision"
    pub client_name: &'a str,
    pub scopes: &'a [komainu_application::ScopeView],
}
// DefaultScreens は scopes.to_vec() して今の ConsentPage（Vec<ScopeView> を持つ）に渡す。

#[non_exhaustive]
pub struct ErrorScreen<'a> {
    pub request: ScreenRequest<'a>,
    pub kind: ErrorKind,
    /// Status komainu will send: 400 or 500.
    pub status: u16,
}

#[non_exhaustive]
pub struct LoggedOutScreen<'a> {
    pub request: ScreenRequest<'a>,
}
```

`request_id`（フィールド）は二つあるので名前を分ける: `ScreenRequest::request_id` は HTTP リクエスト ID（`x-request-id`）、`FormTarget::authorization_request_id` は認可リクエスト ID（hidden フィールド `request_id` の値）。

### フォームの契約

```rust
pub mod form_fields {
    pub const REQUEST_ID: &str = "request_id";
    pub const CSRF_TOKEN: &str = "csrf_token";
    pub const USERNAME: &str = "username";
    pub const PASSWORD: &str = "password";
    pub const DECISION: &str = "decision";
    pub const DECISION_APPROVE: &str = "approve";
    pub const DECISION_DENY: &str = "deny";
}
```

| 画面 | method / action | 必須フィールド | 欠けたとき |
|---|---|---|---|
| ログイン | `post` / `{base_url}/login` | `request_id`、`csrf_token`（hidden）、`username`、`password` | 400 エラー画面（`RequestNotFound`。`csrf_token` が不一致なら `CsrfMismatch`）— 今の挙動のまま |
| 同意 | `post` / `{base_url}/authorize/decision` | `request_id`、`csrf_token`（hidden）、`decision` = `approve` か `deny` | 同上 |
| ログアウト | `post` / `{base_url}/logout` | なし（session Cookie を使う） | — |

ログアウトのフォームは komainu の画面には含まれない（利用者のアプリが置く）。今と同じ。

### LoginErrorKind と ErrorKind

```rust
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginErrorKind {
    InvalidCredentials,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    DuplicateParameter,
    MissingClientId,
    UnknownClient,
    InvalidRedirectUri,
    RedirectUriMismatch,
    MissingRedirectUri,
    RequestNotFound,
    CsrfMismatch,
    LoginRequired,
    /// Store failure or another internal error (status 500).
    TemporarilyUnavailable,
}

impl LoginErrorKind {
    /// The English text the default screens show.
    pub fn default_message(self) -> &'static str;
}
impl ErrorKind {
    pub fn default_message(self) -> &'static str;
}
impl From<komainu_application::NonRedirectableError> for ErrorKind { /* 1 対 1 */ }
```

`default_message` の文言は今の `non_redirectable_message`、`TEMPORARILY_UNAVAILABLE`、`"Invalid username or password."` と同じ。

### RenderError

```rust
/// A failure inside a [`ScreenRenderer`]. Logged by komainu, never shown to the user.
#[derive(Debug)]
pub struct RenderError(Box<dyn std::error::Error + Send + Sync>);

impl RenderError {
    pub fn new(source: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self;
}
impl std::fmt::Display for RenderError { /* "failed to render a screen: {source}" */ }
impl std::error::Error for RenderError { /* source() は中身 */ }
```

### DefaultScreens

```rust
/// The built-in English screens (askama templates under `crates/http/templates`).
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultScreens;
impl ScreenRenderer for DefaultScreens { /* ... */ }
```

askama の `Template` 構造体（`LoginPage` など）は非公開のまま `screens.rs` に移し、コンテキストから組み立てる。テンプレートが受け取る値は今と同じにして、出力を 1 バイトも変えない。

### HttpConfig

```rust
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct HttpConfig {
    // すべて非公開（検証済みの public_base_url を後から書き換えられないようにする）
    public_base_url: String,          // 末尾の '/' を除いた形
    cookie_secure: bool,
    max_body_bytes: usize,
    csrf_cookie_ttl: time::Duration,
    content_security_policy: ContentSecurityPolicy,
}

impl HttpConfig {
    /// Requires an absolute `https` URL with a host and no query or fragment.
    /// Trailing '/' characters are removed.
    pub fn new(public_base_url: &str) -> Result<Self, HttpConfigError>;
    /// Same as `new` but also accepts `http` (local development only).
    pub fn new_insecure(public_base_url: &str) -> Result<Self, HttpConfigError>;
    pub fn with_cookie_secure(self, value: bool) -> Self;
    pub fn with_max_body_bytes(self, value: usize) -> Self;
    pub fn with_csrf_cookie_ttl(self, value: time::Duration) -> Self;
    pub fn with_content_security_policy(self, value: ContentSecurityPolicy) -> Self;

    pub fn public_base_url(&self) -> &str;
    pub fn cookie_secure(&self) -> bool;
    pub fn max_body_bytes(&self) -> usize;
    pub fn csrf_cookie_ttl(&self) -> time::Duration;
    pub fn content_security_policy(&self) -> &ContentSecurityPolicy;
}

#[non_exhaustive]
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HttpConfigError {
    /// Holds `url::ParseError::to_string()`.
    #[error("public_base_url is not an absolute URL: {0}")]
    NotAbsolute(String),
    #[error("public_base_url must not have a query or a fragment")]
    QueryOrFragment,
    #[error("public_base_url must use https")]
    InsecureScheme,
    #[error("public_base_url has an unsupported scheme: {0}")]
    UnsupportedScheme(String),
    #[error("public_base_url must have a host")]
    MissingHost,
}
```

- 検証の規則は今の `crates/server/src/config.rs` の `public_base_url` の検証をそのまま移す。server は `HttpConfigError` を受けて、今と同じ文言（`server.public_base_url ...`、`InsecureScheme` は `(set server.allow_insecure_http = true for local development)` 付き）のエラーに組み立て直す。
- `new` / `new_insecure` で作った直後の値は表のとおり。
- http の中で今 `state.config.<field>` と読んでいる箇所は getter に置き換える。

| フィールド | 既定値 | 備考 |
|---|---|---|
| `cookie_secure` | `new` は `true`、`new_insecure` は `false` | server は `session.cookie_secure` で上書きする |
| `max_body_bytes` | `16384` | 今の server の固定値 |
| `csrf_cookie_ttl` | 600 秒 | `ApplicationConfig::default().authorization_request_ttl` と同じ。ファサードの builder は `ApplicationConfig::authorization_request_ttl` で上書きする（facade.md） |
| `content_security_policy` | `ContentSecurityPolicy::strict()` | |

### ContentSecurityPolicy

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentSecurityPolicy { /* header value, private */ }

impl ContentSecurityPolicy {
    /// `default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'` (today's value).
    pub fn strict() -> Self;
    /// `directives` followed by `; frame-ancestors 'none'`.
    pub fn custom(directives: &str) -> Result<Self, CspError>;
    /// The full header value komainu sends.
    pub fn as_str(&self) -> &str;
}
impl Default for ContentSecurityPolicy { /* strict() */ }

#[non_exhaustive]
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CspError {
    #[error("content security policy must not be empty")]
    Empty,
    #[error("content security policy must not set frame-ancestors; komainu always sends frame-ancestors 'none'")]
    FrameAncestorsNotAllowed,
    #[error("content security policy is not a valid header value")]
    InvalidHeaderValue,
}
```

`custom` の規則:

1. 前後の空白を取り除き、続けて末尾の `;` と空白を、どちらもなくなるまで繰り返し取り除く（例: `"default-src 'self' ;; "` → `"default-src 'self'"`、`" ; "` → `""`）。残りが空なら `Empty`。
2. `;` で区切った各ディレクティブについて、前後の ASCII 空白（スペース・タブなど `char::is_ascii_whitespace`）を取り除き、`split_ascii_whitespace` の最初の語を ASCII 小文字にして `frame-ancestors` と一致するものがあれば `FrameAncestorsNotAllowed`。
3. `"{1 の結果}; frame-ancestors 'none'"` が `HeaderValue::from_str` で通らなければ `InvalidHeaderValue`（改行や制御文字を含む場合）。途中の `;;` や空のディレクティブはそのまま残し、エラーにしない。
4. ディレクティブの中身（ソースの書式など）は検証しない。

### AppState

```rust
#[derive(Clone)]
pub struct AppState { /* authorization, token, config: Arc<HttpConfig>, screens: Arc<dyn ScreenRenderer> — all private */ }

impl AppState {
    /// Uses [`DefaultScreens`].
    pub fn new(authorization: AuthorizationService, token: TokenService, config: HttpConfig) -> Self;
    pub fn with_screens(self, screens: Arc<dyn ScreenRenderer>) -> Self;
}
```

`router(state: AppState) -> Router` のシグネチャと、ルート・ミドルウェアの構成は変えない。

## データ

永続化するデータの追加はない。

## 振る舞い

### ハンドラから renderer への呼び出し

今 `html(status, Template)` を呼んでいる箇所を、次の内部関数に置き換える。

```rust
// crate 内部
fn render(state: &AppState, status: StatusCode, f: impl FnOnce(&dyn ScreenRenderer) -> Result<String, RenderError>) -> Response;
```

| 呼び出し元 | renderer | status |
|---|---|---|
| `GET /authorize`・`POST /authorize`・`GET /authorize/resume` の `ConsentRequired` | `consent` | 200 |
| `GET /login`、`POST /login` の資格情報不一致 | `login`（不一致のとき `error: Some(InvalidCredentials)`、`username` は送られた値） | 200 |
| `NonRedirectableError` によるエラー（`bad_request`） | `error`（`kind` は `ErrorKind::from(error)`） | 400 |
| store エラーなど（`TEMPORARILY_UNAVAILABLE` を出していた箇所） | `error`（`kind: TemporarilyUnavailable`） | 500 |
| `POST /logout` | `logged_out` | 200 |

- `ScreenRequest` はハンドラが組み立てる。`accept_language` は `Accept-Language` ヘッダの値が `to_str()` で読めるときだけ `Some`。`request_id` は `Ctx` が持つ HTTP リクエスト ID。
- `Ok(body)` のとき `(status, [(CONTENT_TYPE, "text/html; charset=utf-8")], body)` を返す。`Set-Cookie` の付け方は今のまま（ハンドラが応答に足す）。
- `Err(e)` のとき `tracing::error!(error = %e, "failed to render a screen")` を記録し、`(500, [(CONTENT_TYPE, "text/plain; charset=utf-8")], "Internal Server Error")` を返す。エラー画面を呼び直さない。
- renderer の呼び出しは同期で、async ハンドラの中でそのまま呼ぶ（`spawn_blocking` しない）。重い処理をしないことは rustdoc に書く。

### セキュリティヘッダ

`add_security_headers` を `axum::middleware::from_fn_with_state` に変え、`Arc<HttpConfig>` から `content_security_policy().as_str()` を `Content-Security-Policy` に入れる。ほかのヘッダ（`X-Frame-Options: DENY`、`Cache-Control: no-store`、`Referrer-Policy: no-referrer`、`X-Content-Type-Options: nosniff`）は今のまま固定で、設定では変えられない。`text/plain` の 500 応答（renderer 失敗時）にはヘッダは付かない（今の `text/html` 判定のまま）。

## エラー

| 状況 | 返すもの | 呼び出し側の扱い |
|---|---|---|
| `HttpConfig::new` に不正な URL | `Err(HttpConfigError::*)` | server は設定エラーとして終了。組み込み利用者は起動を止める |
| `ContentSecurityPolicy::custom` に不正な値 | `Err(CspError::*)` | 同上 |
| renderer が `Err` | 500 `Internal Server Error`（text/plain）、`tracing::error!` に記録 | ブラウザ利用者はやり直す。運用者はログで原因を見る |
| renderer が panic | axum の既定のまま（接続が切れる）。komainu は捕まえない | 利用者の実装の不具合として扱う |

## 設定

| キー | 型 | 既定値 | 意味 |
|---|---|---|---|
| `HttpConfig::content_security_policy` | `ContentSecurityPolicy` | `strict()` | HTML 応答の CSP |
| `HttpConfig` のほかのフィールド | — | 上の表 | 今と同じ意味 |
| `server.content_security_policy`（server の設定ファイル） | 文字列、省略可 | 省略時は `strict()` | `ContentSecurityPolicy::custom` に渡す値 |

## 受け入れ条件

- `DefaultScreens` の出力が、変更前の出力から作った 5 つのスナップショット（login・login_error・consent・error・logged_out）とバイト単位で一致する。比べ方は「実装メモ」の手順に従う（動的な値は固定値を渡すので置換しない）。ハンドラがコンテキストに正しい値を入れることは、下の独自 renderer の項目（`form.action`・`csrf_token`・`accept_language`・`username`）で確かめる。
- 独自 renderer（各メソッドが `"<p>login</p>"` などの固定文字列を返す）を `AppState::with_screens` で渡したとき、4 画面の本文がその文字列になり、ステータス・`Set-Cookie`・セキュリティヘッダは `DefaultScreens` の場合と同じになる。
- 独自 renderer の `login` が受け取る `form.action` は `"{BASE}/login"`、`consent` の `form.action` は `"{BASE}/authorize/decision"` になる。`form.csrf_token` は `komainu_csrf` Cookie の値と一致する。
- `POST /login` に `csrf_token` を付けずに送ったとき、`error` が `ErrorKind::RequestNotFound` で呼ばれ、ステータスは 400 になる。`csrf_token` が Cookie と違うときは `ErrorKind::CsrfMismatch` になる。
- `custom("default-src 'self' ;; ")` は `default-src 'self'; frame-ancestors 'none'`、`custom(" ; ")` は `Empty`。
- `POST /login` が資格情報の不一致のとき、`login` が `error: Some(LoginErrorKind::InvalidCredentials)` と送った `username` で呼ばれる。
- `GET /authorize` で認可リクエストを作って `request_id` と `komainu_csrf` Cookie を取ったあとに `InMemoryUnitOfWorkFactory::fail_next()` を呼び、その Cookie を付けて `GET /login?request_id=...` を送ったとき、`error` が `ErrorKind::TemporarilyUnavailable`、`status == 500` で呼ばれる。
- `Accept-Language: ja` を付けて `GET /login?request_id=bad` を開いたとき、`error` の `request.accept_language` は `Some("ja")`、`kind` は `RequestNotFound` になる。ヘッダがないときは `None`。
- renderer の `login` が `Err` を返すとき、応答は 500、`Content-Type: text/plain; charset=utf-8`、本文 `Internal Server Error` になり、renderer の `error` は呼ばれない。
- `ContentSecurityPolicy::custom("default-src 'self'")` の `as_str()` は `default-src 'self'; frame-ancestors 'none'`。`custom("default-src 'self';")` も同じ値になる。
- `custom("default-src 'self'; Frame-Ancestors https://a.example")` は `FrameAncestorsNotAllowed`、`custom("  ")` は `Empty`、`custom("default-src 'self'\n")` は前後空白除去で通る、`custom("default-src\n'self'")` は `InvalidHeaderValue`。
- `HttpConfig` に `custom("default-src 'self'")` を設定したとき、HTML 応答の `Content-Security-Policy` はその値になり、`X-Frame-Options: DENY` は残る。`/token` の JSON 応答には CSP が付かない。
- `HttpConfig::new("https://auth.example.com/")` の `public_base_url` は `https://auth.example.com`。`new("http://localhost:8080")` は `InsecureScheme`、`new_insecure("http://localhost:8080")` は通る。`new("https://a.example/?x=1")` は `QueryOrFragment`、`new("/relative")` は `NotAbsolute(_)`（中身は比べず `matches!` で variant だけを見る）、`new("ftp://a.example")` は `UnsupportedScheme("ftp")`。

## 実装メモ

- `HttpConfigError`・`CspError` のために `crates/http/Cargo.toml` に `thiserror.workspace = true` を足す。
- 置き換える箇所は HTML を返すすべての箇所: `crates/http/src/authorize.rs` の `html`・`error_page`・`bad_request`・`authorize_failure`（store エラーの 500）・`outcome_response`・resume ハンドラの `bad_request`、`crates/http/src/login.rs` の `login_get`・`login_post` の store エラー（`TEMPORARILY_UNAVAILABLE` の 500）・`invalid_credentials_page`・`logout`、`crates/http/src/consent.rs`。置き換えのあと、内部関数 `html` と `error_page`、定数 `TEMPORARILY_UNAVAILABLE` は削除し、文言は `ErrorKind::default_message` に移す。`grep -rn "TEMPORARILY_UNAVAILABLE\|fn html\|html(\|error_page" crates/http/src` が 0 件になること。例外として、`redirect(location)` が `HeaderValue` を作れなかったときの 500 は renderer を通さず、renderer 失敗時と同じ text/plain の固定応答（`Internal Server Error`）にする（`redirect` は `AppState` もヘッダも受け取らず、`ScreenRequest` を作れないため。Location は検証済みの URL から作るので、実際にはほぼ起きない）。`redirect` のシグネチャは変えない。
- `ErrorPage` テンプレートには、`DefaultScreens::error` の中で `screen.kind.default_message()` を渡す。
- `ScreenRequest` を作るために、`bad_request` などのヘルパーは `&AppState` と `&HeaderMap`、`Ctx` を受ける必要がある。引数をまとめた内部構造体（例: `ScreenCtx<'a> { state, headers, request_id }`）を作ってよい。
- 既定画面のスナップショットは crate 内の単体テスト（`crates/http/src/screens.rs` の `#[cfg(test)]`。コンテキストは `#[non_exhaustive]` なので crate 外では作れない）で比べる。
  1. T4 の最初のコミットで、`crates/http/src/login.rs`（`LoginPage`）と `crates/http/src/authorize.rs`（`ErrorPage`・`LoggedOutPage`）、`crates/http/src/consent.rs`（`ConsentPage`）の `#[cfg(test)]` に `#[ignore]` 付きの生成テストを置き、`cargo test -p komainu-http -- --ignored write_snapshot` で次の 5 ファイルを書き出して commit する（書き出し先は `concat!(env!("CARGO_MANIFEST_DIR"), "/src/snapshots/<name>.html")`、ディレクトリは `std::fs::create_dir_all` で作る）: `crates/http/src/snapshots/{login,login_error,consent,error,logged_out}.html`。渡す固定値は base_url `https://auth.example.com`、request_id（認可リクエスト）`req-1`、csrf_token `csrf-1`、client_name `Example <App>`（エスケープの確認を兼ねる）、username `alice`（login は空文字、login_error は `alice` と `"Invalid username or password."`）、scopes は `read`/`Read your data` と `write`/`Write & delete`、error の message は `non_redirectable_message(NonRedirectableError::CsrfMismatch)`。生成テストは次のコミット（置き換え）で削除する。
  2. 置き換え後、同じ値を入れたコンテキストを `DefaultScreens` に渡し、`include_str!` したスナップショットと `assert_eq!` で比べる。
