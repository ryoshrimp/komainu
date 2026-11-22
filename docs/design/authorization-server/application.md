# komainu-application

- 責務: ユースケース（アプリケーションサービス）と、外部に依存する部分の port trait を定める。トランザクション境界、OAuth のエラーへの対応づけ、監査イベントの記録はこの層で行う。
- 配置: `crates/application`
- 関連要件: F-1〜F-13、N-1、N-3、N-5、N-8

## 公開インターフェース

### 依存

`komainu-domain`、`time = "0.3"`、`uuid = "1"`（`v7` は使わない。`Builder::from_unix_timestamp_millis` で組み立てる）、`base64 = "0.22"`、`thiserror = "2"`。ddd-toolkit には直接依存しない（`Secret<T>` は domain の再エクスポート `komainu_domain::Secret` を使う。README §2.5）。tokio、sqlx、axum、serde には依存しない。

### モジュール構成

```
crates/application/src/
  lib.rs              // pub mod 群と、主要な型の pub use
  context.rs          // RequestContext
  config.rs           // ApplicationConfig, ScopeDefinition
  deps.rs             // Dependencies
  ids.rs              // UUIDv7 と OpaqueToken の生成
  audit.rs            // AuditEvent, AuditKind, AuditActor, AuditOutcome
  port/
    mod.rs  store.rs  repository.rs  clock.rs  random.rs  password.rs  authenticator.rs
  authentication.rs   // BuiltinAuthenticator
  authorization/      // AuthorizationService
    mod.rs  params.rs  error.rs
  token/              // TokenService
    mod.rs  request.rs  error.rs
  admin/              // AdminService
    mod.rs  error.rs
  maintenance.rs      // MaintenanceService
```

### 非同期の書き方

trait オブジェクトで DI するため、port の非同期メソッドは次の `BoxFuture` を返す（ddd-toolkit の `AsyncRepository` と同じ形）。ユースケースのメソッドは普通の `async fn` にする。

```rust
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
```

ユースケースが返す future は `Send` でなければならない（axum のハンドラから呼ぶため）。テストで `fn assert_send<T: Send>(_: T)` を使って確かめる。

### RequestContext

```rust
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// x-request-id (N-8). CLI uses a freshly generated UUIDv7 string.
    pub request_id: String,
    /// Peer address of the HTTP connection. None for CLI and jobs.
    pub client_ip: Option<std::net::IpAddr>,
}
```

ユースケースは第 1 引数に `&RequestContext` を受け取り、監査イベントに `request_id` と `client_ip` を書く。例外は、監査イベントを書かない読み取り専用の 2 つ: `TokenService::verify_access_token`（リソースサーバーがライブラリとして呼ぶ API なので、呼び出し側に `RequestContext` を作らせない）と `MaintenanceService::check_ready`。

### port: 永続化

```rust
#[derive(Debug, Clone, thiserror::Error)]
pub enum StoreError {
    /// Unique constraint violation (e.g. duplicate username).
    #[error("conflict")]
    Conflict,
    /// Connection failure, pool timeout, serialization failure.
    #[error("store unavailable: {0}")]
    Unavailable(String),
    #[error("store error: {0}")]
    Other(String),
}

pub trait UnitOfWorkFactory: Send + Sync + 'static {
    /// Begins a transaction (READ COMMITTED).
    fn begin(&self) -> BoxFuture<'_, Result<Box<dyn UnitOfWork>, StoreError>>;
    /// Readiness check. Ok when the store accepts queries.
    fn ping(&self) -> BoxFuture<'_, Result<(), StoreError>>;
}

/// Dropping without commit rolls back.
pub trait UnitOfWork: Send {
    fn clients(&mut self) -> &mut dyn ClientRepository;
    fn users(&mut self) -> &mut dyn UserRepository;
    fn login_sessions(&mut self) -> &mut dyn LoginSessionRepository;
    fn authorization_requests(&mut self) -> &mut dyn AuthorizationRequestRepository;
    fn authorization_codes(&mut self) -> &mut dyn AuthorizationCodeRepository;
    fn consents(&mut self) -> &mut dyn ConsentRepository;
    fn grants(&mut self) -> &mut dyn GrantRepository;
    fn access_tokens(&mut self) -> &mut dyn AccessTokenRepository;
    fn refresh_tokens(&mut self) -> &mut dyn RefreshTokenRepository;
    fn audit_log(&mut self) -> &mut dyn AuditLogRepository;
    fn purge(&mut self) -> &mut dyn PurgeRepository;
    fn commit(self: Box<Self>) -> BoxFuture<'static, Result<(), StoreError>>;
}
```

リポジトリ（すべて `Send`。メソッドはすべて `&mut self` を取り、`BoxFuture<'_, Result<_, StoreError>>` を返す。下では戻り値の `Result<_, StoreError>` の中身だけを書く）:

| trait | メソッド | 戻り値 | 意味 |
|---|---|---|---|
| `ClientRepository` | `find(&ClientId)` | `Option<Client>` | |
| | `find_for_update(&ClientId)` | `Option<Client>` | 行ロックを取って読む |
| | `insert(&Client)` | `()` | ID 重複は `Conflict` |
| | `update(&Client)` | `()` | 行がなければ `Other` |
| | `list(&ListPage<ClientId>)` | `Vec<Client>` | ID の昇順 |
| `UserRepository` | `find(UserId)` / `find_for_update(UserId)` | `Option<User>` | |
| | `find_by_username(&Username)` | `Option<User>` | |
| | `insert(&User)` | `()` | ユーザー名の重複は `Conflict` |
| | `update(&User)` | `()` | |
| | `list(&ListPage<Username>)` | `Vec<User>` | ユーザー名の昇順 |
| `LoginSessionRepository` | `find(&TokenHash)` | `Option<LoginSession>` | |
| | `insert(&LoginSession)` | `()` | |
| | `delete(&TokenHash)` | `()` | なくてもエラーにしない |
| | `delete_by_subject(&Subject)` | `u64` | 削除件数 |
| `AuthorizationRequestRepository` | `find_for_update(AuthorizationRequestId)` | `Option<AuthorizationRequest>` | |
| | `insert(&AuthorizationRequest)` / `update(&AuthorizationRequest)` | `()` | |
| `AuthorizationCodeRepository` | `find_for_update(&TokenHash)` | `Option<AuthorizationCode>` | |
| | `insert(&AuthorizationCode)` / `update(&AuthorizationCode)` | `()` | |
| `ConsentRepository` | `find(&Subject, &ClientId)` | `Option<Consent>` | |
| | `upsert(&Consent)` | `()` | |
| `GrantRepository` | `find(GrantId)` / `find_for_update(GrantId)` | `Option<Grant>` | |
| | `insert(&Grant)` / `update(&Grant)` | `()` | |
| | `list_active_by_client(&ClientId)` | `Vec<Grant>` | 行ロックを取る |
| | `list_active_by_subject(&Subject)` | `Vec<Grant>` | 行ロックを取る |
| `AccessTokenRepository` | `find(&TokenHash)` | `Option<AccessToken>` | |
| | `insert(&AccessToken)` | `()` | |
| `RefreshTokenRepository` | `find_for_update(&TokenHash)` | `Option<RefreshToken>` | |
| | `insert(&RefreshToken)` / `update(&RefreshToken)` | `()` | |
| `AuditLogRepository` | `append(&AuditEvent)` | `()` | |
| `PurgeRepository` | `purge_expired(cutoff: OffsetDateTime)` | `PurgeCounts` | 下を参照 |
| | `purge_audit_events(cutoff: OffsetDateTime)` | `u64` | `occurred_at <= cutoff` を削除 |

```rust
#[derive(Debug, Clone)]
pub struct ListPage<K> {
    /// Returns items whose key is strictly greater than this.
    pub after: Option<K>,
    /// 1..=1000. Callers clamp.
    pub limit: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PurgeCounts {
    pub authorization_requests: u64,
    pub authorization_codes: u64,
    pub access_tokens: u64,
    pub refresh_tokens: u64,
    pub login_sessions: u64,
    pub grants: u64,
}
```

`purge_expired(cutoff)` は、`expires_at <= cutoff` の認可リクエスト・認可コード・アクセストークン・リフレッシュトークン・ログインセッションを削除し、続けて「`created_at <= cutoff` で、参照するアクセストークン・リフレッシュトークン・認可コードが 1 件もない Grant」を削除する。

### port: そのほか

```rust
pub trait Clock: Send + Sync + 'static {
    /// Current time in UTC.
    fn now(&self) -> OffsetDateTime;
}

pub trait SecureRandom: Send + Sync + 'static {
    /// Fills dest with bytes from a CSPRNG.
    fn fill_bytes(&self, dest: &mut [u8]);
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("password hashing failed: {0}")]
pub struct PasswordHashError(pub String);

pub trait PasswordHasher: Send + Sync + 'static {
    fn hash<'a>(&'a self, password: &'a Password) -> BoxFuture<'a, Result<PasswordHash, PasswordHashError>>;
    /// false on mismatch or on an unparsable hash.
    fn verify<'a>(&'a self, password: &'a Password, hash: &'a PasswordHash) -> BoxFuture<'a, bool>;
    /// Burns roughly the same time as verify. Used when the user does not exist.
    fn verify_dummy<'a>(&'a self, password: &'a Password) -> BoxFuture<'a, ()>;
}

pub struct LoginCredentials {
    /// Raw input; the built-in authenticator normalizes it with Username::try_new.
    pub username: String,
    /// Raw input. The built-in authenticator converts it with Password::try_new;
    /// on failure it returns InvalidCredentials (still audited as login.failed).
    pub password: Secret<String>,
}

pub enum AuthenticationOutcome {
    Authenticated(Subject),
    InvalidCredentials,
    Disabled,
}

pub trait ResourceOwnerAuthenticator: Send + Sync + 'static {
    /// The uow is the caller's transaction. Implementations that do not use the store may ignore it.
    fn authenticate<'a>(
        &'a self,
        uow: &'a mut dyn UnitOfWork,
        credentials: &'a LoginCredentials,
    ) -> BoxFuture<'a, Result<AuthenticationOutcome, StoreError>>;
    /// Whether the subject may still use the server (checked on every session use).
    fn is_active<'a>(&'a self, uow: &'a mut dyn UnitOfWork, subject: &'a Subject)
        -> BoxFuture<'a, Result<bool, StoreError>>;
}
```

`BuiltinAuthenticator`（`authentication.rs`）は `ResourceOwnerAuthenticator` の既定実装で、`BuiltinAuthenticator::new(hasher: Arc<dyn PasswordHasher>)` で作る。

- `authenticate`: まず `Password::try_new` に通し、失敗（空、129 文字以上）したら `verify_dummy` を呼ばずにすぐ `InvalidCredentials` を返す（長さはユーザーの存在と関係しないので、応答時間の差から分かることはない）。次に `Username::try_new` か `find_by_username` で見つからなければ `verify_dummy` を呼んでから `InvalidCredentials`。見つかって `verify` が `false` なら `InvalidCredentials`。ユーザーが無効なら（パスワードが正しくても）`Disabled`。それ以外は `Authenticated(user.subject())`。
- `is_active`: `Subject` を `UserId` として解釈できない、ユーザーがない、無効のどれかなら `false`。

### ID とトークンの生成（`ids.rs`）

```rust
/// UUIDv7 from clock.now() (unix millis) and 10 random bytes.
pub fn new_uuid_v7(clock: &dyn Clock, random: &dyn SecureRandom) -> uuid::Uuid;
/// 32 random bytes, base64url without padding (43 chars). N-1.
pub fn new_opaque_token(random: &dyn SecureRandom) -> OpaqueToken;
```

`ClientId`（UUIDv7 のハイフン付き文字列）、`UserId`、`GrantId`、`AuthorizationRequestId`、監査イベントの ID は `new_uuid_v7` で作る。認可コード、アクセストークン、リフレッシュトークン、クライアントシークレット、セッショントークン、CSRF トークンは `new_opaque_token` で作る。

### ApplicationConfig

```rust
#[derive(Debug, Clone)]
pub struct ScopeDefinition {
    pub name: ScopeToken,
    /// Shown on the consent screen. 1..=200 chars, validated by komainu-server when loading config
    /// (application does not re-validate).
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct ApplicationConfig {
    pub authorization_code_ttl: Duration,     // default 60s
    pub access_token_ttl: Duration,           // default 3600s
    pub refresh_token_ttl: Duration,          // default 30 days
    pub authorization_request_ttl: Duration,  // default 600s
    pub login_session_ttl: Duration,          // default 8h
    pub require_state: bool,                  // default false
    pub allow_public_clients: bool,           // default false
    /// Scopes the server knows. Client allowed_scopes must be a subset.
    pub scopes: Vec<ScopeDefinition>,         // default empty
    /// Expired rows are deleted this long after expiry (F-13).
    pub purge_grace: Duration,                // default 24h
    pub audit_retention: Duration,            // default 90 days
}
impl Default for ApplicationConfig { /* values above */ }
```

### Dependencies とサービスの作り方

```rust
#[derive(Clone)]
pub struct Dependencies {
    pub store: Arc<dyn UnitOfWorkFactory>,
    pub clock: Arc<dyn Clock>,
    pub random: Arc<dyn SecureRandom>,
    pub password_hasher: Arc<dyn PasswordHasher>,
    pub authenticator: Arc<dyn ResourceOwnerAuthenticator>,
    pub config: Arc<ApplicationConfig>,
}

impl AuthorizationService { pub fn new(deps: Dependencies) -> Self; }
impl TokenService { pub fn new(deps: Dependencies) -> Self; }
impl AdminService { pub fn new(deps: Dependencies) -> Self; }
impl MaintenanceService { pub fn new(deps: Dependencies) -> Self; }
```

4 つのサービスはどれも `Clone + Send + Sync`。

### トランザクションの共通ルール

- ユースケース 1 回の呼び出しで UoW を 1 つ使う（例外は下に書いたものだけ）。
- 集約を変更したら、`pull_events()` で取り出したドメインイベントを [§監査イベント](#監査イベント) の表に従って `AuditEvent` に変え、同じ UoW で `append` してから `commit` する。
- エラーを返すときは UoW を commit せずに捨てる。ただし次の 3 つは、記録を残すために commit してからエラーを返す。
  1. 認可コードの再利用を検知して Grant を失効させたとき
  2. リフレッシュトークンの再利用を検知して Grant を失効させたとき
  3. ログイン失敗とクライアント認証失敗の監査イベント（新しい UoW を開いて書く）

### AuthorizationService

画面の遷移は [http.md](http.md) が決める。このサービスは「次に何をすべきか」を返す。

```rust
/// Query parameters of GET /authorize. Empty values are treated as absent (§3.1).
#[derive(Debug, Clone, Default)]
pub struct AuthorizeParams {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    /// Names of the above parameters that appeared more than once.
    pub duplicated: Vec<&'static str>,
}
impl AuthorizeParams {
    /// Unknown parameters are ignored (§3.1).
    pub fn from_pairs(pairs: impl IntoIterator<Item = (String, String)>) -> Self;
}

pub struct ScopeView { pub name: String, pub description: String }

pub struct ConsentPrompt {
    pub client_name: String,
    /// Requested scopes, sorted by name. description is "" for scopes not in config.
    pub scopes: Vec<ScopeView>,
}

pub enum AuthorizeOutcome {
    /// Show the login form for this request.
    LoginRequired { request_id: AuthorizationRequestId },
    /// Show the consent screen.
    ConsentRequired { request_id: AuthorizationRequestId, prompt: ConsentPrompt },
    /// 302 to this absolute URI (code or error response to the client).
    Redirect { location: String },
}

pub struct StartResult {
    pub outcome: AuthorizeOutcome,
    /// Set when a new pending request was created; http stores it in the komainu_csrf cookie.
    pub csrf_token: Option<OpaqueToken>,
}

pub struct LoginFormView { pub client_name: String }

pub struct LoggedIn {
    pub session_token: OpaqueToken,
    pub expires_at: OffsetDateTime,
    /// Equals ApplicationConfig::session_ttl. http uses it for the cookie Max-Age.
    pub max_age: time::Duration,
}

impl AuthorizationService {
    pub async fn start(&self, ctx: &RequestContext, params: AuthorizeParams, session: Option<&OpaqueToken>)
        -> Result<StartResult, AuthorizeError>;
    pub async fn login_form(&self, ctx: &RequestContext, request_id: AuthorizationRequestId)
        -> Result<LoginFormView, AuthorizeError>;
    pub async fn login(&self, ctx: &RequestContext, request_id: AuthorizationRequestId, csrf: &OpaqueToken,
        credentials: LoginCredentials) -> Result<LoggedIn, LoginError>;
    pub async fn resume(&self, ctx: &RequestContext, request_id: AuthorizationRequestId, session: Option<&OpaqueToken>)
        -> Result<AuthorizeOutcome, AuthorizeError>;
    pub async fn decide(&self, ctx: &RequestContext, request_id: AuthorizationRequestId, csrf: &OpaqueToken,
        session: Option<&OpaqueToken>, approve: bool) -> Result<String /* location */, AuthorizeError>;
    pub async fn logout(&self, ctx: &RequestContext, session: &OpaqueToken) -> Result<(), StoreError>;
}
```

#### start の処理順

最初に当てはまったところでエラーを返す。1〜3 はリダイレクトしてはいけない誤り（§4.1.2.1）、4 以降はクライアントへエラーをリダイレクトする誤り。

1. `duplicated` に `client_id` か `redirect_uri` がある → `NonRedirectable(DuplicateParameter)`
2. `client_id` がない → `MissingClientId`。`ClientId::try_new` に失敗、クライアントがない、無効 → `UnknownClient`
3. `redirect_uri` があって `RedirectUri::try_new` に失敗 → `InvalidRedirectUri`。`resolve_redirect_uri` が `NotRegistered` → `RedirectUriMismatch`、`Missing` → `MissingRedirectUri`
4. `state` があって `State::try_new` に失敗 → `invalid_request`（エラー応答に `state` を付けない）
5. ほかのパラメータが重複している → `invalid_request`
6. `response_type` がない → `invalid_request`。`code` 以外 → `unsupported_response_type`
7. クライアントが `AuthorizationCode` を持たない、または `Public` で `allow_public_clients=false` → `unauthorized_client`
8. `state` がなく `require_state=true` → `invalid_request`
9. `scope` があって `ScopeSet::parse` に失敗、または `resolve_scope` が失敗 → `invalid_scope`
10. `AuthorizationRequest` を作る（CSRF トークンを生成し、ハッシュを保存）。
11. セッションを確かめる: `session` が `Some` で、`LoginSession` があり、`is_valid_at(now)`、かつ `authenticator.is_active` が `true` のときだけ「ログイン済み」とする。
    - 未ログイン → 保存して commit し、`LoginRequired`
    - ログイン済みで、`skip_consent=true` か、Consent があって要求スコープを覆う → その場で `approve` し、認可コードを発行する。`AuthorizationRequest`（`Approved`）を insert してから `AuthorizationCode` を insert し、監査を書いて commit し、`Redirect`（`code` と `state`）を返す。`authorization_codes` は `grants` を参照しない（Grant ができるのは交換のとき）ので、この順で FK の制約に当たらない
    - ログイン済みでそれ以外 → 保存して commit し、`ConsentRequired`

`StartResult.csrf_token` は 10 で作ったものを、`Redirect` 以外のときに `Some` で返す。

#### そのほかのメソッド

- `login_form`: 要求が `Pending` で期限内なら、クライアント名を返す。
- `login`: 要求を `find_for_update` で読み、`Pending` で期限内か、`verify_csrf` が通るかを確かめる。`authenticator.authenticate` の結果が `Authenticated` なら、`LoginSession` を作って保存し、監査 `login.succeeded` を書いて commit し、`LoggedIn` を返す。失敗なら UoW を捨て、新しい UoW で監査 `login.failed`（`details.reason` は `invalid_credentials` か `disabled`、`details.username` は入力をそのまま 64 文字までに切ったもの）を書いて commit し、`LoginError::InvalidCredentials` を返す（無効ユーザーも同じエラーにして、存在を推測させない）。
- `resume`: 要求を確かめた後、`start` の 11 と同じ判定をする。違いは、要求をすでに保存済みであることと、CSRF トークンを作り直さないこと。
- `decide`: 要求、CSRF、ログイン済みであることを確かめる（未ログインなら `NonRedirectable(LoginRequired)`）。
  - `approve=true`: Consent がなければ `Consent::grant`、あれば `extend` で要求スコープを足して `upsert`。`AuthorizationRequest::approve`、`AuthorizationCode::issue`、保存、監査、commit。`code`（と `state`）付きの URI を返す。
  - `approve=false`: `deny`、保存、監査、commit。`error=access_denied`（と `state`）付きの URI を返す。
- `logout`: セッションを削除し、あれば監査 `logout` を書いて commit する。セッションがなくても `Ok(())`。

#### AuthorizeError と LoginError

```rust
pub enum AuthorizeError {
    /// Must not redirect to the client. Show an error page (http.md).
    NonRedirectable(NonRedirectableError),
    /// Redirect the user agent to `location`, which carries error/error_description/state.
    Redirect { location: String, error: AuthorizeErrorCode },
    /// Store failure at any stage. http shows a 500 error page and never redirects,
    /// even when the request was already validated (RFC 6749 §4.1.2.1 server_error /
    /// temporarily_unavailable redirects are not used yet; README Q-9).
    Store(StoreError),
}

pub enum NonRedirectableError {
    DuplicateParameter, MissingClientId, UnknownClient,
    InvalidRedirectUri, RedirectUriMismatch, MissingRedirectUri,
    /// Request id unknown, expired, or already approved/denied.
    RequestNotFound,
    CsrfMismatch,
    /// decide was called without a valid session.
    LoginRequired,
}

pub enum AuthorizeErrorCode {
    InvalidRequest, UnauthorizedClient, AccessDenied, UnsupportedResponseType, InvalidScope,
}
impl AuthorizeErrorCode { pub fn as_str(&self) -> &'static str; } // "invalid_request", ...

pub enum LoginError {
    InvalidCredentials,
    /// Request unknown/expired/handled, or CSRF mismatch.
    Authorize(AuthorizeError),
    Store(StoreError),
}
```

- 期限切れ・処理済みの要求は、すべて `RequestNotFound` にする（理由で画面を分けない）。
- エラーのリダイレクト先は `RedirectUri::with_query_params` で作る。パラメータの順は `error`、`error_description`、`state`。`error_description` は固定の英文（例: `response_type is missing`）にする。

### TokenService

```rust
/// Client credentials as presented to the token endpoint (parsed by http).
pub enum ClientAuthentication {
    /// Authorization: Basic, already URL-decoded (§2.3.1).
    Basic { client_id: String, secret: Secret<String> },
    /// client_id + client_secret in the body.
    Post { client_id: String, secret: Secret<String> },
    /// Only client_id in the body (public clients, §3.2.1).
    PublicId { client_id: String },
    None,
}

#[derive(Debug, Clone, Default)]
pub struct TokenRequest {
    pub grant_type: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub refresh_token: Option<String>,
    pub duplicated: Vec<&'static str>,
}
impl TokenRequest {
    /// client_id and client_secret are not read here (http extracts them).
    pub fn from_pairs(pairs: impl IntoIterator<Item = (String, String)>) -> Self;
}

pub struct TokenResponse {
    pub access_token: OpaqueToken,
    /// Always "Bearer".
    pub token_type: &'static str,
    pub expires_in: u64,
    pub refresh_token: Option<OpaqueToken>,
    /// Always included, even when identical to the request.
    pub scope: ScopeSet,
}

pub struct AccessTokenInfo {
    pub grant_id: GrantId,
    pub client_id: ClientId,
    /// None for client_credentials.
    pub subject: Option<Subject>,
    pub scope: ScopeSet,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

impl TokenService {
    pub async fn exchange(&self, ctx: &RequestContext, auth: ClientAuthentication, request: TokenRequest)
        -> Result<TokenResponse, TokenError>;
    /// Ok(None) for unknown, malformed, expired or revoked tokens, or a disabled client.
    pub async fn verify_access_token(&self, token: &str) -> Result<Option<AccessTokenInfo>, StoreError>;
}
```

#### exchange の処理順

1. `duplicated` が空でない → `InvalidRequest`
2. `grant_type` がない → `InvalidRequest`。`authorization_code`、`client_credentials`、`refresh_token` 以外 → `UnsupportedGrantType`
3. クライアント認証（UoW を開いて `clients().find`）:
   - `None` → `InvalidClient { basic_attempted: false }`
   - `Basic` / `Post`: クライアントがない、無効、`auth_method` が提示方法と違う、`verify_secret` が `false` → `InvalidClient { basic_attempted: Basic なら true }`
   - `PublicId`: クライアントがない、無効、`Public` でない、`allow_public_clients=false` → `InvalidClient { basic_attempted: false }`
   - 失敗したときは、新しい UoW で監査 `client_authentication.failed` を書いて commit する。
4. `supports_grant` が `false` → `UnauthorizedClient`
5. グラントごとの処理（下）。成功したら監査 `token.issued` を書いて commit する。

`authorization_code`:

1. `code` がない → `InvalidRequest`。`OpaqueToken::try_new` に失敗、`find_for_update` で見つからない → `InvalidGrant`
2. `redirect_uri` があって `RedirectUri::try_new` に失敗 → `InvalidGrant`
3. `new_uuid_v7` で `grant_id` を作り、`redeem` を呼ぶ。
   - `Replayed { grant_id }` → その Grant を `find_for_update` して `revoke(CodeReplay)`、保存、監査（`authorization_code.replay_detected` と `grant.revoked`）、commit、`InvalidGrant`。Grant が見つからない（削除ジョブで消えた）ときは、失効は飛ばし、監査 `authorization_code.replay_detected` だけを書いて commit し、`InvalidGrant`。すでに失効済みなら `revoke` は何もしないので、`grant.revoked` は書かない
   - `ClientMismatch`、`Expired`、`RedirectUriMismatch` → `InvalidGrant`
4. `Grant::from_authorization_code`、`AccessToken::issue`（スコープはコードのもの）、クライアントが `RefreshToken` を持てば `RefreshToken::issue`。コード、Grant、トークンを保存する。リクエストの `scope` は無視する。

`client_credentials`:

1. `scope` の解析に失敗、または `resolve_scope` が失敗 → `InvalidScope`
2. `Grant::for_client_credentials`、`AccessToken::issue`。リフレッシュトークンは発行しない。

`refresh_token`:

1. `refresh_token` がない → `InvalidRequest`。形式が不正、`find_for_update` で見つからない → `InvalidGrant`
2. `rotate(client_id)`:
   - `Replayed { grant_id }` → Grant を `revoke(RefreshTokenReplay)`、保存、監査（`refresh_token.replay_detected` と `grant.revoked`）、commit、`InvalidGrant`。Grant が見つからないとき、失効済みのときの扱いは `authorization_code` の 3 と同じ
   - `ClientMismatch`、`Expired` → `InvalidGrant`
3. Grant を `find_for_update`。ない、または失効済み → `InvalidGrant`
4. `scope` がない → Grant のスコープ。あって解析に失敗、または Grant のスコープの部分集合でない → `InvalidScope`（§6）
5. 新しい `AccessToken`（4 のスコープ）と新しい `RefreshToken`（Grant のスコープ）を発行し、古いリフレッシュトークンと一緒に保存する。

#### verify_access_token

UoW を開いて読むだけ（commit しない）。`OpaqueToken::try_new` に失敗、ハッシュで見つからない、`is_valid_at(now)` が `false`、Grant がないか失効済み、クライアントがないか無効、のどれかなら `Ok(None)`。

#### TokenError

```rust
pub enum TokenError {
    InvalidRequest,
    /// basic_attempted: the client tried HTTP Basic (http returns 401 + WWW-Authenticate).
    InvalidClient { basic_attempted: bool },
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    InvalidScope,
    Server(StoreError),
}
impl TokenError {
    /// RFC 6749 §5.2 error code. Server -> "server_error".
    pub fn code(&self) -> &'static str;
}
```

### AdminService

CLI（[server.md](server.md)）から使う。入力は domain の型で受け取り、文字列の解析は呼び出し側が行う。監査イベントの `actor` は `AuditActor::Admin`。

```rust
pub struct RegisterClient {
    pub name: ClientName,
    pub client_type: ClientType,
    pub auth_method: TokenEndpointAuthMethod,
    pub redirect_uris: Vec<RedirectUri>,
    pub grant_types: BTreeSet<GrantType>,
    pub allowed_scopes: ScopeSet,
    pub default_scopes: ScopeSet,
    pub skip_consent: bool,
}

pub struct ClientView {
    pub id: ClientId, pub name: ClientName, pub client_type: ClientType,
    pub auth_method: TokenEndpointAuthMethod, pub redirect_uris: Vec<RedirectUri>,
    pub grant_types: BTreeSet<GrantType>, pub allowed_scopes: ScopeSet, pub default_scopes: ScopeSet,
    pub skip_consent: bool, pub active: bool,
    pub created_at: OffsetDateTime, pub updated_at: OffsetDateTime,
}

pub struct RegisteredClient {
    pub client: ClientView,
    /// Some for confidential clients. Shown once; only the hash is stored.
    pub secret: Option<OpaqueToken>,
}

pub struct UserView {
    pub id: UserId, pub username: Username, pub active: bool,
    pub created_at: OffsetDateTime, pub updated_at: OffsetDateTime,
}

impl AdminService {
    pub async fn register_client(&self, ctx: &RequestContext, input: RegisterClient) -> Result<RegisteredClient, AdminError>;
    pub async fn update_client(&self, ctx: &RequestContext, id: &ClientId, update: ClientUpdate) -> Result<ClientView, AdminError>;
    pub async fn rotate_client_secret(&self, ctx: &RequestContext, id: &ClientId) -> Result<OpaqueToken, AdminError>;
    /// Also revokes all active grants of the client (reason ClientDisabled).
    pub async fn disable_client(&self, ctx: &RequestContext, id: &ClientId) -> Result<ClientView, AdminError>;
    pub async fn enable_client(&self, ctx: &RequestContext, id: &ClientId) -> Result<ClientView, AdminError>;
    pub async fn get_client(&self, ctx: &RequestContext, id: &ClientId) -> Result<ClientView, AdminError>;
    pub async fn list_clients(&self, ctx: &RequestContext, page: ListPage<ClientId>) -> Result<Vec<ClientView>, AdminError>;

    pub async fn create_user(&self, ctx: &RequestContext, username: Username, password: NewPassword) -> Result<UserView, AdminError>;
    /// Does not revoke existing login sessions or grants (README Q-8).
    pub async fn set_user_password(&self, ctx: &RequestContext, username: &Username, password: NewPassword) -> Result<UserView, AdminError>;
    /// Also revokes the user's grants (reason UserDisabled) and deletes their login sessions.
    pub async fn disable_user(&self, ctx: &RequestContext, username: &Username) -> Result<UserView, AdminError>;
    pub async fn enable_user(&self, ctx: &RequestContext, username: &Username) -> Result<UserView, AdminError>;
    pub async fn get_user(&self, ctx: &RequestContext, username: &Username) -> Result<UserView, AdminError>;
    pub async fn list_users(&self, ctx: &RequestContext, page: ListPage<Username>) -> Result<Vec<UserView>, AdminError>;
}

pub enum AdminError {
    /// Domain validation or client invariant violation.
    Invalid(DomainError),
    /// allowed_scopes contains a scope not defined in ApplicationConfig::scopes.
    UnknownScope(String),
    /// client_type=public while allow_public_clients=false.
    PublicClientsDisabled,
    NotFound,
    /// Duplicate username.
    Conflict,
    PasswordHash(PasswordHashError),
    Store(StoreError),
}
```

- `register_client` と `update_client`（`allowed_scopes` を変えるとき）は、`allowed_scopes` のすべてが `config.scopes` にあることを確かめる。最初に見つかった未定義のスコープ名を `UnknownScope` に入れる。
- `register_client` は `Confidential` なら `new_opaque_token` でシークレットを作り、そのハッシュを `Client::register` に渡す。
- `get_*` と `list_*` は監査イベントを書かない。`ListPage.limit` は 1〜1000 に丸める。
- `disable_*` と `enable_*` は、すでにその状態でも成功し、`ClientView` / `UserView` を返す。

### MaintenanceService

```rust
pub struct PurgeReport {
    pub counts: PurgeCounts,
    pub audit_events: u64,
}

impl MaintenanceService {
    /// One UoW. cutoff = now - purge_grace for data, now - audit_retention for audit events.
    pub async fn purge_expired(&self, ctx: &RequestContext) -> Result<PurgeReport, StoreError>;
    /// UnitOfWorkFactory::ping.
    pub async fn check_ready(&self) -> Result<(), StoreError>;
}
```

`purge_expired` は監査イベントを書かない（件数はログとメトリクスに出す。[server.md](server.md)）。

## 監査イベント

```rust
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub id: uuid::Uuid,                 // UUIDv7
    pub occurred_at: OffsetDateTime,
    pub kind: AuditKind,
    pub outcome: AuditOutcome,
    pub actor: AuditActor,
    pub request_id: String,
    pub client_ip: Option<IpAddr>,
    pub client_id: Option<ClientId>,
    pub subject: Option<Subject>,
    /// Extra fields. Keys are snake_case ASCII; values must never contain secrets (N-3).
    pub details: BTreeMap<&'static str, String>,
}

pub enum AuditOutcome { Success, Failure }
pub enum AuditActor { Client, User, Admin, System }
impl AuditOutcome { pub fn as_str(&self) -> &'static str; } // "success" / "failure"
impl AuditActor { pub fn as_str(&self) -> &'static str; }   // "client" / "user" / "admin" / "system"
```

`AuditKind` は次の値を持つ enum で、`as_str()` が括弧内の文字列を返す。

| AuditKind（文字列） | 元になるもの | outcome | actor | details |
|---|---|---|---|---|
| `ClientRegistered`（`client.registered`） | `ClientEvent::Registered` | success | admin | `client_type` |
| `ClientUpdated`（`client.updated`） | `ClientEvent::Updated` | success | admin | — |
| `ClientSecretRotated`（`client.secret_rotated`） | `ClientEvent::SecretRotated` | success | admin | — |
| `ClientDisabled`（`client.disabled`） / `ClientEnabled`（`client.enabled`） | `ClientEvent` | success | admin | — |
| `UserCreated`（`user.created`） | `UserEvent::Created` | success | admin | `username` |
| `UserPasswordChanged`（`user.password_changed`） | `UserEvent::PasswordChanged` | success | admin | — |
| `UserDisabled`（`user.disabled`） / `UserEnabled`（`user.enabled`） | `UserEvent` | success | admin | — |
| `LoginSucceeded`（`login.succeeded`） | `login` の成功 | success | user | — |
| `LoginFailed`（`login.failed`） | `login` の失敗 | failure | user | `reason`、`username` |
| `Logout`（`logout`） | `logout` | success | user | — |
| `ConsentGranted`（`consent.granted`） | `ConsentEvent::Granted` | success | user | `scope` |
| `AuthorizationApproved`（`authorization.approved`） | `AuthorizationRequestEvent::Approved` | success | user | `scope` |
| `AuthorizationDenied`（`authorization.denied`） | `AuthorizationRequestEvent::Denied` | failure | user | `scope` |
| `AuthorizationCodeIssued`（`authorization_code.issued`） | `AuthorizationCodeEvent::Issued` | success | user | — |
| `AuthorizationCodeReplayDetected`（`authorization_code.replay_detected`） | `AuthorizationCodeEvent::ReplayDetected` | failure | client | `grant_id` |
| `RefreshTokenReplayDetected`（`refresh_token.replay_detected`） | `RefreshTokenEvent::ReplayDetected` | failure | client | `grant_id` |
| `GrantRevoked`（`grant.revoked`） | `GrantEvent::Revoked` | success | 原因の操作に合わせる（再利用なら client、無効化なら admin） | `grant_id`、`reason`（`code_replay` など snake_case） |
| `TokenIssued`（`token.issued`） | `exchange` の成功 | success | client | `grant_type`、`grant_id`、`scope`、`refresh_token_issued`（`true`/`false`） |
| `ClientAuthenticationFailed`（`client_authentication.failed`） | `exchange` のクライアント認証失敗 | failure | client | `method`（`Basic` → `client_secret_basic`、`Post` → `client_secret_post`、`PublicId` → `none`、`None`（資格情報なし）→ `missing`）、`client_id_presented`（64 文字まで。`None` のときは `null`） |

- ドメインイベントのうち、上の表にないもの（`AuthorizationCodeEvent::Redeemed`、`GrantEvent::Created`、`AccessTokenEvent::Issued`、`RefreshTokenEvent::Issued` / `Rotated`）は、`token.issued` 1 件にまとめて記録し、個別には書かない。
- `scope` は `ScopeSet` の `Display`（スペース区切り）で入れる。

## エラー

| エラー | 発生源 | http / CLI での扱い |
|---|---|---|
| `AuthorizeError::NonRedirectable` | 認可系のユースケース | `400` のエラー画面。種類ごとの文言は [http.md](http.md) |
| `AuthorizeError::Redirect` | 認可系のユースケース | `302` で `location` へ |
| `LoginError::InvalidCredentials` | `login` | `200` でログイン画面を再表示し、「Invalid username or password.」を出す |
| `TokenError` | `exchange` | §5.2 の JSON。ステータスは [http.md](http.md) |
| `AdminError` | `AdminService` | CLI の終了コード（[server.md](server.md)） |
| `StoreError` | すべて | http は `500`（認可系はエラー画面、`/token` は `server_error`）。ログに `error` レベルで出す |

## 設定

`ApplicationConfig` の既定値は上のとおり。設定ファイルとの対応は [server.md](server.md) に書く。

## 受け入れ条件

以下はすべて、`komainu-testing` のインメモリ adapter、`FixedClock`、`SequenceRandom` を使い、`crates/application/tests/*.rs`（結合テスト。ファイルは `admin.rs`、`authorization.rs`、`token.rs`、`maintenance.rs`）で確かめる。

AuthorizationService:

- 有効なクライアントで `start` を呼ぶと、セッションなしなら `LoginRequired` と `csrf_token: Some(_)` を返し、認可リクエストが 1 件保存されている。
- `client_id` が未登録なら `NonRedirectable(UnknownClient)` を返し、認可リクエストは保存されない。
- `redirect_uri` が登録値と 1 文字でも違えば `NonRedirectable(RedirectUriMismatch)` を返す。
- `response_type=token` なら `Redirect` で、`location` は `<redirect_uri>?error=unsupported_response_type&error_description=...&state=xyz` になる。
- `scope=admin`（クライアントに許可されていない）なら `error=invalid_scope` で `Redirect` を返す。
- `require_state=true` で `state` がなければ `error=invalid_request` で `Redirect` を返す。
- `client_id` が 2 回出てくれば `NonRedirectable(DuplicateParameter)`、`scope` が 2 回なら `error=invalid_request` の `Redirect` を返す。
- `login` に間違ったパスワードを渡すと `InvalidCredentials` を返し、`login.failed` の監査イベントが 1 件コミットされている。
- `login` に違う CSRF トークンを渡すと `Authorize(NonRedirectable(CsrfMismatch))` を返す。
- ログイン後の `resume` は `ConsentRequired` を返す。`decide(approve=true)` は `code=<43文字>&state=xyz` 付きの URI を返し、Consent が保存されている。
- 同じユーザーとクライアントで同じスコープの `start` をもう一度呼ぶと、`Redirect`（`code` 付き）を返す。スコープを 1 つ増やすと `ConsentRequired` を返す。
- `skip_consent=true` のクライアントでは、ログイン後の `resume` が `ConsentRequired` を経ずに `Redirect` を返す。
- `decide(approve=false)` は `error=access_denied&state=xyz` 付きの URI を返す。同じ `request_id` でもう一度 `decide` すると `NonRedirectable(RequestNotFound)` を返す。
- 作成から 600 秒たった認可リクエストに `login` すると `Err(LoginError::Authorize(AuthorizeError::NonRedirectable(NonRedirectableError::RequestNotFound)))` を返す。
- 空のパスワードや 129 文字のパスワードで `login` すると `LoginError::InvalidCredentials` を返し、`login.failed`（`details.reason = "invalid_credentials"`）の監査イベントがコミットされている（F-12）。
- 無効にしたユーザーのセッションで `resume` すると `LoginRequired` を返す。

TokenService:

- 発行したコードで `exchange` すると、`expires_in=3600`、`scope` がコードのスコープ、`refresh_token` が `Some`（クライアントが `refresh_token` を持つとき）の応答を返す。
- 同じコードでもう一度 `exchange` すると `InvalidGrant` を返し、1 回目のアクセストークンは `verify_access_token` で `Ok(None)` になる。`authorization_code.replay_detected` と `grant.revoked` の監査イベントがコミットされている。
- 別のクライアントの資格情報でコードを交換すると `InvalidGrant` を返し、コードは未交換のまま残る（本来のクライアントがその後に交換できる）。
- 存在しないクライアント ID で Basic 認証すると `InvalidClient { basic_attempted: true }`、資格情報なしなら `InvalidClient { basic_attempted: false }` を返す。
- `auth_method=client_secret_basic` のクライアントが `Post` で認証すると `InvalidClient` を返す。
- `client_credentials` で `scope` を省略し、クライアントの `default_scopes` が空なら `InvalidScope` を返す。
- `client_credentials` の応答の `refresh_token` は `None`。
- `refresh_token` で交換すると、新しいアクセストークンとリフレッシュトークンを返す。古いリフレッシュトークンでもう一度交換すると `InvalidGrant` を返し、新しいほうのトークンも `verify_access_token` で `Ok(None)` になる。
- Grant のスコープが `{read, write}` のとき、`refresh_token` に `scope=read` を付けると、応答の `scope` は `read`。その後に発行されたリフレッシュトークンで `scope=write` を要求すると成功する。`scope=admin` なら `InvalidScope` を返す。
- `grant_type=password` なら `UnsupportedGrantType` を返す。`client_credentials` を持たないクライアントが `client_credentials` を使うと `UnauthorizedClient` を返す。
- `verify_access_token` は、発行時刻から 3599 秒後なら `Some`、3600 秒後なら `None` を返す。
- 成功した `exchange` ごとに `token.issued` の監査イベントが 1 件あり、その `details` にトークンの平文もハッシュも含まれない。

AdminService:

- `register_client`（confidential）は `secret: Some(_)` を返し、そのシークレットで `exchange` のクライアント認証が通る。
- `config.scopes` にない `read` を `allowed_scopes` に入れると `UnknownScope("read")` を返す。
- `allow_public_clients=false` で `Public` を登録すると `PublicClientsDisabled` を返す。
- `rotate_client_secret` の後、古いシークレットでは認証に失敗し、新しいものでは成功する。
- `disable_client` の後、そのクライアントに発行済みのアクセストークンは `verify_access_token` で `Ok(None)` になる。
- 同じユーザー名（大文字小文字違いを含む）で `create_user` を 2 回呼ぶと、2 回目は `Conflict` を返す。
- `disable_user` の後、そのユーザーのログインセッションは削除され、トークンは検証で無効になる。

MaintenanceService:

- `purge_grace=24h` で、25 時間前と、ちょうど 24 時間前に期限が切れたアクセストークンは削除され、23 時間前に切れたものは残る。
- 91 日前の監査イベントは削除され、89 日前のものは残る。

## 実装メモ

- `Box<dyn UnitOfWork>` から複数のリポジトリを同時に借りられないので、リポジトリの呼び出しは 1 つずつ `uow.clients().find(..).await?` のように書く。
- 監査イベントの組み立ては `audit.rs` に `fn from_client_event(&ClientEvent, &RequestContext, id, now) -> AuditEvent` のような変換関数を置くとまとまる。
- `ScopeSet` の `Display` は辞書順なので、テストで期待値を書くときは辞書順で書く。
