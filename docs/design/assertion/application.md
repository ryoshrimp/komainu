# application（と jose への追加）

- 責務: アサーションの検証規則、JWKS のキャッシュ、トークンエンドポイントのクライアント認証と jwt-bearer グラント、外部発行者と対応表の管理ユースケース、その port を持つ。HTTP の解析と鍵の取得通信はしない（http、adapter-http の責務）。
- 配置: `crates/application`、`crates/jose`
- 関連要件: F-1〜F-13、N-2〜N-5

## jose への追加

`crates/jose/src/jwt.rs`。

```rust
impl Validation {
    /// `new` で渡した audience に加えて受け入れる値を足す。`aud` がいずれか 1 つを含めば通る。
    pub fn accept_audience(mut self, audience: impl Into<String>) -> Self;
}

/// 署名を検証せずに登録クレームだけを読む。どの鍵で検証するかを決めるためだけに使い、
/// 戻り値を信用してはならない。
/// 長さが `max_token_len` を超える、3 セグメントでない、base64url / JSON 不正、
/// 登録クレームの型が不正なら `Malformed` / `InvalidClaim`。
pub fn peek_unverified(token: &str, max_token_len: usize) -> Result<RegisteredClaims, JoseError>;
```

`decode` の `aud` 判定は `validation.audience` と `accept_audience` で足した値のどれかを含むか、に変える。それ以外の判定は変えない。

## 公開インターフェース

### 定数（`crates/application/src/assertion/mod.rs`、`lib.rs` から再公開）

値と意味は [README §4](README.md#4-コンポーネント間の契約) の表のとおり。型はすべて `pub const`:

```rust
pub const CLIENT_ASSERTION_TYPE_JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
pub const GRANT_TYPE_JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
pub const ASSERTION_LEEWAY: time::Duration = time::Duration::seconds(60);
pub const ASSERTION_MAX_LIFETIME: time::Duration = time::Duration::seconds(300);
pub const ASSERTION_MAX_LEN: usize = 8192;
pub const JWKS_CACHE_TTL: time::Duration = time::Duration::seconds(3600);
pub const JWKS_MIN_REFETCH_INTERVAL: time::Duration = time::Duration::seconds(60);
```

`GRANT_TYPE_JWT_BEARER` は `GrantType::JwtBearer.as_str()` と同じ値（http のメトリクスラベル判定で使う）。jose の `Validation::leeway` は `std::time::Duration` を取るので、`assertion/verify.rs` で `ASSERTION_LEEWAY.unsigned_abs()` に変換して渡す。

### ClientAuthentication と TokenRequest（`crates/application/src/token/request.rs`）

```rust
pub enum ClientAuthentication {
    Basic { client_id: String, secret: Secret<String> },
    Post { client_id: String, secret: Secret<String> },
    PublicId { client_id: String },
    /// client_assertion_type が jwt-bearer の URN で、client_assertion がある。
    /// client_id は body に client_id があればその値。
    Assertion { client_id: Option<String>, assertion: Secret<String> },
    None,
}

pub struct TokenRequest {
    // 既存フィールドはそのまま
    /// jwt-bearer グラントの `assertion`。既存の code / refresh_token と同じく
    /// 手書きの Debug で `Redacted` を通し "Some([REDACTED])" と出す。
    pub assertion: Option<String>,
    pub duplicated: Vec<&'static str>,
}
```

`TokenRequest::from_pairs` は `"assertion"` を `collect_params` の名前の配列に加える。2 回以上出現すれば既存どおり `duplicated` に `"assertion"` が入り、`exchange` 冒頭の既存の判定（`duplicated` が空でなければ `InvalidRequest`）で 400 になる。`ClientAuthentication::Assertion` の `Debug` も手書きにし、`assertion` を `[REDACTED]` と出す（`Secret` の `Debug` が既に伏せるなら derive でよい）。`RevocationRequest` は変えない（クライアント認証は `ClientAuthentication` で渡る）。

### ApplicationConfig（`crates/application/src/config.rs`）

```rust
pub struct ApplicationConfig {
    // 既存フィールド
    /// サーバーの issuer 識別子（例 "https://as.example.com"、末尾 / なし）。
    /// アサーションの aud として、この値と "{issuer}/token" を受け入れる。
    /// None なら private_key_jwt と jwt-bearer は無効（広告もしない）。既定 None。
    pub issuer: Option<String>,
}
impl ApplicationConfig {
    pub fn with_issuer(self, issuer: impl Into<String>) -> Self;
}
```

`/revoke` のアサーションも同じ 2 値を受け入れる（RFC 7523 §3 の「トークンエンドポイント URL」に加え、issuer 識別子でもよいとする）。

### Dependencies（`crates/application/src/deps.rs`）

```rust
pub struct Dependencies {
    // 既存フィールド
    pub jwks: Arc<JwksResolver>,
    pub subject_resolver: Arc<dyn AssertionSubjectResolver>,
}
```

### port

`crates/application/src/port/repository.rs` に追加（既存と同じく `&mut self` と `BoxFuture`）。

```rust
pub trait TrustedIssuerRepository: Send {
    fn find(&mut self, id: &IssuerId) -> BoxFuture<'_, Result<Option<TrustedIssuer>, StoreError>>;
    /// 行ロックを取る。
    fn find_for_update(&mut self, id: &IssuerId) -> BoxFuture<'_, Result<Option<TrustedIssuer>, StoreError>>;
    /// 同じ id があれば StoreError::Conflict。
    fn insert(&mut self, issuer: &TrustedIssuer) -> BoxFuture<'_, Result<(), StoreError>>;
    fn update(&mut self, issuer: &TrustedIssuer) -> BoxFuture<'_, Result<(), StoreError>>;
    /// id の昇順。after より大きいものから limit 件。
    fn list(&mut self, page: ListPage<IssuerId>) -> BoxFuture<'_, Result<Vec<TrustedIssuer>, StoreError>>;
}

pub trait SubjectMappingRepository: Send {
    fn find(&mut self, issuer: &IssuerId, subject: &ExternalSubject)
        -> BoxFuture<'_, Result<Option<SubjectMapping>, StoreError>>;
    /// (issuer_id, subject) が同じ行があれば user_id と updated_at を上書きする。
    fn upsert(&mut self, mapping: &SubjectMapping) -> BoxFuture<'_, Result<(), StoreError>>;
    /// 削除したら true、なければ false。
    fn delete(&mut self, issuer: &IssuerId, subject: &ExternalSubject) -> BoxFuture<'_, Result<bool, StoreError>>;
    /// subject の昇順。
    fn list_by_issuer(&mut self, issuer: &IssuerId, page: ListPage<ExternalSubject>)
        -> BoxFuture<'_, Result<Vec<SubjectMapping>, StoreError>>;
}

pub trait UsedAssertionRepository: Send {
    /// (kind, issuer, jti) が未記録なら記録して Recorded、記録済み（期限切れで未削除も含む）なら Replayed。
    /// 同時実行でも Recorded になるのは 1 つだけ。
    fn record(&mut self, used: &UsedAssertion) -> BoxFuture<'_, Result<RecordOutcome, StoreError>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssertionKind { ClientAuthentication, AuthorizationGrant } // DB: "client_authentication" / "authorization_grant"

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsedAssertion {
    pub kind: AssertionKind,
    /// ClientAuthentication ならクライアント ID、AuthorizationGrant なら iss。
    pub issuer: String,
    /// 1〜255 バイト（検証済み）。
    pub jti: String,
    /// アサーションの exp + ASSERTION_LEEWAY。
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordOutcome { Recorded, Replayed }
```

`crates/application/src/port/store.rs`:

- 上の 3 つの Repository trait と `AssertionKind` / `UsedAssertion` / `RecordOutcome` は T3 で作る（`ListPage` は既存の型を使う）。`JwksFetcher` / `AssertionSubjectResolver` 以降は T4。
- `UnitOfWork` に `fn trusted_issuers(&mut self) -> &mut dyn TrustedIssuerRepository;`、`fn subject_mappings(&mut self) -> &mut dyn SubjectMappingRepository;`、`fn used_assertions(&mut self) -> &mut dyn UsedAssertionRepository;` を追加する。
- `PurgeCounts` に `pub used_assertions: u64` を追加する。`PurgeRepository::purge_expired(cutoff)` は `used_assertions` のうち `expires_at < cutoff` を削除する。`cutoff` は既存どおり `MaintenanceService::purge` が渡す値（`now - config.purge_grace`。server では `cleanup.grace_secs`）。`expires_at` には `exp + ASSERTION_LEEWAY` が入っているので、削除されるのは「`exp` + 60 秒 + grace」を過ぎた記録で、その時点ではアサーションは `Expired` で必ず拒否される（F-13、N-2）。

新規 `crates/application/src/port/jwks.rs`:

```rust
pub trait JwksFetcher: Send + Sync + 'static {
    /// uri から JWKS の JSON 本文を取ってくる。パースはしない。
    fn fetch<'a>(&'a self, uri: &'a JwksUri) -> BoxFuture<'a, Result<String, JwksFetchError>>;
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JwksFetchError {
    /// 接続先アドレス・スキームが許されない（SSRF 対策）。
    #[error("destination not allowed")]
    Forbidden,
    #[error("timed out")]
    Timeout,
    /// 200 以外（3xx を含む）。
    #[error("unexpected status {0}")]
    Status(u16),
    #[error("response too large")]
    TooLarge,
    #[error("transport error: {0}")]
    Transport(String),
}
```

新規 `crates/application/src/port/subject.rs`:

```rust
/// アサーションの sub を komainu のユーザーに対応付ける。
pub trait AssertionSubjectResolver: Send + Sync + 'static {
    /// 対応するユーザーがいなければ Ok(None)。ユーザーの状態はここでは見ない（呼び出し側が見る）。
    fn resolve<'a>(
        &'a self,
        uow: &'a mut dyn UnitOfWork,
        issuer: &'a TrustedIssuer,
        subject: &'a ExternalSubject,
    ) -> BoxFuture<'a, Result<Option<UserId>, StoreError>>;
}

/// 既定の実装。uow.subject_mappings().find(issuer.id(), subject) の user_id を返す。
#[derive(Debug, Default, Clone, Copy)]
pub struct MappingTableSubjectResolver;
```

### JwksResolver（`crates/application/src/assertion/jwks.rs`）

```rust
pub struct JwksResolver { /* fetcher, clock, Mutex<HashMap<JwksUri, CacheEntry>> */ }

impl JwksResolver {
    /// fetcher が None なら jwks_uri のクライアントは常に認証失敗（reason "key_fetch_failed"）。
    pub fn new(fetcher: Option<Arc<dyn JwksFetcher>>, clock: Arc<dyn Clock>) -> Self;
}

pub(crate) enum Freshness {
    /// キャッシュが JWKS_CACHE_TTL 以内ならそれを使う。なければ取得するが、
    /// 前回の取得（成功・失敗とも）から JWKS_MIN_REFETCH_INTERVAL 未満なら取得せず RefetchTooSoon。
    Cached,
    /// 前回の取得から JWKS_MIN_REFETCH_INTERVAL 以上経っていれば取り直す。
    /// 経っていなければ TTL 以内のキャッシュを返し、TTL 以内のキャッシュがなければ RefetchTooSoon
    /// （期限切れのキャッシュは返さない。Q-6）。
    Refresh,
}

pub(crate) enum KeyResolveError {
    Fetch(JwksFetchError),
    /// 本文が JWKS としてパースできない、または鍵 0 個。
    InvalidJwks,
    RefetchTooSoon,
}

impl JwksResolver {
    pub(crate) async fn keys(&self, uri: &JwksUri, freshness: Freshness)
        -> Result<Arc<JwkSet>, KeyResolveError>;
}
```

- キャッシュは `std::sync::Mutex<HashMap<JwksUri, CacheEntry>>`（`CacheEntry { keys: Option<(Arc<JwkSet>, fetched_at)>, last_attempt: OffsetDateTime }`）。tokio などの非同期ロックは使わない。application に足す依存は `komainu-jose` だけ。
- `fetch` の成功本文は `JwkSet::from_json` でパースし、失敗または鍵 0 個なら `InvalidJwks`（キャッシュは更新しない、`last_attempt` は更新する）。
- ロックは `await` をまたいで持たない（ロック → 判定 → 解放 → fetch → ロック → 書き込み）。同じ URI への同時取得の重複は許す。
- 取得失敗時は `last_attempt` だけ更新し、既存のキャッシュは消さないが返しもしない（Q-6）。
- エントリー数の上限は設けない（URI はクライアント登録数で抑えられる）。

### verify_assertion（`crates/application/src/assertion/verify.rs`）

```rust
pub(crate) struct Expected<'a> {
    pub issuer: &'a str,
    /// Some なら sub がこの値と一致しなければならない（クライアント認証では client_id）。
    pub subject: Option<&'a str>,
    /// [issuer, "{issuer}/token"]。
    pub audiences: [&'a str; 2],
}

pub(crate) struct VerifiedAssertion {
    pub issuer: String,
    pub subject: String,
    pub jti: String,
    /// `exp` クレームそのもの（猶予は足していない）。記録時に `+ ASSERTION_LEEWAY` する。
    pub exp: OffsetDateTime,
}

pub(crate) fn verify_assertion(
    token: &str,
    keys: &[VerifyingKey],
    expected: &Expected<'_>,
    now: OffsetDateTime,
) -> Result<VerifiedAssertion, AssertionError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AssertionError {
    Malformed, KeyNotFound, Signature, Issuer, Audience, Expired, NotYetValid,
    LifetimeTooLong, MissingSubject, SubjectMismatch, MissingJti,
}
impl AssertionError {
    /// 監査の reason。"malformed", "key_not_found", "signature", "issuer", "audience",
    /// "expired", "not_yet_valid", "lifetime_too_long", "missing_sub", "subject_mismatch", "missing_jti"
    pub fn reason(&self) -> &'static str;
}
```

## データ

application はデータを持たない（キャッシュはメモリのみ）。永続化は [adapters.md](adapters.md)。

## 振る舞い

### verify_assertion の手順

1. `jose::jwt::decode::<NoCustomClaims>(token, keys, &Validation::new(expected.issuer, audiences[0]).accept_audience(audiences[1]).leeway(ASSERTION_LEEWAY).max_token_len(ASSERTION_MAX_LEN), now)`。alg は jose が RS256 / ES256 以外（`none`、`HS*` を含む）を拒否する。`typ` は要求しない。
2. jose のエラーを写す（`JoseError` の全バリアント）:

| `JoseError` | `AssertionError` | reason |
|---|---|---|
| `KeyNotFound` | `KeyNotFound` | `key_not_found` |
| `InvalidSignature`、`AlgorithmMismatch`、`UnsupportedAlgorithm`（`alg=none`、`HS256` など） | `Signature` | `signature` |
| `InvalidIssuer`、`MissingClaim("iss")` | `Issuer` | `issuer` |
| `InvalidAudience`、`MissingClaim("aud")` | `Audience` | `audience` |
| `Expired`、`MissingClaim("exp")` | `Expired` | `expired` |
| `NotYetValid`（`nbf` が未来）、`InvalidClaim("iat")`（`iat` が猶予を超えて未来） | `NotYetValid` | `not_yet_valid` |
| `Malformed`、`UnsupportedHeader`、`InvalidTyp`、`InvalidClaim`（`iat` 以外）、`DuplicateClaim`、`MissingClaim`（上記以外）、`InvalidValue`、`InvalidKey`、`KeyGeneration`、`Encoding` | `Malformed` | `malformed` |

`JoseError` は `#[non_exhaustive]`（`crates/jose/src/error.rs:6`）なので、表のバリアントを列挙したうえで末尾に `_ => Malformed` を置く（jose に将来足されるバリアントは `malformed` になる）。`InvalidClaim("iat")` は `iat` の型不正でも出るが、区別せず `NotYetValid` とする。
3. `sub` がない・空 → `MissingSubject`。`expected.subject` があり不一致 → `SubjectMismatch`。
4. `jti` がない、空、255 バイト超 → `MissingJti`。
5. `exp - now > ASSERTION_MAX_LIFETIME` → `LifetimeTooLong`（境界: ちょうど 300 秒は通す）。

### クライアント認証（`TokenService::authenticate_client` の `Assertion` 分岐）

既存の失敗処理（uow を捨て、新しい uow で `client.authentication_failed` を記録し、`TokenError::InvalidClient { basic_attempted: false }`）を使う。監査の details は `method = "private_key_jwt"`、`client_id_presented`（`truncate_chars` 64、既存どおり値がなければ文字列 `"null"`）、`reason`。`reason` は `Assertion` 分岐の失敗にだけ付け、既存の `PublicId` / `Basic` / `Post` 分岐の監査 details は変えない（N-5）。

| 順 | 処理 | 失敗時の応答 | 監査 reason |
|---|---|---|---|
| 1 | `config.issuer` が None（uow・DB 参照の前に判定） | 401 `invalid_client` | `not_configured` |
| 2 | `peek_unverified(assertion, ASSERTION_MAX_LEN)` が成功し、`iss` と `sub` が両方ある | 401 `invalid_client` | `malformed` |
| 2' | `iss` ≠ `sub` | 401 `invalid_client` | `subject_mismatch` |
| 3 | `client_id` 引数が Some で `iss` と不一致 | 400 `invalid_request`（`TokenError::InvalidRequest`） | 監査なし |
| 4 | `ClientId::try_new(iss)` → `clients().find` → 存在・`is_active`・`auth_method() == PrivateKeyJwt` | 401 `invalid_client` | `unknown_client`（`try_new` 失敗も含む） / `client_disabled` / `method_not_allowed` |
| 5 | 鍵: `Jwks` は `JwkSet::from_json`、`JwksUri` は `jwks.keys(uri, Freshness::Cached)` | 401 `invalid_client` | `invalid_jwks`（`KeyResolveError::InvalidJwks` も） / `key_fetch_failed`（`KeyResolveError::Fetch(_)` のすべての種類、fetcher なし、`Cached` での `RefetchTooSoon` を含む） |
| 6 | `verify_assertion`（`Expected { issuer: iss, subject: Some(iss), audiences }`）。`JwksUri` で `KeyNotFound` なら `jwks.keys(uri, Freshness::Refresh)` で取り直して 1 回だけ再検証。`Refresh` が `RefetchTooSoon` なら再検証せず `key_not_found`、取り直しが失敗なら `key_fetch_failed`、再検証の失敗はその `reason()` | 401 `invalid_client` | `AssertionError::reason()` |
| 7 | `used_assertions().record(ClientAuthentication, iss, jti, exp + ASSERTION_LEEWAY)` が `Replayed` | 401 `invalid_client` | `replay` |

body の `client_id` は省略してよい（RFC 7523 §3）。省略時はアサーションの `iss`（= `sub`）をクライアント ID として扱う。

`client_id_presented` は手順 2 以降で読めた `iss`、読めなければ `client_id` 引数、どちらもなければ `"null"`。

既存の `PublicId` / `Basic` / `Post` の分岐は、`auth_method() == PrivateKeyJwt` のクライアントに対して既存の失敗処理（details は既存のまま）で失敗する（`secret_hash` がないため）。

`revoke()` も `authenticate_client` を使うので、追加の変更はない（F-7）。

### jwt-bearer グラント（`TokenService::exchange`）

- `grant_type` の分岐に `"urn:ietf:params:oauth:grant-type:jwt-bearer"` を加える。`config.issuer` が None なら `UnsupportedGrantType`（uow を開く前）。
- クライアント認証・`supports_grant(GrantType::JwtBearer)`（なければ `UnauthorizedClient`）は既存の共通処理。
- `request.assertion` が None → `InvalidRequest`。

失敗は uow を捨て、新しい uow で監査 `assertion.rejected`（details: `issuer_presented` truncate 64、`client_id`、`reason`）を記録して `TokenError::InvalidGrant`。

| 順 | 処理 | 失敗時の reason |
|---|---|---|
| 1 | `peek_unverified` → `iss` → `IssuerId::try_new` | `malformed` |
| 2 | `trusted_issuers().find` が Some・`is_active`・`allows_client(client.id())` | `unknown_issuer` / `issuer_disabled` / `client_not_allowed` |
| 3 | `JwkSet::from_json(issuer.jwks())` | `invalid_jwks` |
| 4 | `verify_assertion`（`Expected { issuer: iss, subject: None, audiences }`） | `AssertionError::reason()` |
| 5 | `ExternalSubject::try_new(sub)` → `subject_resolver.resolve(uow, &issuer, &subject)` が Some | `malformed` / `unknown_subject` |
| 6 | `users().find(user_id)` が Some かつ有効 | `user_disabled`（存在しないときも同じ） |
| 7 | `used_assertions().record(AuthorizationGrant, iss, jti, exp + ASSERTION_LEEWAY)` が `Replayed` | `replay` |

続けて `client.resolve_scope(request.scope)`（失敗は既存どおり `InvalidScope`、監査なし）→ `Grant::for_jwt_bearer(new grant id, client_id, Subject::from(user_id), scope, now)` → `issue_tokens(uow, client, grant, scope, refresh = false, now)`。監査 `token.issued` の details は既存の項目に `issuer` を加える。

### jti の記録とトランザクション

`record` は要求の uow の中で行い、要求の成功時に commit される。後続の処理で失敗して uow を捨てると記録も消える（Q-3）。

### AdminService

`crates/application/src/admin/mod.rs`（クライアント）と新規 `crates/application/src/admin/issuer.rs`（発行者）。

```rust
pub struct RegisterClient {
    // 既存フィールド
    /// auth_method が PrivateKeyJwt のとき必須、それ以外は None。
    pub keys: Option<ClientKeys>,
}
pub struct ClientView {
    // 既存フィールド
    pub keys: Option<ClientKeys>,
}
// RegisteredClient::secret は PrivateKeyJwt では None。
// update_client は ClientUpdate::keys をそのまま渡す。

pub struct RegisterIssuer {
    pub id: IssuerId,
    pub jwks: JwksDocument,
    pub allowed_clients: BTreeSet<ClientId>,
}
pub struct IssuerView {
    pub id: IssuerId,
    pub jwks: JwksDocument,
    pub allowed_clients: BTreeSet<ClientId>,
    pub status: IssuerStatus,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}
pub struct SubjectMappingView {
    pub issuer_id: IssuerId,
    pub subject: ExternalSubject,
    pub user_id: UserId,
    pub username: Username,
    pub updated_at: OffsetDateTime,
}

impl AdminService {
    pub async fn register_issuer(&self, ctx: &RequestContext, input: RegisterIssuer) -> Result<IssuerView, AdminError>;
    pub async fn update_issuer(&self, ctx: &RequestContext, id: &IssuerId, update: TrustedIssuerUpdate) -> Result<IssuerView, AdminError>;
    pub async fn disable_issuer(&self, ctx: &RequestContext, id: &IssuerId) -> Result<IssuerView, AdminError>;
    pub async fn enable_issuer(&self, ctx: &RequestContext, id: &IssuerId) -> Result<IssuerView, AdminError>;
    pub async fn get_issuer(&self, _ctx: &RequestContext, id: &IssuerId) -> Result<IssuerView, AdminError>;
    pub async fn list_issuers(&self, _ctx: &RequestContext, page: ListPage<IssuerId>) -> Result<Vec<IssuerView>, AdminError>;
    pub async fn map_subject(&self, ctx: &RequestContext, issuer: &IssuerId, subject: ExternalSubject, username: &Username) -> Result<SubjectMappingView, AdminError>;
    pub async fn unmap_subject(&self, ctx: &RequestContext, issuer: &IssuerId, subject: &ExternalSubject) -> Result<(), AdminError>;
    pub async fn list_subject_mappings(&self, _ctx: &RequestContext, issuer: &IssuerId, page: ListPage<ExternalSubject>) -> Result<Vec<SubjectMappingView>, AdminError>;
}
```

上の形は既存の `register_client` / `disable_client`（`ctx: &RequestContext` を取る）と `get_client` / `list_clients`（`_ctx` を取るが使わない）に揃えてある。

- JWKS の検査（クライアントの `ClientKeys::Jwks` と発行者の `jwks`）: `JwkSet::from_json` が成功し、読み込めた鍵（`from_json` が対応外の kty / crv / use / alg を読み飛ばした後の数）が 1〜10 個。JSON 上の要素数には別の上限を設けない（長さは `JwksDocument` の 65536 バイトで抑える）。失敗は `AdminError::InvalidJwks(String)`。文字列は jose のエラーなら `JoseError` の `Display`、鍵数なら `"expected 1 to 10 usable keys, found N"`。秘密鍵成分を含む JWK は jose が `InvalidKey("private key parameters")` で拒否する。`ClientKeys::JwksUri` は登録時に取得しない。
- `register_issuer` / `update_issuer` の検査順: domain の不変条件（`allowed_clients` 1〜100 個など。`DomainError` → `AdminError::Invalid`）→ JWKS の検査 → クライアントの実在。
- `register_issuer` / `update_issuer` の `allowed_clients` は全員が実在すること。いなければ `AdminError::UnknownClient(ClientId)`（最初に見つかった 1 つ）。操作対象（発行者）の不在ではなく入力値の誤りなので `NotFound`（終了コード 3）ではなく終了コード 2 にする。
- `map_subject`: 発行者がなければ `NotFound`、`users().find_by_username` がなければ `NotFound`。無効なユーザーにも対応付けはできる（グラント時に拒否される）。`unmap_subject` は削除対象がなければ `NotFound`。
- 監査: `issuer.registered` / `issuer.updated` / `issuer.disabled` / `issuer.enabled`（`IssuerEvent` から）、`issuer.subject_mapped`（details: `issuer`、`subject` truncate 64、`user_id`）、`issuer.subject_unmapped`（details: `issuer`、`subject` truncate 64）。

`AdminError` に追加: `InvalidJwks(String)`、`UnknownClient(ClientId)`。どちらも `#[error(...)]` を付け、CLI では終了コード 2。

### AuditKind（`crates/application/src/audit.rs`）

追加: `IssuerRegistered`（`"issuer.registered"`）、`IssuerUpdated`（`"issuer.updated"`）、`IssuerDisabled`（`"issuer.disabled"`）、`IssuerEnabled`（`"issuer.enabled"`）、`SubjectMapped`（`"issuer.subject_mapped"`）、`SubjectUnmapped`（`"issuer.subject_unmapped"`）、`AssertionRejected`（`"assertion.rejected"`）。

### ServerCapabilities（`crates/application/src/capabilities.rs`）

```rust
pub struct ServerCapabilities {
    // 既存フィールド
    /// private_key_jwt を広告するとき [RS256, ES256]、しないとき空。
    pub token_endpoint_auth_signing_algs: Vec<komainu_jose::Algorithm>,
    /// token_endpoint_auth_signing_algs と同じ。
    pub revocation_endpoint_auth_signing_algs: Vec<komainu_jose::Algorithm>,
}
```

`from_config` の結果（`revocation_endpoint_auth_methods` は常に `token_endpoint_auth_methods` と同じ、`revocation_endpoint_auth_signing_algs` は常に `token_endpoint_auth_signing_algs` と同じ）:

| `issuer` | `allow_public_clients` | `grant_types` | `token_endpoint_auth_methods` | `token_endpoint_auth_signing_algs` |
|---|---|---|---|---|
| None | false | `[AuthorizationCode, ClientCredentials, RefreshToken]` | `[ClientSecretBasic, ClientSecretPost]` | `[]` |
| None | true | 同上 | `[ClientSecretBasic, ClientSecretPost, None]` | `[]` |
| Some | false | `[AuthorizationCode, ClientCredentials, RefreshToken, JwtBearer]` | `[ClientSecretBasic, ClientSecretPost, PrivateKeyJwt]` | `[RS256, ES256]` |
| Some | true | 同上 | `[ClientSecretBasic, ClientSecretPost, PrivateKeyJwt, None]` | `[RS256, ES256]` |

None の 2 行は既存と同じ値。T6 の時点では Some の行の `grant_types` に `JwtBearer` を入れない（未実装のグラントを広告しない）。T7 で `JwtBearer` を足す。

## エラー

| 状況 | 返すもの | 呼び出し側の扱い |
|---|---|---|
| クライアントアサーションの不備 | `TokenError::InvalidClient { basic_attempted: false }` / `RevocationError::InvalidClient { basic_attempted: false }` | http は 401、`WWW-Authenticate` なし |
| `client_id` とアサーションの `iss` の不一致 | `TokenError::InvalidRequest` | 400 |
| グラントアサーションの不備 | `TokenError::InvalidGrant` | 400 |
| `assertion` なし | `TokenError::InvalidRequest` | 400 |
| `issuer` 未設定で jwt-bearer | `TokenError::UnsupportedGrantType` | 400 |
| `record` などのストア障害 | `TokenError::Server(StoreError)` | 500（既存どおり） |
| JWKS 不正（管理） | `AdminError::InvalidJwks` | CLI 終了コード 2 |
| 許可クライアントが存在しない | `AdminError::UnknownClient` | CLI 終了コード 2 |

## 設定

| キー | 型 | 既定値 | 意味 |
|---|---|---|---|
| `ApplicationConfig::issuer` | `Option<String>` | `None` | アサーションの `aud` の基準。facade が `HttpConfig` から自動設定する（[http-server.md](http-server.md#komainu-facade)） |

## 受け入れ条件

「検証」は `crates/application/src/assertion/verify.rs`、「JWKS キャッシュ」は `crates/application/src/assertion/jwks.rs` の `#[cfg(test)]` 単体テスト（`pub(crate)` の項目を直接使うため）。「クライアント認証」「グラント」は `crates/application/tests/token.rs` と `crates/application/tests/revocation.rs`（公開 API の `TokenService` 経由）、`crates/application/tests/admin.rs`、`crates/application/tests/capabilities.rs`。アサーションはテスト内で `komainu_jose::SigningKey::generate_es256` と `jwt::encode` で作る。時刻は testkit のフェイク時計。

検証:

- `now` = T、`exp` = T+60 の正しいアサーションは通る。`exp` = T+300 は通り、T+301 は `LifetimeTooLong`。`exp` = T-59 は通り、T-60 は `Expired`。
- `aud` が `https://as.example.com`、`https://as.example.com/token`、両方を含む配列のどれでも通る。`https://as.example.com/revoke` は `Audience`。
- `sub` なし → `MissingSubject`、`jti` なし・空・256 バイト → `MissingJti`。
- `alg=none` と `HS256` のヘッダーは通らない。RS256 鍵と ES256 鍵の両方で通る。

JWKS キャッシュ（`StaticJwksFetcher` は呼び出し回数を数える）:

- 同じ URI を 2 回 `Cached` で引くと fetch 1 回。T+3600 秒で引くと 2 回目の fetch。
- 取得から 59 秒後の `Refresh` は fetch せずキャッシュを返す。60 秒後は fetch する。
- キャッシュなしで fetch が `Timeout` を返すと `KeyResolveError::Fetch(Timeout)`。
- TTL 内のキャッシュがある状態で `Refresh` の fetch が `Timeout` を返すと `KeyResolveError::Fetch(Timeout)`、その直後の `Cached` は TTL 内のキャッシュを返す（失敗はキャッシュを消さない）。TTL 切れ後の `Cached` で fetch が失敗すると、古いキャッシュは返さず `Fetch`（Q-6）。その 59 秒後の `Cached` は fetch せず `RefetchTooSoon`、60 秒後は fetch する。
- TTL 切れのキャッシュだけがあり前回取得から 60 秒未満の `Refresh` は `RefetchTooSoon`。
- fetcher が None の `JwksResolver` は `KeyResolveError::Fetch(JwksFetchError::Transport("no fetcher configured"))` を返す。

クライアント認証:

- F-2、F-3 の各ケースが `TokenError` と監査（`InMemoryUnitOfWorkFactory::audit_events`）で確かめられる。
- 同じアサーションで 2 回 `client_credentials` を要求すると、2 回目は `InvalidClient`、reason `replay`。
- `jwks_uri` のクライアントで、キャッシュにない `kid` のアサーションを取得 60 秒後に送ると fetch が 1 回増えて成功する。
- `revoke` に正しいアサーションで成功、不正で `RevocationError::InvalidClient`。
- `issuer` 未設定の `ApplicationConfig` では、正しいアサーションでも `InvalidClient`（reason `not_configured`）。
- `StaticJwksFetcher` に未設定の URI（`Status(404)`）でも、fetcher なしの `TestEnv` でも、`jwks_uri` のクライアントの監査 reason は `key_fetch_failed`。

グラント:

- F-10、F-11 の各ケース。成功時 `TokenResponse::refresh_token` は None、`verify_access_token` の `subject` は `Subject::from(user_id)`、grant の origin は `JwtBearer`。
- 対応付けたユーザーを `disable_user` で無効化すると、jwt-bearer で発行済みのグラントも既存の仕組みで失効する（`list_active_by_subject`）。
- `AssertionSubjectResolver` を常に固定ユーザーを返すフェイクに差し替えると、対応表なしで成功する。

管理・能力:

- `register_client` に `PrivateKeyJwt` と鍵 11 個の JWKS → `InvalidJwks`。`register_issuer` に存在しないクライアント → `UnknownClient`、同じ id を 2 回 → `Conflict`。
- `capabilities.rs`: `issuer` 未設定なら既存と同じ値。設定時は上記の並びで、`allow_public_clients = true` なら `[ClientSecretBasic, ClientSecretPost, PrivateKeyJwt, None]`。

## 実装メモ

- `komainu-jose` の `Algorithm` を `ServerCapabilities` に出すため、`komainu-application` が `komainu-jose` に依存する（通常依存）。
- `authenticate_client` の現在のメソッドラベル（`"client_secret_basic"` など）に `"private_key_jwt"` を足す。
- `Secret<String>` は domain から再公開されている既存の型を使う。
