# adapter crate 群

port の実装を 3 つの crate に分ける。

| crate | 責務 | 配置 |
|---|---|---|
| komainu-adapter-postgres | `UnitOfWorkFactory` と全リポジトリの PostgreSQL 実装、マイグレーション | `crates/adapter-postgres` |
| komainu-adapter-std | `Clock`、`SecureRandom`、`PasswordHasher` の本番実装 | `crates/adapter-std` |
| komainu-testing | テスト用のインメモリ実装（`publish = false`） | `crates/testing` |

- 関連要件: N-1、N-2、N-5、F-12、F-13

## komainu-adapter-postgres

### 公開インターフェース

依存: `komainu-application`、`komainu-domain`、`sqlx = "0.9"`（features は README §3.1）、`time`、`uuid`、`serde_json = "1"`、`thiserror`。dev-dependencies: `komainu-adapter-std`、`komainu-testing`、`testcontainers-modules = "0.15"`（`postgres`）、`tokio`（`macros`, `rt-multi-thread`）。feature `pg-tests` を有効にしたときだけ結合テストを動かす（`#![cfg(feature = "pg-tests")]`）。

```rust
#[derive(Debug, Clone)]
pub struct PgStoreConfig {
    /// postgres://... (never logged)
    pub url: Secret<String>,
    pub max_connections: u32,        // default 10
    pub acquire_timeout: Duration,   // default 5s (std::time::Duration)
}

/// Creates a pool. Does not run migrations.
pub async fn connect(config: &PgStoreConfig) -> Result<sqlx::PgPool, StoreError>;
/// Runs embedded migrations (sqlx::migrate!("./migrations")).
pub async fn migrate(pool: &sqlx::PgPool) -> Result<(), StoreError>;

#[derive(Clone)]
pub struct PgUnitOfWorkFactory { /* PgPool */ }
impl PgUnitOfWorkFactory { pub fn new(pool: sqlx::PgPool) -> Self; }
impl UnitOfWorkFactory for PgUnitOfWorkFactory { /* begin: pool.begin(); ping: SELECT 1 */ }
```

`PgUnitOfWork`（非公開）は `sqlx::Transaction<'static, Postgres>` を持ち、すべてのリポジトリ trait を自分で実装する。`fn clients(&mut self) -> &mut dyn ClientRepository { self }` の形で返す。

### エラーの変換

| sqlx のエラー | `StoreError` |
|---|---|
| `Database` で SQLSTATE `23505`（一意制約違反） | `Conflict` |
| `Database` で SQLSTATE `40001`、`40P01` | `Unavailable` |
| `PoolTimedOut`、`PoolClosed`、`Io`、`Tls` | `Unavailable` |
| それ以外（列の型の不一致、domain の値として不正な値を含む） | `Other` |

DB から読んだ値を domain の型に戻すときに `try_new` が失敗したら、`Other("corrupted <table>.<column>")` にする。

### ロック

`find_for_update` と `list_active_by_*` は `SELECT ... FOR UPDATE` で読む。トランザクションの分離レベルは PostgreSQL の既定（READ COMMITTED）のまま。同じ認可コードを並行して交換すると、2 つ目以降はロックを待ち、1 つ目のコミット後に `Redeemed` の行を読む（N-5）。

## データ

`crates/adapter-postgres/migrations/0001_init.sql` で次のテーブルを作る。時刻はすべて `timestamptz`、ハッシュは `bytea`（32 バイト）。スコープは辞書順に並べた `text[]`。enum は domain の `as_str()` の文字列を `text` で持ち、`CHECK` で値を制限する。列名は domain の `XxxRecord` のフィールド名と同じにする（例外は表に書く）。

### clients

| 列 | 型 | 制約 |
|---|---|---|
| `id` | `text` | PK |
| `name` | `text` | NOT NULL |
| `client_type` | `text` | NOT NULL、`confidential` / `public` |
| `auth_method` | `text` | NOT NULL、`client_secret_basic` / `client_secret_post` / `none` |
| `secret_hash` | `bytea` | NULL 可 |
| `redirect_uris` | `text[]` | NOT NULL（登録順） |
| `grant_types` | `text[]` | NOT NULL |
| `allowed_scopes` | `text[]` | NOT NULL |
| `default_scopes` | `text[]` | NOT NULL |
| `skip_consent` | `boolean` | NOT NULL |
| `status` | `text` | NOT NULL、`active` / `disabled` |
| `created_at`、`updated_at` | `timestamptz` | NOT NULL |

### users

| 列 | 型 | 制約 |
|---|---|---|
| `id` | `uuid` | PK |
| `username` | `text` | NOT NULL、UNIQUE（domain で小文字にしてあるので、そのまま一意にする） |
| `password_hash` | `text` | NOT NULL（PHC 文字列） |
| `status` | `text` | NOT NULL、`active` / `disabled` |
| `created_at`、`updated_at` | `timestamptz` | NOT NULL |

### login_sessions

| 列 | 型 | 制約 |
|---|---|---|
| `id` | `bytea` | PK（セッショントークンのハッシュ） |
| `subject` | `text` | NOT NULL、INDEX |
| `created_at` | `timestamptz` | NOT NULL |
| `expires_at` | `timestamptz` | NOT NULL、INDEX |

### authorization_requests

| 列 | 型 | 制約 |
|---|---|---|
| `id` | `uuid` | PK |
| `client_id` | `text` | NOT NULL、FK `clients(id)` |
| `redirect_uri` | `text` | NOT NULL |
| `redirect_uri_provided` | `boolean` | NOT NULL |
| `scope` | `text[]` | NOT NULL |
| `state` | `text` | NULL 可 |
| `csrf_token_hash` | `bytea` | NOT NULL |
| `status` | `text` | NOT NULL、`pending` / `approved` / `denied` |
| `subject` | `text` | NULL 可 |
| `created_at`、`updated_at` | `timestamptz` | NOT NULL |
| `expires_at` | `timestamptz` | NOT NULL、INDEX |

### authorization_codes

| 列 | 型 | 制約 |
|---|---|---|
| `id` | `bytea` | PK（コードのハッシュ） |
| `client_id` | `text` | NOT NULL、FK `clients(id)` |
| `subject` | `text` | NOT NULL |
| `redirect_uri` | `text` | NOT NULL |
| `redirect_uri_provided` | `boolean` | NOT NULL |
| `scope` | `text[]` | NOT NULL |
| `status` | `text` | NOT NULL、`issued` / `redeemed` |
| `grant_id` | `uuid` | NULL 可（`redeemed` のとき必須。`CHECK`）、FK `grants(id)` |
| `redeemed_at` | `timestamptz` | NULL 可（`redeemed` のとき必須） |
| `issued_at` | `timestamptz` | NOT NULL |
| `expires_at` | `timestamptz` | NOT NULL、INDEX |

`AuthorizationCodeStatus::Redeemed { grant_id, redeemed_at }` は `status`・`grant_id`・`redeemed_at` の 3 列に分けて持つ。

### consents

| 列 | 型 | 制約 |
|---|---|---|
| `subject` | `text` | PK の一部 |
| `client_id` | `text` | PK の一部、FK `clients(id)` |
| `scope` | `text[]` | NOT NULL |
| `created_at`、`updated_at` | `timestamptz` | NOT NULL |

### grants

| 列 | 型 | 制約 |
|---|---|---|
| `id` | `uuid` | PK |
| `client_id` | `text` | NOT NULL、FK `clients(id)` |
| `subject` | `text` | NULL 可 |
| `scope` | `text[]` | NOT NULL |
| `origin` | `text` | NOT NULL、`authorization_code` / `client_credentials` |
| `origin_code_hash` | `bytea` | NULL 可（`origin=authorization_code` のとき必須）。FK は張らない（コードは先に削除されるため） |
| `status` | `text` | NOT NULL、`active` / `revoked` |
| `revoked_at` | `timestamptz` | NULL 可 |
| `revocation_reason` | `text` | NULL 可、`code_replay` / `refresh_token_replay` / `client_disabled` / `user_disabled` |
| `created_at` | `timestamptz` | NOT NULL |

部分インデックス: `(client_id) WHERE status = 'active'`、`(subject) WHERE status = 'active'`。

### access_tokens

| 列 | 型 | 制約 |
|---|---|---|
| `id` | `bytea` | PK（トークンのハッシュ） |
| `grant_id` | `uuid` | NOT NULL、FK `grants(id)`、INDEX |
| `client_id` | `text` | NOT NULL |
| `subject` | `text` | NULL 可 |
| `scope` | `text[]` | NOT NULL |
| `issued_at` | `timestamptz` | NOT NULL |
| `expires_at` | `timestamptz` | NOT NULL、INDEX |

### refresh_tokens

| 列 | 型 | 制約 |
|---|---|---|
| `id` | `bytea` | PK（トークンのハッシュ） |
| `grant_id` | `uuid` | NOT NULL、FK `grants(id)`、INDEX |
| `client_id` | `text` | NOT NULL |
| `status` | `text` | NOT NULL、`active` / `rotated` |
| `rotated_at` | `timestamptz` | NULL 可 |
| `issued_at` | `timestamptz` | NOT NULL |
| `expires_at` | `timestamptz` | NOT NULL、INDEX |

### audit_events

| 列 | 型 | 制約 |
|---|---|---|
| `id` | `uuid` | PK |
| `occurred_at` | `timestamptz` | NOT NULL、INDEX |
| `kind` | `text` | NOT NULL |
| `outcome` | `text` | NOT NULL、`success` / `failure` |
| `actor` | `text` | NOT NULL |
| `request_id` | `text` | NOT NULL |
| `client_ip` | `inet` | NULL 可 |
| `client_id` | `text` | NULL 可（FK は張らない） |
| `subject` | `text` | NULL 可 |
| `details` | `jsonb` | NOT NULL（`AuditEvent.details` を文字列の値だけを持つオブジェクトにしたもの） |

インデックス: `(client_id, occurred_at)`、`(subject, occurred_at)`。

### purge の SQL の順序

`purge_expired(cutoff)` は 1 つのトランザクションの中で、次の順に `DELETE ... WHERE expires_at <= $1` を実行する: `authorization_codes` → `access_tokens` → `refresh_tokens` → `authorization_requests` → `login_sessions`。最後に `grants` を `created_at <= $1 AND NOT EXISTS (access_tokens) AND NOT EXISTS (refresh_tokens) AND NOT EXISTS (authorization_codes.grant_id)` で削除する。

## komainu-adapter-std

依存: `komainu-application`、`komainu-domain`、`time`、`rand = "0.10"`、`argon2 = "0.6"`、`tokio`（`rt`。`spawn_blocking` のため）。

```rust
pub struct SystemClock;                 // OffsetDateTime::now_utc()
impl Clock for SystemClock {}

pub struct OsSecureRandom;              // OS の乱数源。失敗したら panic する（続行できないため）
impl SecureRandom for OsSecureRandom {}

pub struct Argon2PasswordHasher { /* params + dummy hash */ }
impl Argon2PasswordHasher {
    /// Argon2id v0x13 with argon2 crate defaults. Computes a dummy hash for verify_dummy.
    pub fn new() -> Result<Self, PasswordHashError>;
}
impl PasswordHasher for Argon2PasswordHasher {}
```

- `hash` と `verify` は `tokio::task::spawn_blocking` の中で計算する。クロージャには、パスワードを `Secret::new(password.expose().to_owned())` で複製した `Secret<String>` を move で渡す（`Secret` は drop 時に zeroize するので、複製した平文もスレッドの終了時に消える）。`String` のまま渡さない。`spawn_blocking` が失敗したら、`hash` は `PasswordHashError`、`verify` は `false` を返す。
- `hash` の結果は PHC 文字列（`$argon2id$v=19$...`）。ソルトは `OsSecureRandom` 相当の OS 乱数で 16 バイト作る。
- `verify_dummy` は `new` で作っておいたダミーのハッシュに対して `verify` を実行し、結果を捨てる。

## komainu-testing

`publish = false`。application、http、server のテストの dev-dependency として使う。

```rust
/// Snapshot-and-replace store. Not safe for concurrent writers (tests are sequential).
#[derive(Clone, Default)]
pub struct InMemoryUnitOfWorkFactory { /* Arc<Mutex<InMemoryState>> */ }
impl InMemoryUnitOfWorkFactory {
    pub fn new() -> Self;
    /// Committed audit events in append order.
    pub fn audit_events(&self) -> Vec<AuditEvent>;
    /// Committed state, for assertions.
    pub fn state(&self) -> InMemoryState;
    /// The next begin()/ping() returns StoreError::Unavailable.
    pub fn fail_next(&self);
}

#[derive(Clone, Default)]
pub struct InMemoryState {
    pub clients: BTreeMap<ClientId, ClientRecord>,
    pub users: BTreeMap<UserId, UserRecord>,
    pub login_sessions: BTreeMap<TokenHash, LoginSessionRecord>,
    pub authorization_requests: BTreeMap<AuthorizationRequestId, AuthorizationRequestRecord>,
    pub authorization_codes: BTreeMap<TokenHash, AuthorizationCodeRecord>,
    pub consents: BTreeMap<ConsentId, ConsentRecord>,
    pub grants: BTreeMap<GrantId, GrantRecord>,
    pub access_tokens: BTreeMap<TokenHash, AccessTokenRecord>,
    pub refresh_tokens: BTreeMap<TokenHash, RefreshTokenRecord>,
    pub audit_events: Vec<AuditEvent>,
}

#[derive(Clone)]
pub struct FixedClock { /* Arc<Mutex<OffsetDateTime>> */ }
impl FixedClock {
    pub fn new(at: OffsetDateTime) -> Self;
    pub fn set(&self, at: OffsetDateTime);
    pub fn advance(&self, by: Duration);
}

/// Deterministic: fills bytes from an incrementing u64 counter (little endian, repeated).
/// Every call yields a different byte sequence.
#[derive(Clone, Default)]
pub struct SequenceRandom { /* Arc<AtomicU64> */ }

/// hash = "plain$" + password; verify compares strings. verify_dummy does nothing.
pub struct PlainPasswordHasher;

/// Dependencies wired with the in-memory adapters, FixedClock at 2026-01-01T00:00:00Z,
/// SequenceRandom, PlainPasswordHasher and BuiltinAuthenticator.
pub struct TestEnv {
    pub deps: Dependencies,
    pub store: InMemoryUnitOfWorkFactory,
    pub clock: FixedClock,
}
impl TestEnv {
    pub fn new(config: ApplicationConfig) -> Self;
}
```

- `begin` は確定済みの状態を複製して UoW に持たせ、`commit` で複製を確定済みの状態と置き換える。drop すれば何も残らない。
- `insert` で ID が重複すれば `Conflict`。`users` はユーザー名の重複も `Conflict` にする。
- `find_for_update` は `find` と同じ（ロックしない）。

## エラー

| 状況 | 返すもの | 呼び出し側の扱い |
|---|---|---|
| DB に接続できない、プールが枯渇 | `StoreError::Unavailable` | application がそのまま返し、http が `500` / `readyz` が `503` |
| 一意制約違反 | `StoreError::Conflict` | `AdminService` が `AdminError::Conflict` にする |
| マイグレーションの失敗 | `StoreError::Other` | `komainu migrate` が終了コード 1 で終わる |

## 設定

`PgStoreConfig` の 3 項目（`database.url`、`database.max_connections`、`database.acquire_timeout_secs`）。設定ファイルとの対応は [server.md](server.md)。

## 受け入れ条件

adapter-postgres（`--features pg-tests`、testcontainers の `postgres:16-alpine`）:

- 監査ログ以外の各リポジトリで、`insert` → commit → 別の UoW で読み直すと、`to_record()` が等しい集約が返る。読み直しに使うメソッドは、`find` があるものは `find`、`find_for_update` しかないもの（`AuthorizationRequestRepository`、`RefreshTokenRepository` など）は `find_for_update`。`AuditLogRepository` は、`append` → commit の後に `SELECT count(*) FROM audit_events WHERE kind = $1` で 1 件になることを確かめる。
- commit せずに UoW を drop すると、別の UoW から見えない。
- 同じユーザー名の `insert` は `StoreError::Conflict` を返す。
- 同じ認可コードに対して、`TokenService::exchange`（PgUnitOfWorkFactory、SystemClock、OsSecureRandom を使う）を 10 個並行に呼ぶと、成功は 1 つで、残り 9 つは `InvalidGrant` になる。その後、その Grant は `revoked`（`code_replay`）になっている。
- トークン発行後の `access_tokens.id` は、平文のトークンの SHA-256 と一致し、平文はどの列にも保存されていない。`users.password_hash` は `$argon2id$` で始まる。
- `purge_expired(cutoff)` は、`expires_at <= cutoff` の行だけを削除し、件数を `PurgeCounts` で返す。トークンが残っている Grant は削除しない。
- 未適用の DB に `migrate` を 2 回続けて実行しても、2 回目はエラーにならない。

adapter-std:

- `OsSecureRandom` で作った `new_opaque_token` の結果は 43 文字で、`[A-Za-z0-9_-]` だけを含む。1000 回作って重複がない。
- `Argon2PasswordHasher` で `hash` した値は、同じパスワードで `verify` すると `true`、違うパスワードで `false` を返す。同じパスワードを 2 回 `hash` すると別の文字列になる。
- `verify` に PHC 形式でない文字列を渡すと `false` を返す（panic しない）。

komainu-testing:

- `insert` → commit → 別の UoW で `find` できる。commit せずに drop すると見えない。
- `fail_next()` の後の `begin` は `Unavailable` を返し、その次の `begin` は成功する。

## 実装メモ

- `sqlx::query!` のコンパイル時検査を使うと、CI に DB か `.sqlx` のオフラインデータが要る。使うなら `cargo sqlx prepare` の結果をコミットし、CI で `SQLX_OFFLINE=true` にする。使わない場合は `sqlx::query_as` と `FromRow` で書く（どちらでもよい）。
- `text[]` と `ScopeSet` の変換は、`Vec<String>` を経由して `ScopeToken::try_new` を通す。
