# adapters（adapter-postgres、testkit、adapter-http）

- 責務: 新しい port の永続化（PostgreSQL とインメモリ）と conformance、`jwks_uri` の HTTP 取得と SSRF 対策。
- 配置: `crates/adapter-postgres`、`crates/testkit`、新規 `crates/adapter-http`
- 関連要件: F-1、F-5、F-6、F-8、F-9、F-13、N-1、N-2

## データ

### マイグレーション `crates/adapter-postgres/migrations/0004_assertion.sql`

既存の制約名（PostgreSQL の自動命名 `<table>_<column>_check`）を `DROP` して付け直す。0002 と同じやり方。

変えない既存制約: `grants` の表レベル CHECK（`origin <> 'authorization_code' OR origin_code_hash IS NOT NULL`）はそのまま（`jwt_bearer` は `origin_code_hash` が NULL で満たす）。`clients.secret_hash` の CHECK（NULL か 32 バイト）もそのまま。`auth_method` と `secret_hash` の組み合わせは DB では縛らず、既存どおり domain の不変条件で守る。

`clients_keys_check` の意図: `auth_method = 'private_key_jwt'` の行は `jwks` と `jwks_uri` のちょうど一方が非 NULL、それ以外の行は両方 NULL。

```sql
-- clients: private_key_jwt と鍵
ALTER TABLE clients DROP CONSTRAINT clients_auth_method_check;
ALTER TABLE clients ADD CONSTRAINT clients_auth_method_check
    CHECK (auth_method IN ('client_secret_basic', 'client_secret_post', 'none', 'private_key_jwt'));
ALTER TABLE clients
    ADD COLUMN jwks text CHECK (jwks IS NULL OR octet_length(jwks) BETWEEN 1 AND 65536),
    ADD COLUMN jwks_uri text CHECK (jwks_uri IS NULL OR octet_length(jwks_uri) BETWEEN 1 AND 2048),
    ADD CONSTRAINT clients_keys_check CHECK (
        (auth_method = 'private_key_jwt') = (jwks IS NOT NULL OR jwks_uri IS NOT NULL)
        AND NOT (jwks IS NOT NULL AND jwks_uri IS NOT NULL)
    );

-- grants: jwt-bearer 由来
ALTER TABLE grants DROP CONSTRAINT grants_origin_check;
ALTER TABLE grants ADD CONSTRAINT grants_origin_check
    CHECK (origin IN ('authorization_code', 'client_credentials', 'jwt_bearer'));

CREATE TABLE trusted_issuers (
    id text PRIMARY KEY CHECK (octet_length(id) BETWEEN 1 AND 255),
    jwks text NOT NULL CHECK (octet_length(jwks) BETWEEN 1 AND 65536),
    status text NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE trusted_issuer_clients (
    issuer_id text NOT NULL REFERENCES trusted_issuers (id) ON DELETE CASCADE,
    client_id text NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
    PRIMARY KEY (issuer_id, client_id)
);

CREATE TABLE issuer_subjects (
    issuer_id text NOT NULL REFERENCES trusted_issuers (id) ON DELETE CASCADE,
    subject text NOT NULL CHECK (octet_length(subject) BETWEEN 1 AND 255),
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (issuer_id, subject)
);

CREATE TABLE used_assertions (
    kind text NOT NULL CHECK (kind IN ('client_authentication', 'authorization_grant')),
    issuer text NOT NULL CHECK (octet_length(issuer) BETWEEN 1 AND 255),
    jti text NOT NULL CHECK (octet_length(jti) BETWEEN 1 AND 255),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (kind, issuer, jti)
);
CREATE INDEX used_assertions_expires_at_idx ON used_assertions (expires_at);
```

- `clients.id` は 0001 で `text`、`users.id` は `uuid`。
- クライアントの物理削除は現状ないが、外部キーは `ON DELETE CASCADE` にしておく。

### 列と domain の対応

| テーブル.列 | domain |
|---|---|
| `clients.jwks` / `clients.jwks_uri` | `ClientRecord::keys`（`Jwks` → `jwks`、`JwksUri` → `jwks_uri`、`None` → 両方 NULL）。読み出しで両方非 NULL の行、または `jwks` が `JwksDocument::try_new` / `jwks_uri` が `JwksUri::try_new` に通らない行は、既存の `crates/adapter-postgres/src/error.rs` の `corrupted("jwks")` / `corrupted("jwks_uri")` で `StoreError::Other`（`Client::from_record` は検証しないので adapter で検査する） |
| `grants.origin = 'jwt_bearer'` | `GrantOrigin::JwtBearer`（`origin_code_hash` は NULL） |
| `trusted_issuers` + `trusted_issuer_clients` | `TrustedIssuerRecord`（`allowed_clients` は子テーブル） |
| `issuer_subjects` | `SubjectMapping` |
| `used_assertions` | `UsedAssertion`（`kind` は `AssertionKind` の文字列） |

## 公開インターフェース

### adapter-postgres

新規 `crates/adapter-postgres/src/{trusted_issuer.rs,subject_mapping.rs,used_assertion.rs}` に `PgTrustedIssuerRepository` などを置き、`crates/adapter-postgres/src/uow.rs` の `PgUnitOfWork` が `UnitOfWork::{trusted_issuers, subject_mappings, used_assertions}` で返す。既存リポジトリと同じく非公開型。

| メソッド | SQL の要点 |
|---|---|
| `TrustedIssuerRepository::find` / `find_for_update` | `trusted_issuers` を id で取得（`find_for_update` は `FOR UPDATE`）し、`trusted_issuer_clients` を `client_id` 昇順で取得 |
| `insert` | `INSERT trusted_issuers`（一意違反は既存の写しで `StoreError::Conflict`）、子テーブルへ一括 `INSERT` |
| `update` | `UPDATE trusted_issuers`、子テーブルは `DELETE` してから入れ直す |
| `list` | `WHERE id > $after ORDER BY id LIMIT $limit`、子テーブルは `WHERE issuer_id = ANY($ids)` でまとめて取る |
| `SubjectMappingRepository::upsert` | `INSERT ... ON CONFLICT (issuer_id, subject) DO UPDATE SET user_id, updated_at` |
| `delete` | `DELETE ... RETURNING 1` の有無で bool |
| `UsedAssertionRepository::record` | `INSERT ... ON CONFLICT (kind, issuer, jti) DO NOTHING`。影響行数 1 → `Recorded`、0 → `Replayed` |
| `PurgeRepository::purge_expired` | 既存の削除に `DELETE FROM used_assertions WHERE expires_at < $cutoff` を加え、件数を `PurgeCounts::used_assertions` に入れる |

`record` は `ON CONFLICT DO NOTHING` なので、同時に同じキーを挿入しても後の方は先の commit / rollback を待ってから 0 行になる（先が rollback なら 1 行）。これで N-2 を満たす。

### testkit

- `crates/testkit/src/store.rs`: `InMemoryState` に `trusted_issuers: BTreeMap<IssuerId, TrustedIssuerRecord>`、`subject_mappings: BTreeMap<(IssuerId, ExternalSubject), SubjectMapping>`、`used_assertions: BTreeMap<(AssertionKind, String, String), OffsetDateTime>` を加え、既存と同じくトランザクション単位でコピー・反映する。`record` の判定は uow 内のコピーに対して行う（インメモリは直列実行なので同時実行の検査は PostgreSQL 側のみ）。
- `crates/testkit/src/env.rs` の `TestEnv`: `TestEnv::new` は `jwks: JwksResolver::new(None, clock)`、`subject_resolver: MappingTableSubjectResolver` で組む。差し替え用に次を足す（どちらも `self.deps` の該当フィールドを置き換える）。

```rust
impl TestEnv {
    /// 自身の clock を使う JwksResolver::new(Some(fetcher), clock) に置き換える。
    pub fn with_jwks_fetcher(self, fetcher: Arc<dyn JwksFetcher>) -> Self;
    pub fn with_subject_resolver(self, resolver: Arc<dyn AssertionSubjectResolver>) -> Self;
}
```

- 新規 `crates/testkit/src/jwks.rs`（`lib.rs` から `pub use jwks::StaticJwksFetcher`）:

```rust
/// URI ごとに決めた応答を返すフェイク。呼び出し回数を数える。
#[derive(Debug, Default, Clone)]
pub struct StaticJwksFetcher { /* Arc<Mutex<..>> */ }

impl StaticJwksFetcher {
    pub fn new() -> Self;
    /// uri への応答を設定する（上書き）。
    pub fn set(&self, uri: &JwksUri, response: Result<String, JwksFetchError>);
    /// uri への fetch の呼び出し回数。
    pub fn calls(&self, uri: &JwksUri) -> usize;
}
// 未設定の uri は Err(JwksFetchError::Status(404))。
// JwksFetchError は Clone でないので、Err は種類を保存して毎回作り直す。
```

- `crates/testkit/src/conformance/cases.rs` に下記の受け入れ条件のケースを加え、`store_cases()` に登録する。`fixtures.rs` に発行者・対応表の作成ヘルパーを加える。

## komainu-adapter-http（新規）

### 配置

```
crates/adapter-http/
  Cargo.toml   # name = "komainu-adapter-http"
  README.md
  src/lib.rs   # ReqwestJwksFetcher, JwksFetcherConfig, BuildError
  src/ip.rs    # is_global(IpAddr) -> bool
  tests/fetch.rs
```

依存: `komainu-application`、`komainu-domain`、`reqwest.workspace = true`（T5 でルートの定義を `default-features = false, features = ["rustls"]` に減らし、`cookies` はそれを使う `crates/server` の dev 依存側で足す。reqwest 0.13.5 のソースで確認済み: 本文の上限読みに使う `Response::chunk()` と、`ClientBuilder::dns_resolver` / `reqwest::dns::{Resolve, Resolving, Addrs, Name}` は feature なしで使える。`stream` は `bytes_stream()` 用なので不要、`hickory-dns` は組み込みの hickory リゾルバー用なので不要）、`tokio = { workspace = true, features = ["net"] }`、`thiserror.workspace = true`、`tracing.workspace = true`。dev: `tokio`（`macros`, `rt-multi-thread`）、`axum`（テスト用サーバー）。ルート `Cargo.toml` の `members` と `[workspace.dependencies]` に `komainu-adapter-http = { path = "crates/adapter-http", version = "..." }` を足す（既存の adapter と同じ書き方）。

### 公開インターフェース

```rust
#[derive(Debug, Clone)]
pub struct JwksFetcherConfig {
    /// 接続から本文読み終わりまでの全体の制限。既定 5 秒。
    pub timeout: Duration,
    /// 本文の最大バイト数。既定 65536。
    pub max_body_bytes: usize,
    /// true ならグローバルでないアドレスと http スキームを許す。テスト専用。既定 false。
    pub allow_non_global_for_testing: bool,
}
impl Default for JwksFetcherConfig { /* 上の既定値 */ }

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("failed to build HTTP client: {0}")]
    Client(String),
}

pub struct ReqwestJwksFetcher { /* reqwest::Client, config */ }

impl ReqwestJwksFetcher {
    pub fn new(config: JwksFetcherConfig) -> Result<Self, BuildError>;
}
impl JwksFetcher for ReqwestJwksFetcher { /* ... */ }
```

### 振る舞い

`reqwest::Client` は 1 度だけ作る:

- `redirect(Policy::none())`、`no_proxy()`、`timeout(config.timeout)`、`user_agent("komainu/<version>")`、`https_only(!allow_non_global_for_testing)`。
- `dns_resolver(Arc<GlobalOnlyResolver>)`: `tokio::net::lookup_host((host, 0))` の結果から `is_global` でないアドレスを除く。残りが 0 個なら resolve をエラーにする（reqwest からは connect エラーとして返る）。`allow_non_global_for_testing` なら除かない。

`fetch(uri)`:

1. URL のホストが IP リテラルなら、その場で `is_global` を確かめ、偽なら `Forbidden`（リテラルは DNS リゾルバーを通らないため）。スキームが https でない（テスト設定以外）も `Forbidden`。
2. `GET`、`Accept: application/json`。
3. エラーの写し: タイムアウト → `Timeout`。名前解決で全アドレスが除かれた → `Forbidden`（リゾルバーのエラー型で判別）。その他の接続・TLS エラー → `Transport(エラーの表示)`。
4. ステータスが 200 以外（3xx を含む） → `Status(code)`。
5. `Content-Length` が `max_body_bytes` を超えていれば読まずに `TooLarge`。本文は `Response::chunk()` をループで呼んで読み、累計が超えた時点で `TooLarge`（`bytes()` は上限なしで全部読むので使わない）。
6. UTF-8 でなければ `Transport("invalid utf-8")`。本文を返す（JSON の検査は application）。

### `is_global(IpAddr) -> bool`（`src/ip.rs`）

偽にするもの:

- IPv4: `0.0.0.0/8`、`10.0.0.0/8`、`100.64.0.0/10`、`127.0.0.0/8`、`169.254.0.0/16`、`172.16.0.0/12`、`192.0.0.0/24`、`192.0.2.0/24`、`192.88.99.0/24`、`192.168.0.0/16`、`198.18.0.0/15`、`198.51.100.0/24`、`203.0.113.0/24`、`224.0.0.0/4`、`240.0.0.0/4`（`255.255.255.255` を含む）
- IPv6: `::/128`、`::1/128`、`::ffff:0:0/96`（中の IPv4 で判定する）、`64:ff9b::/96`（中の IPv4 で判定する）、`100::/64`、`2001::/23`、`2001:db8::/32`、`fc00::/7`、`fe80::/10`、`ff00::/8`

それ以外は真。

### エラー

application の `JwksFetchError` をそのまま返す（[application.md §port](application.md#port)）。ログには URI と種類を `tracing::warn!` で出す（本文は出さない）。

### 設定

| 項目 | 既定値 | 変更方法 |
|---|---|---|
| `timeout` | 5 秒 | `JwksFetcherConfig`（server の設定ファイルには出さない） |
| `max_body_bytes` | 65536 | 同上 |
| `allow_non_global_for_testing` | false | 同上。server からは常に false |

## 受け入れ条件

conformance（`cargo test -p komainu-testkit` と `cargo test -p komainu-adapter-postgres --features pg-tests` の両方で通る）:

- `private_key_jwt` のクライアントを `Jwks` で保存して読み出すと同じ `ClientRecord` になる。`JwksUri` でも同じ。
- `GrantOrigin::JwtBearer` のグラントを保存して読み出せる。
- 発行者を insert → find で同じ内容（`allowed_clients` を含む）。同じ id の insert は `Conflict`。`update` で `allowed_clients` を {A,B} から {B,C} にすると find が {B,C}。`list` が id の昇順で `after` / `limit` に従う。
- 対応表: upsert → find、同じキーで別ユーザーを upsert すると上書き、delete が true、2 回目の delete が false、`list_by_issuer` が subject の昇順。
- `record` を同じ (kind, issuer, jti) で 2 回呼ぶと `Recorded` → `Replayed`。kind が違えば両方 `Recorded`。commit 前に uow を捨てると、次の uow の `record` は `Recorded`。
- `purge_expired(cutoff)` が `expires_at < cutoff` の記録だけを消し、件数を返す。

PostgreSQL のみ（`crates/adapter-postgres/tests/` の pg-tests）:

- 2 つの接続で同じキーを同時に `record` して両方 commit すると、`Recorded` は 1 つだけ。
- `0004` 適用後、既存の `client_secret_basic` クライアントが読み出せる（既存データへの影響なし）。`auth_method='private_key_jwt'` で鍵なしの行の INSERT は制約違反。

adapter-http（`crates/adapter-http/tests/fetch.rs`、ローカルの axum サーバーを `allow_non_global_for_testing = true` で叩く。SSRF の拒否は既定設定で確かめる）:

- 200 と JWKS の本文 → 本文が返る。
- 302 → `Status(302)` で、リダイレクト先にはリクエストが来ない。
- 500 → `Status(500)`。
- 6 秒待ってから応答（`timeout` を 1 秒に設定）→ `Timeout`。
- 65537 バイトの本文（`Content-Length` あり・なしの両方）→ `TooLarge`。65536 バイトは成功。
- 既定設定で `https://127.0.0.1/`、`https://[::1]/`、`https://10.0.0.1/`、`https://169.254.169.254/` → `Forbidden`（接続しない）。`https://localhost/` → `Forbidden`。
- `is_global` のユニットテスト（`src/ip.rs`）: 上の各範囲の先頭・末尾のアドレスが偽、`8.8.8.8`、`2606:4700::1111` が真、`::ffff:127.0.0.1` が偽。

## 実装メモ

- reqwest 0.13 の `dns_resolver<R: IntoResolve>(self, resolver: R)` は `Arc<R: Resolve>` を受け取る。`trait Resolve: Send + Sync { fn resolve(&self, name: Name) -> Resolving; }`、`Resolving = Pin<Box<dyn Future<Output = Result<Addrs, Box<dyn Error + Send + Sync>>> + Send>>`、`Addrs = Box<dyn Iterator<Item = SocketAddr> + Send>`。ホスト名は `Name::as_str()`。名前解決エラーを判別するため、
リゾルバー独自のエラー型 `ForbiddenAddress` を `std::error::Error::source()` のチェーンで `downcast_ref` して探す。
- チェーンからたどれない場合の代替（実装者が選んでよい）: `fetch` の冒頭で自分で `tokio::net::lookup_host` し、グローバルでないアドレスが残らなければ `Forbidden` を返す。接続はリゾルバー経由のままにする（再バインド対策はリゾルバー側の除外で保つ）。どちらでも受け入れ条件「`https://localhost/` → `Forbidden`」を満たすこと。
- `HTTPS_PROXY` などの環境変数は `no_proxy()` で無視する。
