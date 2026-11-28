# 署名鍵: domain・永続化・暗号化・SigningKeyService

[README](README.md) に戻る。

## domain

### 責務・配置・関連要件

- 配置: 新規 `crates/domain/src/signing_key/`（`mod.rs` で再公開、`crates/domain/src/lib.rs` から `pub use signing_key::*`）
- 責務: 鍵の値・時刻・状態の判定と、ローテーションで何を作り何を消すかの計算（I/O なし、乱数なし）
- 関連要件: F-2、F-3、F-5、F-6

### 公開インターフェース

```rust
// key.rs

/// The JWS algorithm of an AS signing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SigningAlgorithm { Es256, Rs256 }
impl SigningAlgorithm {
    /// "ES256" / "RS256"
    pub fn as_str(&self) -> &'static str;
}
impl FromStr for SigningAlgorithm { type Err = DomainError; } // "ES256" / "RS256" のみ（大文字小文字を区別）。他は DomainError

/// kid: RFC 7638 thumbprint. 1..=64 chars of [A-Za-z0-9_-].
#[derive(ValueObject)] // 既存の値オブジェクトと同じ derive・validate の書き方
pub struct SigningKeyId(String);

/// Sealed (encrypted) private key bytes. 1..=16384 bytes.
/// Debug は手書きで長さだけ出す: `SealedPrivateKey(<N bytes>)`。
#[derive(Clone, PartialEq, Eq)]
pub struct SealedPrivateKey(Vec<u8>);
impl SealedPrivateKey {
    pub fn new(bytes: Vec<u8>) -> Result<Self, DomainError>;
    pub fn as_bytes(&self) -> &[u8];
}

/// Public key as a JWK JSON object string. 1..=8192 bytes, starts with '{'.
/// 中身の JWK としての妥当性は application（jose）が保証する。domain は長さと先頭文字だけ見る。
#[derive(ValueObject)] // SigningKeyId と同じ（Debug・Clone・PartialEq・Eq は ValueObject の derive が付ける）
pub struct PublicJwk(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStatus { Pending, Active, Retired, Expired }

/// Entity / AggregateRoot の derive は付けない（ドメインイベントを持たない。状態は時刻から決まり、
/// 監査は application が書く）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSigningKey { /* private fields: ServerSigningKeyRecord と同じ */ }

/// Persistence form of [`ServerSigningKey`]（既存の `TrustedIssuerRecord` などと同じ形）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSigningKeyRecord {
    pub kid: SigningKeyId,
    pub algorithm: SigningAlgorithm,
    pub sealed_private_key: SealedPrivateKey,
    pub public_jwk: PublicJwk,
    pub created_at: OffsetDateTime,
    pub activates_at: OffsetDateTime,
    pub retires_at: OffsetDateTime,
    pub deletes_at: OffsetDateTime,
}

impl ServerSigningKey {
    /// created_at <= activates_at <= retires_at <= deletes_at でなければ DomainError。
    pub fn new(record: ServerSigningKeyRecord) -> Result<Self, DomainError>;
    /// 永続化からの復元。既存の from_record と同じく検証しない（時刻の順序は DB の CHECK が保証する）。
    pub fn from_record(record: ServerSigningKeyRecord) -> Self;
    pub fn to_record(&self) -> ServerSigningKeyRecord;

    pub fn kid(&self) -> &SigningKeyId;
    pub fn algorithm(&self) -> SigningAlgorithm;
    pub fn sealed_private_key(&self) -> &SealedPrivateKey;
    pub fn public_jwk(&self) -> &PublicJwk;
    pub fn created_at(&self) -> OffsetDateTime;
    pub fn activates_at(&self) -> OffsetDateTime;
    pub fn retires_at(&self) -> OffsetDateTime;
    pub fn deletes_at(&self) -> OffsetDateTime;

    /// now < activates_at → Pending
    /// activates_at <= now < retires_at → Active
    /// retires_at <= now < deletes_at → Retired
    /// deletes_at <= now → Expired
    pub fn status_at(&self, now: OffsetDateTime) -> KeyStatus;

    /// JWKS に載せるか（Pending・Active・Retired）。
    pub fn is_published_at(&self, now: OffsetDateTime) -> bool;

    /// 即時退役。retires_at = min(retires_at, now)、deletes_at = min(deletes_at, 更新後の retires_at + overlap)。
    /// Pending の鍵も対象（activates_at > now なら activates_at = now にそろえて不変条件を保つ）。
    /// Retired / Expired の鍵には何もしない（false を返す）。変えたら true。
    pub fn retire(&mut self, now: OffsetDateTime, overlap: Duration) -> bool;

    /// Pending の鍵を即現役にする: activates_at = now（retires_at・deletes_at は変えない）。
    /// Pending でなければ何もしない（false）。変えたら true。
    pub fn activate_now(&mut self, now: OffsetDateTime) -> bool;
}

/// 署名に使う鍵: keys のうち algorithm が一致し status_at(now) == Active のもので、
/// activates_at が最大のもの（同じなら kid の辞書順で最大）。無ければ None。
pub fn current_key<'a>(
    keys: &'a [ServerSigningKey],
    algorithm: SigningAlgorithm,
    now: OffsetDateTime,
) -> Option<&'a ServerSigningKey>;
```

```rust
// policy.rs

/// Lifetimes of AS signing keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigningPolicy { /* private */ }

impl SigningPolicy {
    /// 検証（違反は DomainError）:
    /// - prepublish >= 1 時間
    /// - active_period > prepublish
    /// - retire_overlap >= 0（Duration が負なら違反）
    pub fn new(active_period: Duration, prepublish: Duration, retire_overlap: Duration)
        -> Result<Self, DomainError>;
    pub fn active_period(&self) -> Duration;   // 既定 90 日
    pub fn prepublish(&self) -> Duration;      // 既定 7 日
    pub fn retire_overlap(&self) -> Duration;  // 既定 7 日
}
impl Default for SigningPolicy { /* 90 日・7 日・7 日 */ }
```

```rust
// rotation.rs

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyToCreate {
    pub algorithm: SigningAlgorithm,
    pub activates_at: OffsetDateTime,
    /// activates_at + active_period
    pub retires_at: OffsetDateTime,
    /// retires_at + retire_overlap
    pub deletes_at: OffsetDateTime,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RotationPlan {
    /// algorithms の順（同じアルゴリズムは高々 1 件）
    pub create: Vec<KeyToCreate>,
    /// 即現役にする Pending の鍵（algorithms の順、同じアルゴリズムは高々 1 件）
    pub activate: Vec<SigningKeyId>,
    /// kid の辞書順
    pub delete: Vec<SigningKeyId>,
}

/// 定期ローテーションの計画。
pub fn plan_rotation(
    keys: &[ServerSigningKey],
    algorithms: &[SigningAlgorithm],
    now: OffsetDateTime,
    policy: &SigningPolicy,
) -> RotationPlan;

/// 即時ローテーション（F-5）で作る鍵: activates_at = now。
pub fn immediate_key(algorithm: SigningAlgorithm, now: OffsetDateTime, policy: &SigningPolicy) -> KeyToCreate;
```

### 振る舞い（plan_rotation）

1. `delete`: `status_at(now) == Expired` のすべての鍵（`algorithms` に無いアルゴリズムの鍵も含む）。
2. `algorithms` の各アルゴリズム `a` について（`delete` 対象の鍵は除いて考える）:
   - `cur = current_key(keys, a, now)`
   - `cur` が無く、`a` の Pending の鍵がある → そのうち `activates_at` が最も早いもの（同じなら kid の辞書順で最小）を `activate` に入れ、作らない。署名できない状態を早く解消することを優先する（公開から間がない鍵だと、検証側の JWKS キャッシュが切れるまで検証に失敗し得るが許容する）。
   - `cur` も Pending も無い → `activates_at = now` で 1 件作る（起動直後・全鍵失効後・停止が長かった場合）。
   - `cur` があり、`a` の Pending の鍵で `activates_at >= cur.retires_at` のものが無く、`now >= cur.retires_at - prepublish` → `activates_at = cur.retires_at` で 1 件作る。
   - それ以外 → 作らない。
3. `algorithms` に無いアルゴリズムの鍵は作らず、期限どおりに消えるのを待つ。

例（既定値、`t0` に空の DB で起動）: `t0` に鍵 A（activates t0、retires t0+90d、deletes t0+97d）。`t0+83d` 以降の最初の実行で鍵 B（activates t0+90d）。`t0+90d` から B で署名。`t0+97d` 以降の最初の実行で A を削除。

### エラー

| 場面 | エラー | 呼び出し側の扱い |
|------|--------|------------------|
| 値オブジェクト・`ServerSigningKey::new`・`SigningPolicy::new` の検証違反 | `DomainError`（既存の型。必要ならバリアントを追加） | adapter は読み出した列の値オブジェクトの変換に失敗したら既存の `corrupted("signing_keys.<列名>")` を返す。`SigningPolicy::new` 失敗は設定エラー |

### 受け入れ条件（domain）

- `status_at` が各境界（`activates_at` ちょうど、`retires_at` ちょうど、`deletes_at` ちょうど）で上の表どおりになる。
- `current_key` が、同じアルゴリズムの Active が 2 つあるとき `activates_at` の新しい方を返し、別アルゴリズムの鍵を返さない。
- `plan_rotation`:
  - 鍵が無い → `algorithms` の各アルゴリズムに `activates_at = now` が 1 件ずつ。
  - 現役鍵の `retires_at - prepublish` の 1 秒前 → 作らない。ちょうど → `activates_at = retires_at` で 1 件。
  - 次の鍵がすでにある → 作らない。
  - `deletes_at <= now` の鍵は `delete` に入り、`algorithms` から外したアルゴリズムの鍵も同様。外したアルゴリズムの鍵は作らない。
  - 現役鍵が無く Pending が 2 つある → `create` は空、`activate` に `activates_at` の早い方の kid が 1 つ。
- `activate_now`: Pending の鍵で `activates_at == now` になり `status_at(now) == Active`。Active の鍵には `false`。
- `retire`: Active の鍵で `retires_at == now`・`deletes_at == now + overlap`、Pending の鍵で `activates_at == retires_at == now`。Retired の鍵には `false` で変化なし。
- `SigningPolicy::new`: `prepublish = 59 分` → エラー、`active_period == prepublish` → エラー、既定値 → Ok。
- `SealedPrivateKey` の `Debug` がバイト列の中身を含まない。

## 永続化

### 公開インターフェース（port）

`crates/application/src/port/repository.rs` に追加し、`UnitOfWork` に `fn signing_keys(&mut self) -> &mut dyn SigningKeyRepository;` を `purge` の前に足す。

```rust
pub trait SigningKeyRepository: Send {
    /// ローテーション用の排他ロックを取る。UoW の終了（commit / drop）まで保持。
    /// 取れるまで待つ（タイムアウトはしない。DB の statement_timeout に任せる）。
    fn lock_rotation(&mut self) -> BoxFuture<'_, Result<(), StoreError>>;
    /// すべての鍵。activates_at 昇順、同じなら kid 昇順。
    fn list(&mut self) -> BoxFuture<'_, Result<Vec<ServerSigningKey>, StoreError>>;
    /// kid が重複したら StoreError::Conflict。
    fn insert(&mut self, key: &ServerSigningKey) -> BoxFuture<'_, Result<(), StoreError>>;
    /// activates_at・retires_at・deletes_at だけを更新する。行が無ければ StoreError::Other("signing key not found")。
    fn update_schedule(&mut self, key: &ServerSigningKey) -> BoxFuture<'_, Result<(), StoreError>>;
    /// 消したら true、行が無ければ false。
    fn delete(&mut self, kid: &SigningKeyId) -> BoxFuture<'_, Result<bool, StoreError>>;
}
```

### データ（`crates/adapter-postgres/migrations/0005_signing_keys.sql`）

```sql
CREATE TABLE signing_keys (
    kid text PRIMARY KEY,
    alg text NOT NULL CHECK (alg IN ('ES256', 'RS256')),
    sealed_private_key bytea NOT NULL,
    public_jwk text NOT NULL,
    created_at timestamptz NOT NULL,
    activates_at timestamptz NOT NULL,
    retires_at timestamptz NOT NULL,
    deletes_at timestamptz NOT NULL,
    CHECK (created_at <= activates_at AND activates_at <= retires_at AND retires_at <= deletes_at)
);
```

- `lock_rotation`: `SELECT pg_advisory_xact_lock(hashtextextended('komainu:signing_keys', 0))`。
- 読み出した行は各列を値オブジェクトに変換して `ServerSigningKeyRecord` を作り、`ServerSigningKey::from_record` で復元する。変換に失敗したら既存の `corrupted("signing_keys.<列名>")`（中身は出さない）。`alg` は `SigningAlgorithm::from_str`。
- 期限切れの行の削除は `rotate_due` が行う。`PurgeRepository::purge_expired` には足さない。

### インメモリ（`crates/testkit/src/store.rs`）

- `InMemoryState` に `signing_keys: BTreeMap<String, ServerSigningKey>` を足す。
- `lock_rotation` は何もしない（インメモリの UoW はコミット時に状態を丸ごと差し替えるため、排他は保証しない。N-2 は PostgreSQL でだけ確かめる）。

### 受け入れ条件（永続化）

conformance（`crates/testkit/src/conformance/cases.rs` に追加。インメモリと PostgreSQL の両方で走る）:

- `insert` → コミット → 新しい UoW の `list` で `==`（`PartialEq`）が成り立つ値が返る。順序は `activates_at` 昇順。
- 同じ kid の `insert` は `Conflict`。
- `update_schedule` で 3 つの時刻だけが変わる。存在しない kid は `Other`。
- `delete` は存在すれば `true`、2 回目は `false`。
- コミットしない UoW の `insert` は他の UoW から見えない。

PostgreSQL のみ（`crates/adapter-postgres/tests/`）:

- 2 つの UoW で `lock_rotation` を取ると、2 つ目は 1 つ目のコミットまで返らない（`tokio::time::timeout(200ms)` で 2 つ目が未完了であることを確かめ、1 つ目のコミット後に完了する）。
- N-2 のテスト（`SigningKeyService` を使うので T4 で書く。`crates/adapter-postgres/tests/signing_keys.rs`、`pg-tests` feature）: 空の DB・同じプールで `SigningKeyService` を 2 つ作り、`tokio::join!` で `rotate_due` を同時に呼ぶと、2 つの `RotationReport::created` の件数の合計が `algorithms` の数と同じで、`list` もその件数。

## 鍵の暗号化

### 公開インターフェース

```rust
// crates/application/src/port/sealer.rs（application の lib.rs から再公開）

/// Encrypts AS private keys at rest. Implementations must be authenticated encryption
/// bound to `aad`.
pub trait KeySealer: Send + Sync + 'static {
    fn seal(&self, plaintext: &Secret<Vec<u8>>, aad: &[u8]) -> Result<SealedPrivateKey, SealError>;
    /// aad が seal 時と違う、鍵が違う、改ざんされている → SealError::Open
    fn open(&self, sealed: &SealedPrivateKey, aad: &[u8]) -> Result<Secret<Vec<u8>>, SealError>;
}

#[derive(Debug, thiserror::Error)]
pub enum SealError {
    #[error("failed to seal the private key")]
    Seal,
    #[error("failed to open the sealed private key")]
    Open,
}
```

`Secret` は `komainu_jose::Secret`（`ddd_toolkit::secret::Secret`）。

```rust
// crates/adapter-std/src/sealer.rs（adapter-std の lib.rs から再公開）

/// AES-256-GCM. Format: 0x01 || nonce (12 bytes) || ciphertext || tag (16 bytes).
pub struct AesGcmKeySealer { /* key, random */ }

impl AesGcmKeySealer {
    pub fn new(key: Secret<[u8; 32]>, random: Arc<dyn SecureRandom>) -> Self;
    /// 標準 base64（パディングあり。前後の空白は除く）で 32 バイト。違えば InvalidSealerKey。
    pub fn from_base64(key: &Secret<String>, random: Arc<dyn SecureRandom>) -> Result<Self, InvalidSealerKey>;
    /// 新しい鍵暗号化鍵（32 バイトの乱数）を標準 base64 で返す。CLI の generate-encryption-key 用。
    pub fn generate_key_base64(random: &dyn SecureRandom) -> Secret<String>;
}
impl fmt::Debug for AesGcmKeySealer { /* "AesGcmKeySealer { .. }" */ }

#[derive(Debug, thiserror::Error)]
#[error("the key encryption key must be 32 bytes in standard base64")]
pub struct InvalidSealerKey;
```

- ノンスは呼び出しごとに `random.fill_bytes` で 12 バイト。
- `open`: 長さが `1 + 12 + 16` 未満、先頭が `0x01` でない、復号失敗はすべて `SealError::Open`。
- ルート `Cargo.toml` の `[workspace.dependencies]` に `aes-gcm = { version = "0.11.1", default-features = false, features = ["aes", "alloc"] }`。
- `adapter-std` に `aes-gcm.workspace = true` と `base64.workspace = true`（無ければ）、`komainu-jose.workspace = true`（`Secret` のため。application が再公開していればそれを使い jose は足さない）を足す。

### 受け入れ条件（鍵の暗号化）

- `seal` → `open` で平文に戻る。出力の先頭は `0x01`、長さは平文 + 29。
- 同じ平文を 2 回 `seal` すると出力が違う。
- `open` を別の aad・別の鍵・1 バイト改ざん・先頭バイト `0x02`・28 バイトの入力で呼ぶと `SealError::Open`。
- `from_base64`: 32 バイトなら Ok、31 / 33 バイトや base64 でない文字列は `InvalidSealerKey`。`generate_key_base64` の出力は `from_base64` で読める。
- `format!("{:?}", sealer)` に鍵のバイト列が含まれない。

## SigningKeyService

### 責務・配置・関連要件

- 配置: 新規 `crates/application/src/signing/{mod.rs,config.rs,error.rs,cache.rs}`。`SigningConfig`・`SigningConfigError` は `signing/config.rs` に置く（`crates/application/src/config.rs` はそれを参照するだけ）。application の lib.rs から `SigningKeyService`・`SigningConfig`・`SigningConfigError`・`SigningKeyError`・`SigningKeySummary`・`RotationReport`・`RevokeOutcome`・`KeySealer`・`SealError` を再公開する
- 責務: ローテーション（定期・即時）、失効、一覧、JWKS の JSON、署名、復号済み鍵のキャッシュ、監査
- 関連要件: F-1、F-2、F-3、F-5、F-6、F-9、F-14、N-1、N-3

### 設定（`crates/application/src/config.rs` と `crates/application/src/signing/config.rs`）

```rust
pub struct ApplicationConfig {
    // 既存のフィールド …
    /// None: AS signing disabled (default).
    pub signing: Option<SigningConfig>,
}
impl ApplicationConfig {
    pub fn with_signing(mut self, value: SigningConfig) -> Self;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningConfig {
    /// 空でない・重複なし（SigningConfig::new で検証）。
    algorithms: Vec<SigningAlgorithm>,
    policy: SigningPolicy,
}
impl SigningConfig {
    /// algorithms が空・重複 → SigningConfigError::Algorithms
    pub fn new(algorithms: Vec<SigningAlgorithm>, policy: SigningPolicy) -> Result<Self, SigningConfigError>;
    pub fn algorithms(&self) -> &[SigningAlgorithm];
    pub fn policy(&self) -> &SigningPolicy;
}
impl Default for SigningConfig { /* [Es256]、SigningPolicy::default() */ }

#[derive(Debug, thiserror::Error)]
pub enum SigningConfigError {
    #[error("signing algorithms must be non-empty and unique")]
    Algorithms,
}
```

`Dependencies`（`crates/application/src/deps.rs`）に `pub signing_keys: Option<Arc<SigningKeyService>>` を足す。

### 公開インターフェース

```rust
pub struct SigningKeyService { /* store, sealer, clock, random, config: SigningConfig, cache */ }

impl SigningKeyService {
    pub fn new(
        store: Arc<dyn UnitOfWorkFactory>,
        sealer: Arc<dyn KeySealer>,
        clock: Arc<dyn Clock>,
        random: Arc<dyn SecureRandom>,
        config: SigningConfig,
    ) -> Self;

    pub fn config(&self) -> &SigningConfig;

    /// 定期ローテーション。lock_rotation → list → plan_rotation → 即現役化（activate_now → update_schedule）・作成・削除 → 監査（actor system）→ commit → キャッシュ破棄。
    pub async fn rotate_due(&self, ctx: &RequestContext) -> Result<RotationReport, SigningKeyError>;

    /// 即時ローテーション（F-5）。algorithm が config に無ければ AlgorithmNotEnabled。
    /// lock → 同じアルゴリズムの Pending・Active をすべて retire(now, overlap) → immediate_key で作成 → 監査（actor admin）→ commit → キャッシュ破棄。
    pub async fn rotate_now(&self, ctx: &RequestContext, algorithm: SigningAlgorithm)
        -> Result<SigningKeySummary, SigningKeyError>;

    /// 失効（F-6）。lock → delete。無ければ NotFound。
    /// 消した鍵のアルゴリズムが config にあり、残りの鍵でそのアルゴリズムの current_key が None なら、
    /// plan_rotation と同じ規則で、そのアルゴリズムの Pending があれば即現役にし（replacement はその鍵）、
    /// 無ければ immediate_key で 1 件作る。監査（actor admin）→ commit → キャッシュ破棄。
    pub async fn revoke(&self, ctx: &RequestContext, kid: &SigningKeyId)
        -> Result<RevokeOutcome, SigningKeyError>;

    /// すべての鍵（Expired も含む）。activates_at 昇順。DB を直接読む（キャッシュを使わない）。
    pub async fn list(&self) -> Result<Vec<SigningKeySummary>, SigningKeyError>;

    /// JWKS の JSON（`{"keys":[...]}`。is_published_at(now) の鍵、activates_at 昇順）。キャッシュを使う。
    pub async fn jwks_json(&self) -> Result<Arc<str>, SigningKeyError>;

    /// 現役鍵で JWS（compact）に署名する。typ が Some ならヘッダーの typ。キャッシュを使う。
    pub async fn sign_jws(&self, algorithm: SigningAlgorithm, payload: &[u8], typ: Option<&str>)
        -> Result<String, SigningKeyError>;

    /// 現役鍵で JWT に署名する（komainu_jose::jwt::encode）。
    pub async fn sign_jwt<T: Serialize>(&self, algorithm: SigningAlgorithm, claims: &Claims<T>, typ: Option<&str>)
        -> Result<String, SigningKeyError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningKeySummary {
    pub kid: SigningKeyId,
    pub algorithm: SigningAlgorithm,
    pub status: KeyStatus,           // list を呼んだ時点の now で判定
    pub created_at: OffsetDateTime,
    pub activates_at: OffsetDateTime,
    pub retires_at: OffsetDateTime,
    pub deletes_at: OffsetDateTime,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RotationReport {
    pub created: Vec<SigningKeySummary>,
    pub activated: Vec<SigningKeyId>,
    pub deleted: Vec<SigningKeyId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeOutcome {
    pub revoked: SigningKeyId,
    /// 代わりに現役にした鍵（新しく作ったか、Pending を即現役にしたもの。どちらでもなければ None）
    pub replacement: Option<SigningKeySummary>,
}
```

`Claims` は `komainu_jose::jwt::Claims`。

### 振る舞い

- **鍵の生成**（作成時）: ES256 は `SigningKey::generate_es256()`、RS256 は `SigningKey::generate_rsa(RsaKeySize::Bits2048)`。`.with_thumbprint_kid()` → kid は `kid()` の文字列。`public_jwk = verifying_key().to_jwk()`。`sealed = sealer.seal(&to_pkcs8_der()?, aad)`、`aad = b"komainu:signing-key:" ++ kid`。`created_at = now`。生成はロックを取った UoW の中で行う（RSA 2048 の生成は 1 秒未満を想定。ローテーションは 1 時間に 1 回程度なので許容する）。鍵の生成は jose の内部で OS の乱数を使い、渡された `SecureRandom` は使わない（テストで鍵は決定的にならないので、kid の値を固定するテストは書かない）。サービスの `random` は監査イベントの組み立て（既存のサービスと同じ使い方）だけに使う。
- **キャッシュ**（`cache.rs`）: `tokio::sync::Mutex` ではなく `std::sync::Mutex<Option<Cached>>` で持ち、ロックを持ったまま await しない。`Cached { loaded_at, keys: Vec<ServerSigningKey>, signers: HashMap<SigningKeyId, Arc<SigningKey>>, jwks: Arc<str> }`。
  - 有効期間は 60 秒（定数 `CACHE_TTL`）。`now - loaded_at >= 60 秒` か `None` なら読み直す。
  - 読み直し: 新しい UoW で `list`（コミットせずに drop）→ `is_published_at(now)` の鍵から JWKS を作る（`VerifyingKey::from_jwk` → `JwkSet::new` → `to_json`）→ Pending・Active の鍵だけ `open` → `SigningKey::from_pkcs8_der` → `with_thumbprint_kid` で `signers` に入れる。
  - 同時に複数のリクエストが読み直しても構わない（後勝ち）。
  - JWKS は読み直した時点の `is_published_at` で作るので、最大 60 秒、Expired になった鍵が残り得る（許容する。削除は `rotate_due` が行い、その台ではキャッシュも破棄される）。署名は呼び出し時点の `now` で `current_key` を選ぶ。`signers` には読み直し時点の Pending も入っているので、キャッシュ中に Pending が Active になってもすぐその鍵で署名できる。
  - 自分の台での `rotate_due`（作成・即現役化・削除のどれかがあったとき）・`rotate_now`・`revoke` のコミット後に `None` に戻す。
- **署名**: `algorithm` が config に無い → `AlgorithmNotEnabled`。キャッシュの `keys` から `current_key(keys, algorithm, now)` → 無い → `NoActiveKey(algorithm)`。`signers` から鍵を取り、`jws::sign(payload, &key, &SignOptions::new().typ(..))` または `jwt::encode`。ヘッダーの `kid` は `SigningKey` に付けた kid が入る（jose の挙動）。
- **監査**（`AuditKind` に追加。`as_str` の値をそのまま DB に入れる）:

  | AuditKind | as_str | details |
  |-----------|--------|---------|
  | `SigningKeyCreated` | `signing_key.created` | `kid`、`alg`、`activates_at`（RFC 3339） |
  | `SigningKeyActivated` | `signing_key.activated` | `kid`、`alg`（Pending を即現役にしたとき） |
  | `SigningKeyRetired` | `signing_key.retired` | `kid`、`alg`、`deletes_at` |
  | `SigningKeyDeleted` | `signing_key.deleted` | `kid`、`alg` |
  | `SigningKeyRevoked` | `signing_key.revoked` | `kid`、`alg` |

  `rotate_due` は actor `System`、`rotate_now` / `revoke` は actor `Admin`。outcome は `Success`、`client_id` / `subject` は `None`。同じ UoW で `audit_log()` に書く。

### エラー

```rust
#[derive(Debug, thiserror::Error)]
pub enum SigningKeyError {
    #[error("signing algorithm is not enabled: {}", .0.as_str())]
    AlgorithmNotEnabled(SigningAlgorithm),
    #[error("no active signing key for {}", .0.as_str())]
    NoActiveKey(SigningAlgorithm),
    #[error("signing key not found")]
    NotFound,
    /// SealError、jose の鍵生成・変換・署名の失敗（中身の秘密は含めない）
    #[error("key operation failed: {0}")]
    Crypto(String),
    #[error("store error: {0}")]
    Store(StoreError),
}

impl From<StoreError> for SigningKeyError { /* Store(e) */ }
impl From<SealError> for SigningKeyError { /* Crypto(e.to_string()) */ }
impl From<komainu_jose::JoseError> for SigningKeyError { /* Crypto(e.to_string()) */ }
```

`Crypto` の文字列は元のエラーの `Display` だけ（`SealError` と `JoseError` の `Display` は秘密を含まない）。

| エラー | 起きる場面 | 呼び出し側の扱い |
|--------|------------|------------------|
| `AlgorithmNotEnabled` | 設定に無いアルゴリズムで署名・即時ローテーション | CLI は終了コード 2 とメッセージ。後続の署名利用者はプログラムの誤りとして扱う |
| `NoActiveKey` | 起動時のローテーション前・DB から鍵が消された直後 | `/token` などの利用側は `server_error` 相当。定期タスクで直る |
| `NotFound` | 存在しない kid の失効 | CLI は既存の NotFound と同じ終了コード |
| `Crypto` | 鍵暗号化鍵の取り違え（`open` 失敗）など | `/jwks` は 500。定期タスクはログに出して次回に再試行 |
| `Store` | DB 障害 | `/jwks` は 500（既存の `server_error` と同じ扱い） |

### 受け入れ条件（SigningKeyService）

`crates/application/tests/signing.rs`（testkit のインメモリストア、`TestKeySealer`、手で進められる時計）:

- 空のストアで `rotate_due` → `config.algorithms` の各アルゴリズムに Active の鍵が 1 つ。2 回目の `rotate_due` は何も作らない。
- 時計を 83 日進めて `rotate_due` → Pending の鍵が 1 つ増え、`jwks_json` に 2 つの kid が載る（キャッシュの 60 秒を過ぎたあと）。90 日で `sign_jwt` のヘッダー kid が新しい鍵になる。97 日で `rotate_due` → 古い鍵が削除され `RotationReport::deleted` に入る。
- `sign_jwt(Es256, ..)` の結果が、`jwks_json` から作った `JwkSet` の鍵で `jwt::decode` できる。`sign_jws` も同様に `jws::verify` できる。
- `sign_jwt(Rs256, ..)` を ES256 だけの設定で呼ぶと `AlgorithmNotEnabled`。`rotate_due` 前に呼ぶと `NoActiveKey`。
- `rotate_now(Es256)` → 新しい鍵が即 Active、それまでの Active / Pending は Retired（`deletes_at = now + retire_overlap`）、直後の `sign_jwt` は新しい鍵で署名（キャッシュ破棄の確認）。
- Pending がある状態で現役鍵を `revoke` → `replacement` がその Pending の鍵（新しく作らない）で、`signing_key.activated` が記録される。
- `revoke(現役鍵の kid)`（Pending なし）→ 行が消え、`replacement` が Some で、直後の `jwks_json` に古い kid が無い。`revoke(退役鍵の kid)` → `replacement` は None。存在しない kid → `NotFound`。
- 各操作で表の監査イベントが記録され、details に秘密鍵・暗号文が含まれない。
- 現役鍵が無く Pending だけある状態で（キャッシュを読み込ませてから）`rotate_due` → `RotationReport::activated` にその kid、直後の `sign_jwt` がその鍵で成功する（キャッシュ破棄の確認）。
- `ApplicationConfig::validate`: `signing` が Some で `retire_overlap < access_token_ttl` → `RetireOverlapTooShort`、等しければ Ok、`signing` が None なら見ない。
- キャッシュが有効な間、`sign_jwt` を 10 回呼んでも `InMemoryUnitOfWorkFactory::begin_count()` が増えない。
- 保存された `sealed_private_key` を `TestKeySealer.open(sealed, b"komainu:signing-key:other")` で開くと `SealError::Open`、`b"komainu:signing-key:" ++ kid` なら成功する（aad に kid を使っていることの確認）。

### 実装メモ

- `TestKeySealer`（`crates/testkit/src/sealer.rs`、testkit の lib.rs から公開）: 暗号化はしないが aad の取り違えを検出する。`seal` の出力は `b"TEST" ++ (aad の長さ: u32 BE) ++ aad ++ plaintext`、`open` は先頭と aad を照合して違えば `SealError::Open`。本番で使わないことを doc に書く。
- `InMemoryUnitOfWorkFactory`（`crates/testkit/src/store.rs`）に `pub fn begin_count(&self) -> usize` を足す（`Arc<AtomicUsize>`、`begin` のたびに加算。`ping` は数えない）。
- `TestEnv`（`crates/testkit/src/env.rs`）に `with_signing(config: SigningConfig) -> Self` を足し、`config.signing` と `deps.signing_keys`（`TestKeySealer` を使う）を設定する。
- `SigningKeyService` の内部で `Dependencies` を持たない（`Dependencies` が `SigningKeyService` を持つため循環する）。
