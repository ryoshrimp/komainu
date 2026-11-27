# domain

- 責務: 認証方式・グラント種別の追加、クライアントの公開鍵、外部発行者（`TrustedIssuer`）と `sub` 対応表（`SubjectMapping`）の型と不変条件を持つ。JWT・JWKS の中身の解釈（パース、署名検証）はしない（application と jose の責務）。
- 配置: `crates/domain`
- 関連要件: F-1、F-8、F-9、F-10

## 公開インターフェース

既存の newtype と同じく `ddd_toolkit::ValueObject` を derive し、`try_new` で検証する。不正値は `DomainError::invalid(<field>, <理由>)`。

### 列挙への追加（`crates/domain/src/client/client.rs`、`crates/domain/src/token/grant.rs`）

```rust
pub enum TokenEndpointAuthMethod {
    ClientSecretBasic,
    ClientSecretPost,
    None,
    /// RFC 7523 §2.2. as_str / FromStr: "private_key_jwt"
    PrivateKeyJwt,
}

pub enum GrantType {
    AuthorizationCode,
    ClientCredentials,
    RefreshToken,
    /// RFC 7523 §2.1. as_str / FromStr: "urn:ietf:params:oauth:grant-type:jwt-bearer"
    JwtBearer,
}

pub enum GrantOrigin {
    AuthorizationCode { code_hash: TokenHash },
    ClientCredentials,
    /// DB の grants.origin は "jwt_bearer"
    JwtBearer,
}

impl Grant {
    /// subject 付き、origin = JwtBearer の有効なグラントを作る。
    pub fn for_jwt_bearer(
        id: GrantId,
        client_id: ClientId,
        subject: Subject,
        scope: ScopeSet,
        now: OffsetDateTime,
    ) -> Grant;
}
```

`GrantType::JwtBearer` の文字列は URN そのもの（DB の `clients.grant_types` とメタデータにもこの値が入る）。

### 鍵の型（新規 `crates/domain/src/shared/jwks.rs`）

```rust
/// JWKS の JSON 文字列。長さだけ検証する（1〜65536 バイト）。
/// JSON として正しいか、鍵として使えるかは application が jose で確かめる。
pub struct JwksDocument(String);
impl JwksDocument {
    pub fn try_new(value: String) -> Result<Self, DomainError>;
    pub fn as_str(&self) -> &str;
}

/// jwks_uri。絶対 URL、スキーム https、userinfo なし、フラグメントなし、2048 バイト以下。
pub struct JwksUri(String);
impl JwksUri {
    pub fn try_new(value: String) -> Result<Self, DomainError>;
    pub fn as_str(&self) -> &str;
    /// テスト用に http と任意ホストを許す（adapter-http のテストで使う）。本番コードから呼ばない。
    #[doc(hidden)]
    pub fn new_unchecked_for_testing(value: String) -> Self;
}

/// クライアントの公開鍵の持ち方。どちらか一方。
pub enum ClientKeys {
    Jwks(JwksDocument),
    JwksUri(JwksUri),
}
```

`JwksUri` は `Hash` / `Eq` を derive する（`JwksResolver` のキャッシュキー）。

### Client への追加

- `Client` / `ClientRecord` / `NewClient` に `keys: Option<ClientKeys>` を追加する。`Client::keys(&self) -> Option<&ClientKeys>` を追加する。
- `ClientUpdate` に `keys: Option<ClientKeys>` を追加する（`Some` で置き換え）。
- `Client::rotate_secret` は `PrivateKeyJwt` のクライアントでは Public と同じエラーを返す。

### 外部発行者（新規 `crates/domain/src/issuer/`）

```rust
/// アサーションの iss と完全一致で照合する識別子。1〜255 バイト、各文字は 0x21〜0x7E。
#[derive(ValueObject, PartialOrd, Ord)]
pub struct IssuerId(String);

pub enum IssuerStatus { Active, Disabled } // as_str: "active" / "disabled"

pub struct NewTrustedIssuer {
    pub id: IssuerId,
    pub jwks: JwksDocument,
    pub allowed_clients: BTreeSet<ClientId>,
}

#[derive(Default)]
pub struct TrustedIssuerUpdate {
    pub jwks: Option<JwksDocument>,
    /// Some で全置き換え。
    pub allowed_clients: Option<BTreeSet<ClientId>>,
}

pub struct TrustedIssuer { /* 非公開フィールド */ }
impl TrustedIssuer {
    pub fn register(new: NewTrustedIssuer, now: OffsetDateTime) -> Result<Self, DomainError>;
    pub fn update(&mut self, update: TrustedIssuerUpdate, now: OffsetDateTime) -> Result<(), DomainError>;
    pub fn disable(&mut self, now: OffsetDateTime); // 既に Disabled なら何もしない（イベントも出さない）
    pub fn enable(&mut self, now: OffsetDateTime);  // 同上
    pub fn id(&self) -> &IssuerId;
    pub fn jwks(&self) -> &JwksDocument;
    pub fn allowed_clients(&self) -> &BTreeSet<ClientId>;
    pub fn allows_client(&self, client_id: &ClientId) -> bool;
    pub fn is_active(&self) -> bool;
    pub fn status(&self) -> IssuerStatus;
    pub fn created_at(&self) -> OffsetDateTime;
    pub fn updated_at(&self) -> OffsetDateTime;
    // イベントは既存の Client と同じく #[aggregate(events)] で持ち、生成される pull_events() で取り出す。
    pub fn to_record(&self) -> TrustedIssuerRecord;
    /// 既存の Client::from_record と同じく検証しない（保存済みの値を信頼する）。
    pub fn from_record(record: TrustedIssuerRecord) -> Self;
}

pub struct TrustedIssuerRecord {
    pub id: IssuerId,
    pub jwks: JwksDocument,
    pub allowed_clients: BTreeSet<ClientId>,
    pub status: IssuerStatus,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

pub enum IssuerEvent {
    Registered { issuer_id: IssuerId, occurred_at: OffsetDateTime },
    Updated { issuer_id: IssuerId, occurred_at: OffsetDateTime },
    Disabled { issuer_id: IssuerId, occurred_at: OffsetDateTime },
    Enabled { issuer_id: IssuerId, occurred_at: OffsetDateTime },
}
```

イベントは既存の `Client`（`crates/domain/src/client/client.rs:183` の `#[aggregate(events)]`）と同じ仕組みで積み、`pull_events()` で取り出す。

### sub の対応表（`crates/domain/src/issuer/subject.rs`）

```rust
/// アサーションの sub。1〜255 バイト、空でない。制御文字（0x00〜0x1F、0x7F）を含まない。
#[derive(ValueObject, PartialOrd, Ord)]
pub struct ExternalSubject(String);

pub struct SubjectMapping {
    pub issuer_id: IssuerId,
    pub subject: ExternalSubject,
    pub user_id: UserId,
    /// 作成または最後に上書きした時刻。
    pub updated_at: OffsetDateTime,
}
```

`SubjectMapping` は振る舞いを持たない値の組（集約にしない）。

## データ

永続化の形は [adapters.md §データ](adapters.md#データ)。domain は DB を知らない。

## 振る舞い

### Client の不変条件（`check_invariants` に追加・変更）

既存の規則に次を加える。既存規則「Confidential は `secret_hash` 必須かつ `auth_method != None`」は次のように置き換える。

| auth_method | client_type | secret_hash | keys |
|---|---|---|---|
| `ClientSecretBasic` / `ClientSecretPost` | Confidential | 必須 | `None` |
| `PrivateKeyJwt` | Confidential | `None` | 必須 |
| `None` | Public | `None` | `None` |

- `grant_types` に `JwtBearer` を含められるのは Confidential だけ。
- `JwtBearer` は `redirect_uris` を必要としない（`client_credentials` と同じ扱い）。`authorization_code` を含まないなら `redirect_uris` は空でなければならない、という既存規則はそのまま。
- `refresh_token` は `authorization_code` を必要とする、という既存規則はそのまま（jwt-bearer はリフレッシュトークンを出さない）。

### Client::update

- `auth_method` の変更は「`ClientSecretBasic` ↔ `ClientSecretPost`」だけ許す。それ以外の変更（`PrivateKeyJwt` との行き来）は `DomainError::invalid("auth_method", "cannot switch between secret and private_key_jwt")`（Q-4）。
- `keys` を `Some` にできるのは `PrivateKeyJwt` のクライアントだけ。他は `DomainError::invalid("keys", ...)`。
- 変更後に不変条件を検査する。成功すれば既存と同じ `Updated` イベント。

### TrustedIssuer

- `allowed_clients` は 1〜100 個。0 個・101 個以上は `DomainError::invalid("allowed_clients", ...)`。register と update の両方で検査する。
- クライアントが実在するかは domain では確かめない（AdminService が確かめる）。
- `register` は `Registered`、`update` は `Updated`、状態が変わった `disable` / `enable` は `Disabled` / `Enabled` を積む。

## エラー

| 状況 | 返すもの | 呼び出し側の扱い |
|---|---|---|
| newtype の検証失敗、不変条件違反 | `DomainError::invalid(field, reason)` | AdminService が `AdminError::Invalid` に包む（CLI は終了コード 2） |

## 設定

該当なし。

## 受け入れ条件

- `TokenEndpointAuthMethod::from_str("private_key_jwt")` が `PrivateKeyJwt`、`as_str` が往復する。`GrantType` の URN も同様。
- `JwksUri::try_new` は `https://idp.example.com/jwks` を受け、`http://...`、`https://u:p@h/`、`https://h/#f`、相対 URL、2049 バイトを拒否する。
- `JwksDocument::try_new` は空文字列と 65537 バイトを拒否する。
- Confidential・`PrivateKeyJwt`・`keys` あり・`secret_hash` なしで `register` できる。`keys` なし、または `secret_hash` ありなら拒否する。`ClientSecretBasic` で `keys` ありは拒否する。
- Public クライアントに `JwtBearer` を付けると拒否する。`grant_types = {JwtBearer}` だけで `redirect_uris` が空のクライアントを登録できる。
- `update` で `ClientSecretBasic` → `PrivateKeyJwt` は拒否、`ClientSecretBasic` → `ClientSecretPost` は成功する。`PrivateKeyJwt` のクライアントの `keys` を `JwksUri` に置き換えられる。
- `PrivateKeyJwt` のクライアントの `rotate_secret` はエラーになる。
- `IssuerId::try_new` は空、256 バイト、空白を含む値を拒否する。`allowed_clients` が 0 個・101 個の `TrustedIssuer::register` は拒否する。
- `disable` を 2 回呼んでもイベントは 1 つ。`allows_client` は登録したクライアントだけ `true`。
- `Grant::for_jwt_bearer` の `origin` は `JwtBearer`、`subject` は `Some`。

## 実装メモ

- `crates/domain/src/client/client.rs` の既存の `TokenEndpointAuthMethod` の `match` を網羅しているコード（application の `authenticate_client` のラベル、CLI の出力など）は、バリアント追加でコンパイルエラーになる。T2 では `PrivateKeyJwt` を「認証失敗」として扱う最小の分岐を入れ、T6 で本実装に置き換える。`GrantType::JwtBearer` と `GrantOrigin::JwtBearer` も同様に、T2 では `UnsupportedGrantType` / 記録の読み書きだけにする。
