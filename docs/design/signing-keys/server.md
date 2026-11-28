# HTTP・ファサード・サーバー

[README](README.md) に戻る。

## HTTP

### 責務・配置・関連要件

- 配置: 新規 `crates/http/src/jwks.rs`、`crates/http/src/{lib.rs,state.rs,metadata.rs}`、新規 `crates/http/tests/jwks.rs`
- 関連要件: F-7、F-8

### 公開インターフェース

```rust
// state.rs
impl AppState {
    /// 署名鍵サービスを渡す。渡すと GET /jwks が有効になり、メタデータに jwks_uri が入る
    /// （self.metadata を作り直す）。
    pub fn with_signing_keys(self, service: Arc<SigningKeyService>) -> Self;
}

// metadata.rs
pub struct AuthorizationServerMetadata {
    // issuer の次に置く
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    // 既存のフィールド …
}
```

- `AuthorizationServerMetadata::new(&HttpConfig, &ServerCapabilities)` は `jwks_uri: None` にする。`with_signing_keys` で `Some(format!("{}/jwks", http_config.public_base_url()))` を入れる（`token_endpoint` と同じ基底。`ApplicationConfig::issuer` は使わない）。
- ルート: `crates/http/src/lib.rs` のルーターに `GET /jwks` を常に登録する。

### `GET /jwks`

| 条件 | ステータス | ヘッダー | 本文 |
|------|------------|----------|------|
| `signing_keys` が None | 404 | なし | 空（ルーターに fallback が無いので axum の既定の 404 と同じ） |
| 成功 | 200 | `Content-Type: application/json;charset=UTF-8`（既存の `JSON_CONTENT_TYPE` と完全一致）、`Cache-Control: public, max-age=300`、`Access-Control-Allow-Origin: *` | `SigningKeyService::jwks_json()` の文字列そのもの |
| `jwks_json` が `Err` | 500 | `Content-Type: application/json;charset=UTF-8`、既存の `no_store_headers()` | `{"error":"server_error"}`（`jwks.rs` で組み立てる。`token_error_response` は使わない）。エラーは `tracing::error!` に出す（秘密は含まれない） |

鍵が 0 個（起動直後のローテーション前など）でも 200 で `{"keys":[]}` を返す。

### 受け入れ条件（HTTP）

`crates/http/tests/jwks.rs`（testkit の `TestEnv::with_signing`）:

- `rotate_due` 後の `GET /jwks` が 200、上表のヘッダー、本文の `keys` に ES256 の JWK が 1 つ（`kid`・`use: "sig"`・`alg: "ES256"`）。
- `with_signing_keys` を呼ばない `AppState` で `GET /jwks` が 404、メタデータに `jwks_uri` キーが無い。
- `with_signing_keys` を呼んだ `AppState` のメタデータに `"jwks_uri": "<public_base_url>/jwks"`。
- キャッシュが空の状態（最初の呼び出し）で `InMemoryUnitOfWorkFactory::fail_next()` を呼んでから `GET /jwks` すると 500。

## ファサード

### 公開インターフェース（`crates/komainu/src/builder.rs`）

```rust
impl KomainuBuilder {
    /// 署名鍵の暗号化。ApplicationConfig::signing が Some のとき必須。
    pub fn key_sealer(mut self, sealer: Arc<dyn KeySealer>) -> Self;
}

impl Komainu {
    /// 署名が有効なときの署名鍵サービス。
    pub fn signing_keys(&self) -> Option<&Arc<SigningKeyService>>;
}

pub enum BuildError {
    // 既存 …
    /// ApplicationConfig::signing is set but no key sealer was given.
    #[error("a key sealer is required when signing is enabled; call KomainuBuilder::key_sealer")]
    MissingKeySealer,
    /// ApplicationConfig::validate failed.
    #[error("invalid application configuration: {0}")]
    InvalidConfig(#[source] ApplicationConfigError),
}
```

`build()` の追加手順:

1. 最初に `application_config.validate()` → `Err` なら `InvalidConfig`。
2. `config.signing` が `Some(signing)`: `key_sealer` が None なら `MissingKeySealer`。あれば `SigningKeyService::new(store, sealer, clock, random, signing.clone())` を `Arc` で作り、`Dependencies::signing_keys` に入れる。`None` なら `signing_keys: None`（`key_sealer` だけ渡されていても無視する）。
3. `http` 機能: `signing_keys` が Some なら `AppState::new(..).with_signing_keys(service)`。
4. 鍵の生成（`rotate_due`）は build では行わない（async にしないため）。ライブラリ利用者は起動時と定期的に `komainu.signing_keys()` の `rotate_due` を呼ぶ。crate doc にその例を書く。

`komainu` クレートから `KeySealer`・`SealError`・`SigningKeyService`・`SigningConfig`・`SigningConfigError`・`SigningPolicy`・`SigningAlgorithm`・`SigningKeyError`・`SigningKeySummary`・`RotationReport`・`RevokeOutcome`・`ApplicationConfigError` を再公開し、`std` 機能では `AesGcmKeySealer` も再公開する（既存の再公開の並びに合わせる）。

### 受け入れ条件（ファサード）

- `signing` 有り・`key_sealer` 無しで `build()` が `MissingKeySealer`。
- `disabled_grant_types` に `AuthorizationCode` で `build()` が `InvalidConfig`。
- `signing` 有り・`key_sealer` 有りで `signing_keys()` が Some、`metadata().jwks_uri` が Some。`signing` 無しなら両方 None。

## サーバー

### 設定（`crates/server/src/config.rs`）

`DEFAULTS` に追加:

```toml
[oauth]
# 既存のキー …
disabled_grant_types = []
disabled_auth_methods = []

[signing]
# 空なら署名機能は無効。`komainu key generate-encryption-key` で作る 32 バイトの標準 base64。
encryption_key = ""
algorithms = ["ES256"]
active_days = 90
prepublish_days = 7
retire_overlap_days = 7
rotation_interval_secs = 3600
```

| キー | 型 | 既定 | 検証（どちらも終了コード 2） |
|------|----|------|------|
| `oauth.disabled_grant_types` | 文字列の配列 | `[]` | 各要素が `GrantType::from_str` で読めること（受け付ける値: `client_credentials`、`refresh_token`、`urn:ietf:params:oauth:grant-type:jwt-bearer`）、`authorization_code` を含まないこと |
| `oauth.disabled_auth_methods` | 文字列の配列 | `[]` | 各要素が `TokenEndpointAuthMethod::from_str` で読めること（受け付ける値: `client_secret_basic`、`client_secret_post`、`private_key_jwt`、`none`）。全体を `ApplicationConfig::validate` に通す |
| `signing.encryption_key` | 文字列（秘密） | `""` | 空でなければ `AesGcmKeySealer::from_base64` が通ること。値をエラーメッセージに出さない |
| `signing.algorithms` | 文字列の配列 | `["ES256"]` | `SigningAlgorithm::from_str`、空・重複でない（`SigningConfig::new`） |
| `signing.active_days` | 整数 | 90 | 1 以上、`SigningPolicy::new` が通ること |
| `signing.prepublish_days` | 整数 | 7 | 1 以上（日単位なので最小 1 時間の制約は自動で満たす）、`active_days` 未満 |
| `signing.retire_overlap_days` | 整数 | 7 | 0 以上。`access_token_ttl` 以上であることは `ApplicationConfig::validate`（`RetireOverlapTooShort`）で検証する |
| `signing.rotation_interval_secs` | 整数 | 3600 | 60 以上、`prepublish_days * 86400` 未満 |

- 検証の分担: キーの形式・範囲（文字列の読み取り、整数の範囲、`authorization_code` を含まない、`rotation_interval_secs` の範囲、`encryption_key` の base64 として 32 バイト）は `config::validate`（既存の `ConfigError`）。ライブラリの型への変換（`SigningPolicy::new`・`SigningConfig::new`・`AesGcmKeySealer::from_base64`）と `ApplicationConfig::validate`（`NoAuthMethod`・`RetireOverlapTooShort`）は `Settings::from_config`（anyhow）。どちらも `execute` で `Exit::usage` になる。
- 環境変数は既存の仕組みで `KOMAINU_SIGNING__ENCRYPTION_KEY` などになる。配列の環境変数での指定は既存の配列キーと同じ扱い（特別な対応はしない）。
- `encryption_key` は `Secret<String>` で持ち、`Config` の `Debug` に出さない（既存の秘密の設定と同じやり方）。
- `Settings`（`crates/server/src/wiring.rs`）に `pub key_sealer: Option<Arc<dyn KeySealer>>` を足す。`Settings::from_config` は、`encryption_key` が空でなければ `ApplicationConfig::with_signing(SigningConfig::new(..)?)` を設定し、`key_sealer = Some(Arc::new(AesGcmKeySealer::from_base64(.., Arc::new(OsSecureRandom))?))` にする。最後に `application.validate()` を呼ぶ。`disabled_*` は `with_disabled_grant_types` / `with_disabled_auth_methods`。
- `wiring::services(store, application, http)` を `services(store, application, http, key_sealer: Option<Arc<dyn KeySealer>>)` に変え、Some なら `KomainuBuilder::key_sealer` に渡す。呼び出し元（`crates/server/src/lib.rs` の `admin`、`crates/server/src/serve.rs`、テスト）をすべて直す。

### 起動時と定期のローテーション

- 新規 `crates/server/src/rotation.rs`: `run_once(service: &SigningKeyService) -> Result<RotationReport, SigningKeyError>`（`background_context()` を作って `rotate_due`、ログとメトリクスを出す）と、`cleanup::run_periodic` と同じ引数の形の `run_periodic(service, interval, shutdown)`（各回で `run_once` を呼ぶ。context は受け取らない）。
- `run_serve`（`crates/server/src/serve.rs`）: マイグレーションの後、`listen`（bind）の前に、署名が有効なら `rotation::run_once` を 1 回呼ぶ。`Err` なら `Exit::runtime`（起動しない）。その後 `run_periodic` を cleanup と同じく spawn し、同じ shutdown で止める。
- `run_periodic` の各回: 失敗は `tracing::error!`（エラーの Display のみ）を出して次回に再試行。成功時、作成・即現役化・削除があれば `tracing::info!(created = n, activated = k, deleted = m)`。メトリクス `komainu_signing_keys_rotated_total{kind="created"|"activated"|"deleted"}` を加算（cleanup のメトリクスと同じ書き方）。
- 署名が無効なら何もしない（spawn もしない）。

### CLI（新規 `crates/server/src/cli/key.rs`）

```text
komainu key list [--format text|json]
komainu key rotate --alg <ES256|RS256> [--format text|json]
komainu key revoke <KID> [--format text|json]
komainu key generate-encryption-key
```

- `Command` に `Key(key::KeyCommand)` を足す。`AdminCommand` には足さない。`KeyCommand` は `List` / `Rotate` / `Revoke` / `GenerateEncryptionKey` のサブコマンド。
- `crates/server/src/lib.rs` の `execute`:
  1. 先頭（`config::load` の前）で `Command::Key(KeyCommand::GenerateEncryptionKey)` を処理して return する。
  2. それ以外の `Key` は、設定の読み込みと `Settings::from_config` の後、DB に接続する前に `settings.key_sealer.is_none()` なら `Exit::usage("signing is disabled: set signing.encryption_key")`。
  3. `admin` と同じく接続して `wiring::services(..)` を作り、`key::run(services.komainu.signing_keys().expect(..), command)` を呼ぶ（2 で確かめたので Some）。
- `generate-encryption-key`: 設定ファイル・DB を読まずに `AesGcmKeySealer::generate_key_base64(&OsSecureRandom)` を標準出力に 1 行で出して終了コード 0。設定の読み込みより前に処理する。
- 呼び出しの `RequestContext` は `background_context()`。
- `list` の text 出力: 1 行 1 鍵、`<kid>  <alg>  <status>  activates=<RFC 3339>  retires=<RFC 3339>  deletes=<RFC 3339>`（status は `pending` / `active` / `retired` / `expired`）。json 出力: `SigningKeySummary` の各フィールドを snake_case のキー、時刻は RFC 3339 文字列、`status` と `algorithm` は文字列（例: `"active"`、`"ES256"`）。
- `rotate` の出力: 作った鍵 1 件を `list` と同じ形式で。`revoke` の出力: text は `revoked <kid>` と、`replacement` が Some なら（新しく作ったか Pending を即現役にしたかに関係なく）`replacement ` + `list` と同じ 1 行。json は `{"revoked": "<kid>", "replacement": <鍵 or null>}`。
- `SigningKeyError` の終了コード: `AlgorithmNotEnabled` → 2、`NotFound` → 3、`NoActiveKey`・`Crypto`・`Store` → 1。

### 受け入れ条件（サーバー）

- 設定の検証テスト: `config::validate` の分は `crates/server/src/config.rs` の既存テストの並び、`Settings::from_config` の分（`RetireOverlapTooShort`、`NoAuthMethod`）は `crates/server/src/wiring.rs` のテストで、上表の各違反がエラーになり、`encryption_key` の値がエラーメッセージに含まれない。既定値（`encryption_key = ""`）で署名無効のまま読み込める。
- `komainu key generate-encryption-key` が設定ファイルなしで成功し、出力が `from_base64` で読める 44 文字。
- PostgreSQL を使うテスト（既存の serve / CLI のテストと同じ仕組み）: 署名を有効にした設定で `serve` を起動すると、起動直後の `GET /jwks` に ES256 の鍵が 1 つあり、メタデータに `jwks_uri` がある。`komainu key list` に 1 件 `active` で出る。`komainu key rotate --alg ES256` の後 `list` で 2 件（`active` と `retired`）。`komainu key revoke <retired の kid>` の後 1 件。
- 署名が無効なとき `komainu key list` が DB に接続せずに終了コード 2（DB の無い環境でも確かめられる）。
- `oauth.disabled_grant_types = ["client_credentials"]` で起動したサーバーのメタデータに `client_credentials` が無い。

## ドキュメント

- `docs/getting-started.md` に「署名鍵を有効にする」節: 鍵暗号化鍵の生成（`komainu key generate-encryption-key`）と `KOMAINU_SIGNING__ENCRYPTION_KEY` での設定、鍵暗号化鍵を失うと保存済みの鍵が使えなくなること（そのときは、サーバーをすべて止め、新しい鍵暗号化鍵を設定し、`komainu key list` で確かめたうえで pending・retired・expired の鍵を先に、active の鍵を最後に `komainu key revoke` し、新しい鍵暗号化鍵で起動する。active を revoke すると新しい鍵暗号化鍵で暗号化した代わりの鍵が現役になる。復号できない pending・active の鍵が残る間は署名も /jwks も失敗し、古い鍵で発行したトークンは検証できなくなる）、`[signing]` の各キーの意味、`komainu key list|rotate|revoke`、`GET /jwks`。
- 同じファイルの設定の説明に `oauth.disabled_grant_types` / `oauth.disabled_auth_methods` を足す。
- `docs/design/authorization-server/README.md` の §8 ロードマップの表に「AS 署名鍵・JWKS・グラントと認証方式の拡張ポイント（#27） | 済 | [signing-keys](../signing-keys/README.md)」の行を足す（既存の行の書式に合わせる）。
