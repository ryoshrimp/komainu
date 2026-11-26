# http・komainu facade・server

- 責務: `/token` と `/revoke` のフォームからアサーションを取り出して `ClientAuthentication` にする、メタデータに追加項目を出す、facade で fetcher と resolver を配線する、CLI でクライアントの鍵と外部発行者を管理する。
- 配置: `crates/http`、`crates/komainu`、`crates/server`
- 関連要件: F-1〜F-12、N-3、N-5

## http（`crates/http`）

### フォーム解析（`crates/http/src/form.rs`、`crates/http/src/client_auth.rs`）

`BodyCredentials` に 2 項目を加え、`split_client_credentials` で取り出す（`rest` には入れない）。

```rust
pub(crate) struct BodyCredentials {
    pub client_id: Option<String>,
    pub client_secret: Option<Secret<String>>,
    pub client_assertion_type: Option<String>,
    /// 取り出した時点で Secret に包む。
    pub client_assertion: Option<Secret<String>>,
}
```

- 4 項目のどれかが 2 回以上出現したら、既存の `client_id` / `client_secret` と同じく `split_client_credentials` が `None` を返し、`crates/http/src/token.rs` と `revoke.rs` の既存の分岐で 400 `invalid_request` になる。`assertion`（グラント用）の重複は application の `TokenRequest::duplicated` で検出する（[application.md](application.md#clientauthentication-と-tokenrequest)）。
- 空文字は既存と同じく無いものとして扱う。

`client_authentication(headers, body)` の判定順:

1. `client_assertion_type` と `client_assertion` の片方だけある → `Err(InvalidRequest)`。
2. 両方ある場合:
   1. `Authorization: Basic` がある、または `client_secret` がある → `Err(InvalidRequest)`（F-4）。
   2. `client_assertion_type` が `CLIENT_ASSERTION_TYPE_JWT_BEARER` でない → `Err(InvalidClient { basic_attempted: false })`（F-3）。
   3. `Ok(ClientAuthentication::Assertion { client_id, assertion })`。`client_id` は body の値（`iss` との照合は application）。
3. どちらもない → 既存の判定のまま。

`/revoke`（`crates/http/src/revoke.rs`）も同じ `split_client_credentials` と `client_authentication` を使っているので、追加の変更はない。`RevocationError::InvalidClient { basic_attempted: false }` は既存どおり 401、`WWW-Authenticate` なし。

### TokenRequest の `assertion`

`TokenRequest::from_pairs` が `assertion` を読む（[application.md](application.md#clientauthentication-と-tokenrequest)）。http 側の変更はない。

### メトリクス（`crates/http/src/token.rs`）

`grant_type_label` に `Some("urn:ietf:params:oauth:grant-type:jwt-bearer") => "jwt_bearer"` を加える。クライアント認証方式のラベルは追加しない。

### メタデータ（`crates/http/src/metadata.rs`）

```rust
pub struct AuthorizationServerMetadata {
    // 既存フィールド
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub token_endpoint_auth_signing_alg_values_supported: Vec<&'static str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub revocation_endpoint_auth_signing_alg_values_supported: Vec<&'static str>,
}
```

- 値は `ServerCapabilities::{token,revocation}_endpoint_auth_signing_algs` の既存の `Algorithm::as_str()`（`crates/jose/src/algorithm.rs:20`、`"RS256"`, `"ES256"`）。
- `grant_types_supported` の `GrantType::JwtBearer` は `"urn:ietf:params:oauth:grant-type:jwt-bearer"`、`token_endpoint_auth_methods_supported` の `PrivateKeyJwt` は `"private_key_jwt"`（既存の `as_str` 経由）。
- `ApplicationConfig::issuer` が未設定なら、メタデータの出力は既存と同じ（スナップショット `crates/http/src/snapshots/` が変わらない）。

## komainu facade

`crates/komainu`。

### feature

```toml
[features]
default = ["http", "postgres", "std", "jwks-uri"]
jwks-uri = ["dep:komainu-adapter-http"]

[dependencies]
komainu-adapter-http = { workspace = true, optional = true }
```

`lib.rs` で `#[cfg(feature = "jwks-uri")] pub use komainu_adapter_http as adapter_http;`（既存の `adapter_postgres` / `adapter_std` の再公開と同じ書き方）。

### KomainuBuilder（`crates/komainu/src/builder.rs`）

```rust
impl KomainuBuilder {
    /// jwks_uri の取得に使う fetcher。省略時は jwks-uri feature があれば
    /// ReqwestJwksFetcher::new(JwksFetcherConfig::default())、なければ None
    /// （jwks_uri のクライアントは認証失敗）。
    pub fn jwks_fetcher(mut self, fetcher: Arc<dyn JwksFetcher>) -> Self;
    /// jwt-bearer の sub を解決する。省略時は MappingTableSubjectResolver。
    pub fn subject_resolver(mut self, resolver: Arc<dyn AssertionSubjectResolver>) -> Self;
}

pub enum BuildError {
    // 既存バリアント
    /// ReqwestJwksFetcher の作成に失敗した。
    #[cfg(feature = "jwks-uri")]
    JwksFetcher(komainu_adapter_http::BuildError),
}
```

`build()` での `issuer` の決め方:

- `http` feature があり、`application_config.issuer` が None なら、`http_config.public_base_url()` を設定する（自動で有効になる）。
- `application_config.issuer` が Some なら、その値を使う（`http_config` と違ってもよい。issuer にパスがある埋め込み向け）。
- `http` feature がなければ、利用者が `with_issuer` しない限り None。

`Dependencies` には `jwks: Arc::new(JwksResolver::new(fetcher, clock.clone()))` と `subject_resolver` を入れる。

## server（`crates/server`）

### 配線（`crates/server/src/wiring.rs`）

`Settings::from_config` で `ApplicationConfig::with_issuer(<正規化済み public_base_url>)` を設定する（facade の自動設定に頼らず明示する。CLI の管理コマンドでも同じ設定にするため）。fetcher は facade の既定（`ReqwestJwksFetcher`、既定設定）を使う。新しい設定キーは足さない。

### CLI: `komainu client`（`crates/server/src/cli/client.rs`）

- `AUTH_METHODS` に `"private_key_jwt"` を、`GRANT_TYPES` に `"urn:ietf:params:oauth:grant-type:jwt-bearer"` を加える。
- `CreateArgs` / `UpdateArgs` に追加:

```rust
/// JWKS の JSON ファイル。private_key_jwt で --jwks-uri と排他。
#[arg(long, value_name = "PATH", conflicts_with = "jwks_uri")]
jwks_file: Option<PathBuf>,
/// JWKS の URL（https）。private_key_jwt で --jwks-file と排他。
#[arg(long, value_name = "URL")]
jwks_uri: Option<String>,
```

| 状況 | 結果 |
|---|---|
| `create --auth-method private_key_jwt` で `--jwks-file` / `--jwks-uri` のどちらもない | 終了コード 2 |
| `private_key_jwt` 以外で `--jwks-file` / `--jwks-uri` がある | 終了コード 2 |
| 両方指定 | clap の排他エラー（終了コード 2） |
| ファイルが読めない | 終了コード 2（メッセージにパス） |
| `JwksDocument::try_new` / `JwksUri::try_new` の失敗、`AdminError::InvalidJwks` | 終了コード 2 |
| `update` で `private_key_jwt` のクライアントに `--jwks-file` / `--jwks-uri` | 鍵を置き換える |
| `update --auth-method` で `client_secret_*` ↔ `private_key_jwt` | `AdminError::Invalid` → 終了コード 2（Q-4） |
| `rotate-secret` を `private_key_jwt` のクライアントに | 既存の Public と同じく終了コード 2 |

- `create` の出力: `private_key_jwt` ではシークレットの行を出さない（JSON では `client_secret` キーを出さない）。
- `show` / `list` の出力（`crates/server/src/cli/output.rs`）: テキストに `keys: jwks (N keys)` / `keys: jwks_uri <URL>` / 鍵なしは行を出さない。JSON に `"keys": {"type": "jwks", "jwks": <JSON 値>}` / `{"type": "jwks_uri", "jwks_uri": "<URL>"}` / `null`。

### CLI: `komainu issuer`（新規 `crates/server/src/cli/issuer.rs`）

`Command` と `AdminCommand` に `Issuer(issuer::IssuerCommand)` を加え（`#[command(subcommand)]`、doc は "Manage trusted external assertion issuers."）、`run_admin` から `issuer::run` に回す。

| サブコマンド | 引数 | 動作 |
|---|---|---|
| `create` | `--issuer <ID>`、`--jwks-file <PATH>`、`--client <CLIENT_ID>`（1〜100 個、繰り返し。0 個は clap の必須エラー、101 個以上は domain の `DomainError` → `AdminError::Invalid`、どちらも終了コード 2。個数の検査はクライアントの実在より先に行う）、`--output` | `register_issuer` |
| `list` | `--limit <N>`（既定 100）、`--after <ID>`、`--output` | `list_issuers` |
| `show` | `<ID>`、`--output` | `get_issuer` |
| `update` | `<ID>`、`--jwks-file <PATH>`、`--client <CLIENT_ID>`（指定時は一覧全体を置き換え）、`--output` | `update_issuer`。`--jwks-file` と `--client` を `#[group(required = true, multiple = true)]` にまとめ、どちらも指定なしは clap のエラー（終了コード 2） |
| `disable` / `enable` | `<ID>` | `disable_issuer` / `enable_issuer` |
| `map-subject` | `<ID>`、`--subject <SUB>`、`--username <NAME>`、`--output` | `map_subject` |
| `unmap-subject` | `<ID>`、`--subject <SUB>` | `unmap_subject` |
| `list-subjects` | `<ID>`、`--limit <N>`（既定 100）、`--after <SUB>`、`--output` | `list_subject_mappings` |

- 終了コード: 既存の `admin_exit` に `AdminError::InvalidJwks(_) | AdminError::UnknownClient(_)` → 2 を加える。`IssuerId` / `ExternalSubject` / `Username` / `ClientId` のパース失敗は 2、`NotFound` は 3、`Conflict` は 4。
- 出力: テキストは `id`、`status`、`clients`（カンマ区切り）、`keys: N`、`created_at`、`updated_at`。JSON は `{"id","status","allowed_clients":[...],"jwks":<JSON 値>,"created_at","updated_at"}`。`list-subjects` は `subject`、`username`、`user_id`、`updated_at`。時刻の形式は既存の `client show` に合わせる。
- `disable` / `enable` / `unmap-subject` の成功時の出力は既存の `client disable` に合わせる。

## エラー

| 状況 | HTTP |
|---|---|
| `client_assertion_type` / `client_assertion` の片方のみ、重複、他方式との併用 | 400 `invalid_request` |
| `client_assertion_type` が jwt-bearer の URN でない | 401 `invalid_client`、`WWW-Authenticate` なし |
| application の `InvalidClient { basic_attempted: false }` | 401 `invalid_client`、`WWW-Authenticate` なし |

その他は既存の `TokenError` / `RevocationError` → レスポンスの写しのまま。

## 設定

新しい設定ファイルのキーはない。`ApplicationConfig::issuer` は `server.public_base_url` から決まる。

## 受け入れ条件

http（`crates/http/tests/token.rs`、`revoke.rs`、`metadata.rs`。application はインメモリ store とテスト鍵で実物を使う）:

- F-2: 正しいアサーションの `client_credentials` が 200。`client_id` 併記で一致 200、不一致 400 `invalid_request`。
- F-3: 署名を壊したアサーションで 401、レスポンスヘッダーに `WWW-Authenticate` がない。`client_assertion_type=urn:example:other` で 401。
- F-4: `client_assertion` + `Authorization: Basic` で 400、`client_assertion` + `client_secret` で 400、`client_assertion` のみで 400、`client_assertion` が 2 回で 400。
- F-7: `/revoke` に正しいアサーションで 200、不正で 401。
- F-10: jwt-bearer で 200、JSON に `refresh_token` がない。メトリクスのラベルが `jwt_bearer`。
- F-11: `assertion` なしで 400 `invalid_request`、未登録発行者で 400 `invalid_grant`。
- F-12: `issuer` 設定時、メタデータに追加項目が並ぶ（`allow_public_clients = false` で `token_endpoint_auth_methods_supported` が `["client_secret_basic","client_secret_post","private_key_jwt"]`）。未設定時は既存スナップショットと一致。
- N-3: `ClientAuthentication::Assertion` と `TokenRequest` の `Debug` 出力にアサーション本文が含まれない。

komainu（`crates/komainu/tests/` または builder のユニットテスト）:

- `http_config` だけ設定した `build()` で、`metadata()` に `private_key_jwt` が含まれる。
- `default-features = false, features = ["http", "std"]` でビルドが通る（`cargo check -p komainu --no-default-features --features http,std`）。この構成での振る舞い（fetcher なしで `jwks_uri` のクライアントは `key_fetch_failed`）は application の `tests/token.rs` で確かめるので、facade では機能テストをしない。

server（`crates/server/tests/cli.rs`、`e2e_scenario.rs`）:

- F-1、F-8、F-9 の終了コードと出力。
- e2e: `issuer create` → `user create alice` → `issuer map-subject` → 外部発行者の鍵で署名した `assertion` で `/token`（クライアントは `client_secret_basic`）→ 200 → 得たアクセストークンを `Komainu::token().verify_access_token` に渡すと subject が alice のユーザー ID。
- e2e: `client create --auth-method private_key_jwt --jwks-file` → アサーションで `client_credentials` → 200 → 同じアサーションで再送 → 401。

## 実装メモ

- `client_auth.rs` のユニットテストに上の判定順の各分岐を足す。
