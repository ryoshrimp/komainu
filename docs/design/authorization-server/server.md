# komainu-server

- 責務: 単体サーバーのバイナリ `komainu`。設定の読み込みと検証、DI の組み立て、メインと ops の 2 つのリスナー、ログとメトリクスの初期化、管理 CLI、定期削除ジョブ、グレースフルシャットダウン。
- 配置: `crates/server`（`src/lib.rs` に処理を置き、`src/main.rs` は `komainu_server::run()` を呼んで終了コードを返すだけにする）
- 関連要件: F-11、F-13、N-8、N-9

## 公開インターフェース

依存: すべての komainu crate、`tokio = "1"`（`full`）、`axum`、`clap = "4"`（`derive`, `env`）、`figment = "0.10"`（`toml`, `env`）、`serde`、`serde_json`、`tracing`、`tracing-subscriber = "0.3"`（`json`, `env-filter`）、`metrics`、`metrics-exporter-prometheus = "0.18"`（`http-listener` は使わない）、`url`、`anyhow = "1"`（`run()` と CLI の最上位のエラー表示だけ。README §3.1 と同じ範囲）。dev-dependencies: `figment`（`test` feature。`figment::Jail` で環境変数とファイルを安全に差し替える。edition 2024 では `std::env::set_var` が `unsafe` で、workspace の `unsafe_code = "forbid"` に当たるため）、`assert_cmd = "2"`、`predicates = "3"`、`reqwest = "0.12"`、`testcontainers-modules`、`komainu-testing`。

```
crates/server/src/
  main.rs       // std::process::exit(komainu_server::run())
  lib.rs        // pub fn run() -> i32; pub mod config, wiring, serve, ops, telemetry, cleanup (T17), cli
  config.rs     // Config, load(), validate()
  wiring.rs     // build Dependencies / AppState from Config
  serve.rs      // main + ops listeners, graceful shutdown
  ops.rs        // /healthz /readyz /metrics
  telemetry.rs  // tracing subscriber, Prometheus recorder
  cleanup.rs    // periodic purge
  cli/
    mod.rs  client.rs  user.rs  issuer.rs  output.rs
```

### 終了コード

| コード | 意味 |
|---|---|
| 0 | 成功 |
| 1 | 実行時のエラー（DB に接続できない、マイグレーションの失敗、強制停止など） |
| 2 | 使い方・設定・入力値の誤り（clap のエラー、設定の検証エラー、`AdminError::Invalid` / `UnknownScope` / `PublicClientsDisabled` / `InvalidJwks` / `UnknownClient`、読めない `--jwks-file`） |
| 3 | 対象が見つからない（`AdminError::NotFound`） |
| 4 | 重複（`AdminError::Conflict`） |

エラーメッセージは 1 行で標準エラー出力に出す（例: `error: invalid redirect_uri: fragment is not allowed`）。

## 設定

設定ファイルは TOML。読み込む場所は `--config <PATH>`（グローバルオプション）で、指定がなければカレントディレクトリの `komainu.toml`。`--config` で指定したファイルがなければ終了コード 2。指定がなく `komainu.toml` もなければ、既定値と環境変数だけで動く。

環境変数は `KOMAINU_` で始め、階層を `__` でつなぐ（例: `KOMAINU_DATABASE__URL`、`KOMAINU_SERVER__PUBLIC_BASE_URL`）。優先順位は 既定値 < ファイル < 環境変数。`[[scopes]]` は環境変数では指定できない。

`config/komainu.example.toml`（すべての項目と既定値）:

```toml
[server]
listen = "0.0.0.0:8080"
public_base_url = "https://auth.example.com"  # required
allow_insecure_http = false                   # true allows http:// in public_base_url (local dev only)
shutdown_timeout_secs = 30

[ops]
listen = "127.0.0.1:9090"

[database]
url = "postgres://komainu:komainu@localhost:5432/komainu"  # required
max_connections = 10
acquire_timeout_secs = 5

[session]
cookie_secure = true
ttl_secs = 28800

[oauth]
authorization_code_ttl_secs = 60
access_token_ttl_secs = 3600
refresh_token_ttl_secs = 2592000
authorization_request_ttl_secs = 600
require_state = false

[clients]
allow_public = false

[[scopes]]
name = "read"
description = "Read your data"

[[scopes]]
name = "write"
description = "Modify your data"

[cleanup]
enabled = true
interval_secs = 600
grace_secs = 86400
audit_retention_days = 90

[log]
format = "json"   # "json" | "pretty"
filter = "info"   # tracing EnvFilter syntax. RUST_LOG overrides it.
```

`[[scopes]]` の既定値は空。`public_base_url` と `database.url` には既定値がなく、ないと終了コード 2。

検証（`config::validate`。最初の誤りで終了コード 2 とメッセージを返す）:

- `public_base_url` が絶対 URL で、クエリとフラグメントを持たない。スキームは `https`、または `allow_insecure_http=true` のときだけ `http`。末尾の `/` は取り除いて使う。
- `*_secs` と `audit_retention_days` と `max_connections` は 1 以上。
- `scopes[].name` が `ScopeToken::try_new` を通り、重複がない。`description` は 1〜200 文字。
- `server.listen` と `ops.listen` がソケットアドレスとして読め、同じではない。
- `public_base_url` が `https` で `cookie_secure=false` のときは、エラーにせず `warn` ログを出す。

設定と各 crate の対応:

| 設定 | 渡す先 |
|---|---|
| `oauth.*`、`session.ttl_secs`、`clients.allow_public`、`scopes`、`cleanup.grace_secs`、`cleanup.audit_retention_days` | `ApplicationConfig` |
| `database.*` | `PgStoreConfig` |
| `server.public_base_url`、`session.cookie_secure`、`oauth.authorization_request_ttl_secs`（→ `csrf_cookie_ttl`） | `HttpConfig`（`max_body_bytes` は既定値の 16 KiB で固定） |

`Config` の `Debug` 出力では `database.url` を `[REDACTED]` にする（`Secret<String>` で持てば、`Secret` の `Debug` がそう出すので手書きは要らない）。

`Config` は `#[derive(Debug, serde::Deserialize)]` だけを付け、`Clone` と `PartialEq` は derive しない（`Secret` がどちらも実装しないため）。`wiring` は `Config` を値で受け取り、`database.url` を `PgStoreConfig` へ move する（`clone_secret()` で複製しない）。ほかの設定は `wiring` の中で各 crate の設定へ写す。`database.url` の型が違う（TOML で `url = 123` など）ときの deserialize のエラーは、`Secret` が中身を出さないように文言を `failed to deserialize secret` に固定する（ddd-toolkit 0.5.0 の仕様）。figment がキー名を付けるので、終了コード 2 のメッセージには `database.url` と `failed to deserialize secret` が含まれる。

## CLI

```
komainu [--config PATH] <COMMAND>

komainu serve [--migrate]
komainu migrate
komainu client create --name NAME
    [--type confidential|public]                  # default confidential
    [--auth-method client_secret_basic|client_secret_post|private_key_jwt|none]
                                                  # default: client_secret_basic (confidential), none (public)
    [--redirect-uri URI]...                       # repeatable
    [--grant-type authorization_code|client_credentials|refresh_token|urn:ietf:params:oauth:grant-type:jwt-bearer]...
                                                  # repeatable; default authorization_code
    [--scope "a b"]                               # allowed_scopes; default empty
    [--default-scope "a"]                         # default_scopes; default empty
    [--skip-consent]
    [--jwks-file PATH | --jwks-uri URL]           # private_key_jwt のときだけ必須、ほかでは指定不可
    [--output text|json]                          # default text
komainu client list [--limit N] [--after CLIENT_ID] [--output text|json]   # limit default 100
komainu client show CLIENT_ID [--output text|json]
komainu client update CLIENT_ID [--name NAME] [--redirect-uri URI]... [--grant-type G]...
    [--scope "a b"] [--default-scope "a"] [--skip-consent true|false] [--auth-method M]
    [--jwks-file PATH | --jwks-uri URL] [--output text|json]
komainu client rotate-secret CLIENT_ID [--output text|json]
komainu client disable CLIENT_ID
komainu client enable CLIENT_ID
komainu issuer create --issuer ID --jwks-file PATH --client CLIENT_ID... [--output text|json]
                                      # --client は 1 回以上（最大 100）
komainu issuer list [--limit N] [--after ID] [--output text|json]          # limit default 100
komainu issuer show ID [--output text|json]
komainu issuer update ID [--jwks-file PATH] [--client CLIENT_ID]... [--output text|json]
                                      # どちらか 1 つは必須。--client は許可するクライアントの一覧をまるごと置き換える
komainu issuer disable ID
komainu issuer enable ID
komainu issuer map-subject ID --subject SUB --username NAME [--output text|json]   # 既存の対応は上書き
komainu issuer unmap-subject ID --subject SUB
komainu issuer list-subjects ID [--limit N] [--after SUB] [--output text|json]     # limit default 100
komainu user create USERNAME          # password: first line of stdin
komainu user set-password USERNAME    # password: first line of stdin
komainu user list [--limit N] [--after USERNAME] [--output text|json]
komainu user show USERNAME [--output text|json]
komainu user disable USERNAME
komainu user enable USERNAME
```

- `client update` で `--redirect-uri` や `--grant-type` を 1 つでも指定すると、その項目の一覧をまるごと置き換える。指定しない項目は変えない。
- `private_key_jwt` のクライアントはシークレットを持たない。`create` は `client_secret` を出さず、`rotate-secret` は終了コード 2 になる。`update` で `private_key_jwt` とシークレット方式の間を切り替えることはできない（終了コード 2）。`--jwks-file` は JWK Set の JSON ファイルで、読めない、公開鍵でない、鍵が 1〜10 個でないときは終了コード 2。`--jwks-uri` は `https` の URL（登録時には取得せず、検証時に取得して最長 1 時間キャッシュする。キャッシュに無い `kid` は、前回取得から 60 秒以上経っていれば再取得する）。`show` の `text` には `keys: jwks (N keys)` か `keys: jwks_uri <URL>` の行が付く。
- `issuer` は外部の発行者（jwt-bearer グラントで受け付けるアサーションの署名者）を管理する。`--client` は存在するクライアントでなければならない（なければ `UnknownClient`、終了コード 2）。`map-subject` の `--username` が存在しないユーザー、`ID` が存在しない発行者のときは終了コード 3。`issuer show` の `text` は `id`、`status`、`clients`、`keys`（鍵の数）、`created_at`、`updated_at`。`issuer list` の `text` は `<id>\t<status>`。
- パスワードは標準入力の最初の 1 行（末尾の `\n` と `\r\n` を除く）。`NewPassword::try_new` に通らなければ（空、8 文字未満、129 文字以上）終了コード 2。
- `--scope` と `--default-scope` は 1 回だけ指定でき、値はスペース区切りの文字列（`ScopeSet::parse`）。空文字（`--scope ""`）は空の集合を表す（`ScopeSet::empty()`。`parse` は呼ばない）。
- `client update` で `redirect_uris` を空にするには `--clear-redirect-uris` を付ける（`--redirect-uri` と同時には指定できない。clap の `conflicts_with`）。`grant_types` は空にできない（不変条件 1）。
- `serve` と `migrate` 以外のコマンドは、DB に接続して `AdminService` を呼ぶ。`RequestContext` の `request_id` は UUIDv7、`client_ip` は `None`。
- 管理コマンドは、マイグレーション未適用の DB に対してはエラー（終了コード 1）になる。

出力（`text`）:

```
$ komainu client create --name demo --redirect-uri https://app.example/cb --grant-type authorization_code --grant-type refresh_token --scope "read write"
client_id: 01936f2e-...
client_secret: Zq3...(43 chars)
```

`client_secret` の行は confidential のときだけ出し、標準エラー出力に `Store the client secret now. It cannot be shown again.` を出す。`rotate-secret` も同じ形式。`show` と `list` はシークレットを出さない。`list` の `text` は 1 行 1 件で `<client_id>\t<name>\t<type>\t<active|disabled>`（ユーザーは `<username>\t<active|disabled>`）。

`json` は `ClientView` / `UserView` を次の形にして 1 つの JSON（`list` は配列）で出す。時刻は RFC 3339。

```json
{"client_id":"...","client_secret":"...","name":"demo","client_type":"confidential",
 "auth_method":"client_secret_basic","redirect_uris":["https://app.example/cb"],
 "grant_types":["authorization_code","refresh_token"],"allowed_scopes":["read","write"],
 "default_scopes":[],"skip_consent":false,"active":true,
 "created_at":"2026-11-22T00:00:00Z","updated_at":"2026-11-22T00:00:00Z"}
```

`client_secret` は `create` と `rotate-secret` のときだけ含める。

## serve

1. 設定を読み、`telemetry::init(&config.log)` でログを初期化し、Prometheus の recorder を登録する。
2. `adapter_postgres::connect`。`--migrate` があれば `migrate` を実行する。
3. `wiring` で `Dependencies`（`PgUnitOfWorkFactory`、`SystemClock`、`OsSecureRandom`、`Argon2PasswordHasher`、`BuiltinAuthenticator`）と `AppState` を作る。
4. メインのリスナー（`komainu_http::router` を `into_make_service_with_connect_info::<SocketAddr>()` で）と ops のリスナーを起動し、`cleanup.enabled` なら削除ジョブも起動する。
5. `info` ログ `komainu started` に `listen`、`ops_listen`、`version` を出す。

### ops エンドポイント（`ops.listen`）

| パス | レスポンス |
|---|---|
| `GET /healthz` | 常に `200`、本文 `ok` |
| `GET /readyz` | `MaintenanceService::check_ready` が成功すれば `200`、本文 `ready`。失敗すれば `503`、本文 `not ready` |
| `GET /metrics` | `200`、`Content-Type: text/plain; version=0.0.4`、Prometheus のテキスト形式 |

### 停止

SIGTERM か SIGINT（Ctrl-C）を受けたら:

1. `info` ログ `shutdown requested` を出す。
2. 2 つのリスナーで新しい接続の受け付けを止め（axum の `with_graceful_shutdown`）、削除ジョブを止める。
3. 処理中のリクエストが終わるのを `shutdown_timeout_secs` 秒まで待つ。終われば終了コード 0、時間切れなら `warn` ログを出して終了コード 1。

## 削除ジョブ

```rust
/// Runs one purge and records logs/metrics. Never panics on store errors.
pub async fn run_once(service: &MaintenanceService) -> Result<PurgeReport, StoreError>;
/// Calls run_once every interval until `shutdown` resolves. The first run is one interval after start.
pub async fn run_periodic(service: MaintenanceService, interval: std::time::Duration, shutdown: impl Future<Output = ()>);
```

- 成功したら `info` ログ `cleanup finished` に種類ごとの件数を出し、`komainu_cleanup_deleted_total{kind}` に件数を足す。`kind` は `authorization_requests`、`authorization_codes`、`access_tokens`、`refresh_tokens`、`login_sessions`、`grants`、`audit_events`。
- 失敗したら `warn` ログを出し、次の周期で再び実行する。
- どちらも `komainu_cleanup_runs_total{result="success"|"failure"}` を 1 増やす。
- 複数のサーバーが同時に動かしても、同じ行を消し合うだけで害はない（排他はしない）。

## ログ

- `log.format = "json"` は `tracing_subscriber::fmt().json()`（1 行 1 JSON、`timestamp`、`level`、`target`、`fields`、`span`）。`pretty` は人が読む形式。
- `RUST_LOG` があれば `log.filter` より優先する。
- トークン、コード、シークレット、パスワード、セッション ID、`database.url` をログに出さない（N-3）。

## エラー

| 状況 | 扱い |
|---|---|
| 設定の検証エラー | 終了コード 2 |
| 起動時に DB へ接続できない | `error` ログを出して終了コード 1（再試行しない。再起動はプロセス管理側に任せる） |
| 起動後に DB が落ちた | プロセスは動かし続ける。`/readyz` が `503`、各リクエストは `500` |
| リスナーのアドレスが使用中 | 終了コード 1 |

## 受け入れ条件

設定（単体テスト、DB 不要）:

- `config/komainu.example.toml` を読み込むと検証を通る。
- TOML で `[database]` に `url = 123` と書いたとき、終了コード 2 で、標準エラーに `database.url` と `failed to deserialize secret` が含まれる。
- `figment::Jail` の中で同じファイルを置き、`KOMAINU_DATABASE__URL=postgres://other/db` を設定すると、その値が使われる（`config.database.url.expose_secret_ref()` で比べる）。
- `public_base_url = "http://auth.example.com"`（`allow_insecure_http` なし）は終了コード 2 になる。
- `[[scopes]]` に同じ `name` が 2 つあれば終了コード 2。
- `format!("{:?}", config)` に `database.url` のパスワードが含まれない。

CLI（`--features pg-tests`、testcontainers の PostgreSQL に `migrate` した後、`assert_cmd` で実行）:

- `client create --name demo --grant-type client_credentials --scope read` は終了コード 0 で、`client_id:` と `client_secret:` の 2 行を出す。その ID とシークレットで `TokenService::exchange`（client_credentials）が成功する。
- `client show <id>` の出力に `client_secret` が含まれない。
- `client show 00000000-0000-0000-0000-000000000000` は終了コード 3。
- `--redirect-uri "https://app.example/cb#frag"` を付けた `client create` は終了コード 2。
- `--scope admin`（設定にないスコープ）は終了コード 2。
- `echo -n 'password123' | komainu user create alice` は終了コード 0。もう一度同じコマンドを実行すると終了コード 4。
- `client disable <id>` の後、そのクライアントに発行済みのアクセストークンは `verify_access_token` で `Ok(None)` になる（F-11）。
- 各管理コマンドの後、`audit_events` に対応する `kind`（`client.registered` など）の行が 1 件増え、`actor` が `admin` になっている（F-12）。

serve と ops（`--features pg-tests`）:

- サーバーを起動すると、`GET /healthz` と `GET /readyz` が `200` を返す。
- `/token` を 1 回呼んだ後の `GET /metrics` に `komainu_http_requests_total` と `komainu_token_requests_total` が含まれる。
- SIGTERM を送ると、終了コード 0 で 30 秒以内に終わる（手動確認でもよい。README の T15）。

削除ジョブ（`--features pg-tests`）:

- 期限から 25 時間、ちょうど 24 時間、23 時間たったアクセストークンを 1 件ずつ入れて `run_once` を呼ぶと、前の 2 件だけが消え、`PurgeReport.counts.access_tokens == 2` になる（F-13）。

## 実装メモ

- figment の環境変数は `Env::prefixed("KOMAINU_").split("__")` で読める。`[[scopes]]` を環境変数から外すには `.ignore(&["scopes"])` を使う。
- `metrics-exporter-prometheus` は `PrometheusBuilder::new().install_recorder()` でハンドルを得て、`/metrics` のハンドラで `handle.render()` を返す。テストで複数回登録しないよう、recorder の登録は `serve` の中だけで行う。
