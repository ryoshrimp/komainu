# komainu-http

- 責務: HTTP のエンドポイントと画面。リクエストの解析、Cookie、OAuth エラーの HTTP 表現、セキュリティヘッダー、request id、HTTP メトリクス。ビジネスルールは持たず、application のユースケースを呼ぶだけ。
- 配置: `crates/http`
- 関連要件: F-1〜F-9、N-6〜N-8

## 公開インターフェース

依存: `komainu-application`、`komainu-domain`、`axum = "0.8"`（`form`, `query`）、`tower = "0.5"`、`tower-http = "0.7"`（`trace`, `request-id`, `limit`）、`askama = "0.16"`、`serde = "1"`、`serde_json = "1"`、`form_urlencoded = "1"`、`base64 = "0.22"`、`url = "2"`、`time`、`uuid`、`tracing`、`metrics = "0.24"`、`subtle`。dev-dependencies: `komainu-testing`、`tokio`、`http-body-util`。

```rust
#[derive(Debug, Clone)]
pub struct HttpConfig {
    /// External base URL, e.g. https://auth.example.com or https://example.com/oauth.
    /// Validated by komainu-server (absolute http(s) URL, no query/fragment) and stored as a
    /// string with the trailing '/' removed. Paths are built by plain concatenation:
    /// format!("{public_base_url}/login").
    pub public_base_url: String,
    /// Adds `Secure` to cookies.
    pub cookie_secure: bool,
    /// Max request body for form posts.
    pub max_body_bytes: usize, // default 16 * 1024
    /// Max-Age of the komainu_csrf cookie; set to ApplicationConfig::authorization_request_ttl.
    pub csrf_cookie_ttl: time::Duration,
}

#[derive(Clone)]
pub struct AppState {
    pub authorization: AuthorizationService,
    pub token: TokenService,
    pub config: Arc<HttpConfig>,
}

/// All endpoints below plus the middleware stack. Mount at "/" (the base path is part of public_base_url
/// only for Location headers; embedders using a prefix should nest this router under the same prefix).
pub fn router(state: AppState) -> axum::Router;
```

`client_ip` は、リクエストの extension に `axum::extract::ConnectInfo<SocketAddr>` があればそのアドレス、なければ `None` にする（`X-Forwarded-For` は見ない）。

## エンドポイント

すべてのパスは `router` の基準からの相対。`<base>` は `public_base_url` の文字列。

| メソッドとパス | 用途 |
|---|---|
| `GET /authorize`、`POST /authorize` | 認可エンドポイント（§3.1、§4.1.1）。POST は `application/x-www-form-urlencoded` のボディを GET のクエリと同じに扱う |
| `GET /login?request_id=<uuid>` | ログイン画面 |
| `POST /login` | ログインの送信 |
| `GET /authorize/resume?request_id=<uuid>` | ログイン後の続き |
| `POST /authorize/decision` | 同意の送信 |
| `POST /logout` | ログアウト |
| `POST /token` | トークンエンドポイント（§3.2） |

ほかのメソッドは axum の既定どおり `405`。

### GET/POST /authorize

1. クエリ（POST ならボディ）を `form_urlencoded::parse` で `(String, String)` の列にし、`AuthorizeParams::from_pairs` に渡す。
2. Cookie `komainu_session` があれば `OpaqueToken::try_new` に通し、失敗したら `None` にする。
3. `AuthorizationService::start` を呼び、結果に応じて返す。

| 結果 | レスポンス |
|---|---|
| `LoginRequired { request_id }` | `302`、`Location: <base>/login?request_id=<id>`。`csrf_token` を `komainu_csrf` に設定 |
| `ConsentRequired { request_id, prompt }` | `200` 同意画面。`csrf_token` を `komainu_csrf` に設定し、同じ値を画面の hidden に入れる |
| `Redirect { location }` | `302`、`Location: <location>` |
| `Err(NonRedirectable(e))` | `400` エラー画面（下の表） |
| `Err(Redirect { location, .. })` | `302`、`Location: <location>` |
| `Err(Store(_))` | `500` エラー画面「Temporarily unavailable.」 |

### GET /login

- `request_id` が UUID として読めない → `400` エラー画面（`RequestNotFound` の文言）。
- Cookie `komainu_csrf` がない → `400`（`CsrfMismatch` の文言）。
- `login_form` が成功 → `200` ログイン画面。hidden に `request_id` と `csrf_token`（Cookie の値）を入れる。
- `login_form` が `Err(NonRedirectable(e))` → `400` エラー画面（下の文言表）。`Err(Store(_))` → `500` エラー画面「Temporarily unavailable.」。`Err(Redirect { .. })` は返らない。

### POST /login

フォーム: `request_id`、`csrf_token`、`username`、`password`（どれも必須。欠けていれば `400`、`RequestNotFound` の文言）。

1. フォームの `csrf_token` と Cookie `komainu_csrf` が一致しなければ（時間定数比較）`400`（`CsrfMismatch`）。
2. `AuthorizationService::login` を呼ぶ。`password` は検証せず `Secret::new(String)` に包んで `LoginCredentials` に渡す（長さの誤りも application が `InvalidCredentials` にして監査に残す。F-12）。

監査に残らないのは、フォームの項目が欠けているときと CSRF の不一致のときだけ（どちらも `400`。ユーザー名とパスワードの照合まで進んでいないため）。ログイン試行のメトリクス `komainu_login_attempts_total{result}` は、`login` を呼んだ結果ごとに http が数える（`result` は `success`、`invalid_credentials`、`error`）。

| 結果 | レスポンス |
|---|---|
| `LoggedIn { session_token, max_age, .. }` | `302`、`Location: <base>/authorize/resume?request_id=<id>`。`komainu_session` を設定（`Max-Age` は `max_age` の秒数） |
| `InvalidCredentials` | `200` ログイン画面を再表示し、「Invalid username or password.」を出す。`username` の入力値は残し、`password` は空にする |
| `Authorize(NonRedirectable(e))` | `400` エラー画面 |
| `Store(_)` | `500` エラー画面 |

### GET /authorize/resume

`AuthorizationService::resume` を呼ぶ。`LoginRequired` → `302 <base>/login?request_id=<id>`、`ConsentRequired` → `200` 同意画面（hidden の `csrf_token` は Cookie の値。Cookie がなければ `400` `CsrfMismatch`）、`Redirect` → `302`。エラーは `/authorize` と同じ。

### POST /authorize/decision

`Content-Type` は `application/x-www-form-urlencoded` だけを受け付ける（ほかは `400`、`RequestNotFound` の文言。`/login` も同じ）。フォーム: `request_id`、`csrf_token`、`decision`（`approve` か `deny`。ほかの値は `400`、`RequestNotFound` の文言）。CSRF の二重確認は `/login` と同じ。`decide` の結果の URI へ `302`。成功したら `komainu_csrf` を削除する（`Max-Age=0`）。

### POST /logout

Cookie `komainu_session` があれば `logout` を呼び、`komainu_session` を削除して、`200` で「Signed out.」の画面を返す。`logout` が `StoreError` を返したら `500` エラー画面「Temporarily unavailable.」（Cookie は削除する）。Cookie がなくても同じ画面を返す。CSRF の確認はしない（ログアウトさせられる以上の害がないため）。

### エラー画面の文言

| `NonRedirectableError` | 画面の文言（英語） |
|---|---|
| `DuplicateParameter` | `The request contains duplicated parameters.` |
| `MissingClientId` | `client_id is missing.` |
| `UnknownClient` | `Unknown client.` |
| `InvalidRedirectUri` | `redirect_uri is invalid.` |
| `RedirectUriMismatch` | `redirect_uri does not match a registered URI.` |
| `MissingRedirectUri` | `redirect_uri is required for this client.` |
| `RequestNotFound` | `This authorization request has expired or was already used. Please start again from the application.` |
| `CsrfMismatch` | `The form has expired. Please start again from the application.` |
| `LoginRequired` | `Please sign in again.`（`400` ではなく `302 <base>/login?request_id=<id>` にする） |

### POST /token

1. `Content-Type` が `application/x-www-form-urlencoded`（`; charset=` などの引数は許す）でなければ `invalid_request`。
2. ボディを `(String, String)` の列にする。`client_id` と `client_secret` を取り出し、残りを `TokenRequest::from_pairs` に渡す。`client_id` か `client_secret` が 2 回出てくれば `invalid_request`。
3. `Authorization` ヘッダーを見て `ClientAuthentication` を決める。

| 条件 | 結果 |
|---|---|
| `Authorization: Basic` があり、ボディに `client_secret` もある | `invalid_request` |
| `Basic` があり、ボディの `client_id` が Basic の ID と違う | `invalid_request` |
| `Basic` の値が base64 として不正、`:` を含まない、ID かシークレットの URL デコード（`application/x-www-form-urlencoded`、§2.3.1）に失敗 | `invalid_client`（`basic_attempted = true`） |
| `Basic` が正しい形 | `Basic { client_id, secret }` |
| `Basic` がなく、ボディに `client_id` と `client_secret` | `Post` |
| `Basic` がなく、ボディに `client_id` だけ | `PublicId` |
| `Basic` がなく、ボディに `client_secret` だけ | `invalid_request` |
| どれもない（`Basic` 以外の方式のヘッダーを含む） | `None` |

この表で `invalid_request` になった場合（2 の重複も含む）は、http が `TokenError::InvalidRequest` と同じ応答を返し、`exchange` は呼ばない。クライアントを特定する前の形式の誤りなので、`client_authentication.failed` の監査は書かない（メトリクス `komainu_token_requests_total{result="invalid_request"}` には数える）。`/token` のエラー応答はすべて `Content-Type: application/json;charset=UTF-8`。

4. `TokenService::exchange` を呼ぶ。

成功時は `200`。

```http
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Cache-Control: no-store
Pragma: no-cache

{"access_token":"<43 chars>","token_type":"Bearer","expires_in":3600,"refresh_token":"<43 chars>","scope":"read write"}
```

`refresh_token` は `None` ならキーごと省く。

エラー時は §5.2 の JSON（`{"error":"<code>","error_description":"<固定の英文>"}`）に、成功時と同じ `Cache-Control` と `Pragma` を付ける。

| `TokenError` | ステータス | 追加のヘッダー |
|---|---|---|
| `InvalidRequest`、`InvalidGrant`、`UnauthorizedClient`、`UnsupportedGrantType`、`InvalidScope` | `400` | |
| `InvalidClient { basic_attempted: true }` | `401` | `WWW-Authenticate: Basic realm="komainu"` |
| `InvalidClient { basic_attempted: false }` | `401` | なし |
| `Server(_)` | `500` | |

## Cookie

| 名前 | 値 | 属性 |
|---|---|---|
| `komainu_session` | セッショントークンの平文 | `HttpOnly; SameSite=Lax; Path=/; Max-Age=<秒>`、`cookie_secure` なら `Secure` |
| `komainu_csrf` | CSRF トークンの平文 | `HttpOnly; SameSite=Lax; Path=/; Max-Age=<csrf_cookie_ttl の秒>`、`cookie_secure` なら `Secure` |

`komainu_csrf` は 1 つだけなので、同じブラウザで認可を 2 つ並行して始めると、先に始めたほうの画面は `CsrfMismatch` になる（仕様として受け入れる）。

## 共通ミドルウェア

外側から順に:

1. **request id**: `x-request-id` ヘッダーが 1〜128 文字の `%x21-7E` ならそのまま使い、そうでなければ UUIDv7 を作る。レスポンスにも `x-request-id` を付ける。ハンドラは `RequestContext.request_id` にこの値を入れる。
2. **トレース**: `tower_http::trace::TraceLayer`。span `http_request` に `request_id`、`method`、`path`（クエリを含めない。`code` や `state` がログに出ないようにする）を持たせ、完了時に `status` と `latency_ms` を `info` で出す。
3. **メトリクス**: 下の表。
4. **ボディの上限**: `RequestBodyLimitLayer(max_body_bytes)`。超えたら `413`。
5. **セキュリティヘッダー**: HTML を返すレスポンス（`Content-Type: text/html`）に付ける。

| ヘッダー | 値 |
|---|---|
| `X-Frame-Options` | `DENY` |
| `Content-Security-Policy` | `default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'` |
| `Cache-Control` | `no-store` |
| `Referrer-Policy` | `no-referrer` |
| `X-Content-Type-Options` | `nosniff` |

`form-action` は指定しない（同意後のクライアントへのリダイレクトを妨げるブラウザがあるため）。

## メトリクス

`metrics` crate のマクロで記録する。recorder の登録は server が行う。

| 名前 | 種類 | ラベル | 記録する時点 |
|---|---|---|---|
| `komainu_http_requests_total` | counter | `method`、`route`（axum の `MatchedPath`。なければ `unmatched`）、`status` | すべてのレスポンス |
| `komainu_http_request_duration_seconds` | histogram | `method`、`route` | すべてのレスポンス |
| `komainu_token_requests_total` | counter | `grant_type`（`authorization_code` / `client_credentials` / `refresh_token` / `other`）、`result`（`success` かエラーコード） | `/token` |
| `komainu_authorization_requests_total` | counter | `result`（`login_required` / `consent_required` / `code` / `redirect_error` / `error_page`） | `/authorize` と `/authorize/resume` と `/authorize/decision` |
| `komainu_login_attempts_total` | counter | `result`（`success` / `failure`） | `POST /login` |

## 画面

`crates/http/templates/` に askama のテンプレートを置く。すべて `base.html` を継承し、`<meta name="viewport">` と最小限のインライン CSS だけを持つ（外部の CSS・JS・画像を読まない）。

| ファイル | 構造体 | フィールド |
|---|---|---|
| `login.html` | `LoginPage` | `client_name: String`、`request_id: String`、`csrf_token: String`、`username: String`、`error: Option<&'static str>` |
| `consent.html` | `ConsentPage` | `client_name: String`、`scopes: Vec<ScopeView>`、`request_id: String`、`csrf_token: String` |
| `error.html` | `ErrorPage` | `message: &'static str` |
| `logged_out.html` | `LoggedOutPage` | なし |

同意画面には「Allow」（`decision=approve`）と「Deny」（`decision=deny`）の 2 つの submit ボタンを置く。

## エラー

ハンドラで起きたエラーは、上の各表のとおりに変換する。`500` を返すときは、`StoreError` の内容を `error` レベルでログに出し、画面や JSON には出さない。

## 設定

`HttpConfig` の各項目。設定ファイルとの対応は [server.md](server.md)。

## 受け入れ条件

すべて `komainu-testing` の `TestEnv` で `AppState` を作り、`tower::ServiceExt::oneshot` で確かめる。`public_base_url = https://auth.example.com`。

認可系:

- 有効な `GET /authorize?response_type=code&client_id=..&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&scope=read&state=xyz` は `302`、`Location: https://auth.example.com/login?request_id=<uuid>` を返し、`Set-Cookie: komainu_csrf=...; HttpOnly; SameSite=Lax; Path=/` が付く。
- 続けて `POST /login`（正しい資格情報と CSRF）→ `302 .../authorize/resume?...` と `komainu_session` の Set-Cookie。`GET /authorize/resume` → `200` で同意画面。`POST /authorize/decision`（`approve`）→ `302`、`Location` が `https://app.example/cb?code=<43文字>&state=xyz`（F-1）。
- 未登録の `client_id` → `400` で、`Location` ヘッダーがない（F-2）。
- `scope=unknown` → `302`、`Location: https://app.example/cb?error=invalid_scope&error_description=...&state=xyz`（F-2）。
- フォームの `csrf_token` と Cookie が違う `POST /login` は `400`（N-7）。Cookie なしでも `400`。
- `cookie_secure = true` のとき、`komainu_session` と `komainu_csrf` の Set-Cookie に `Secure` が付く。
- ログイン画面、同意画面、エラー画面のレスポンスには、§共通ミドルウェアの 5 つのヘッダーが付く（N-6）。
- 同意画面の HTML では、クライアント名 `<script>` がエスケープされて `&lt;script&gt;` と出る。

トークン系:

- 正しい `client_secret_basic` で `grant_type=client_credentials&scope=read` → `200`、JSON に `access_token`、`token_type":"Bearer"`、`expires_in":3600`、`scope":"read"` があり、`refresh_token` キーがない。`Cache-Control: no-store` と `Pragma: no-cache` が付く（F-3、F-5）。
- 間違ったシークレットの Basic → `401`、`WWW-Authenticate: Basic realm="komainu"`、`{"error":"invalid_client",...}`（F-8）。
- Basic とボディの `client_secret` の両方 → `400`、`invalid_request`（F-8）。
- Basic の ID とシークレットの一部を percent-encode しても（例: シークレットの先頭の `A` を `%41` にする）、URL デコードしてから照合して認証が通る（§2.3.1）。シークレット中の `-` を `%2D` にしても通る。
- `Content-Type: application/json` の `/token` → `400`、`invalid_request`。
- 交換済みのコードで `/token` → `400`、`invalid_grant`（F-4）。

ミドルウェア:

- `x-request-id: abc-123` を付けたリクエストのレスポンスに `x-request-id: abc-123` が付き、その操作の監査イベントの `request_id` も `abc-123` になる（N-8）。ヘッダーがなければ UUID 形式の値が付く。
- 17 KiB のボディの `POST /token` は `413` になる。

## 実装メモ

- axum の `Query` / `Form` extractor は重複を検出できないので、`RawQuery` と `Bytes` で受けて `form_urlencoded::parse` する。
- 認可系のハンドラは `Result<Response, AuthorizeError>` を返し、`AuthorizeError` に `IntoResponse` を実装すると表のとおりに書きやすい。`TokenError` も同様（孤児ルールのため、http crate の newtype で包む）。
- `OpaqueToken` の比較（フォームと Cookie）は `subtle::ConstantTimeEq` で行う。
