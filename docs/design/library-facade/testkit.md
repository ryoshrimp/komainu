# komainu-testkit と store の適合性テスト

- 責務: テスト用のインメモリ adapter（今の `komainu-testing` の中身）と、任意の `UnitOfWorkFactory` 実装が application の期待する契約を満たすかを確かめる適合性テストを公開する。本番用の adapter は持たない
- 配置: `crates/testkit`（`crates/testing` から移動）
- 関連要件: F-3、F-9

## 公開インターフェース

### 改名

| 項目 | 変更前 | 変更後 |
|---|---|---|
| ディレクトリ | `crates/testing` | `crates/testkit` |
| package 名 | `komainu-testing` | `komainu-testkit` |
| Rust の crate 名 | `komainu_testing` | `komainu_testkit` |
| `publish` | `false` | 指定なし（公開する） |
| `description` | `In-memory adapters for testing komainu` | `In-memory adapters and store conformance tests for komainu` |

既存の公開型（`FixedClock`、`TestEnv`、`PlainPasswordHasher`、`SequenceRandom`、`InMemoryState`、`InMemoryUnitOfWorkFactory`）は名前もシグネチャも変えない。rustdoc に「本番で使わないこと」（`PlainPasswordHasher` は平文、`SequenceRandom` は予測できる）を明記する。

### 依存の追加

```toml
[dependencies]
tokio = { workspace = true, features = ["macros"] }   # conformance のケースで tokio::join! を使う
uuid.workspace = true                                  # dev-dependencies から移す

[dev-dependencies]
tokio = { workspace = true, features = ["macros", "rt"] }   # tests/ の #[tokio::test] 用
```

ケースは呼び出し側のランタイムで動く。testkit は tokio のランタイムを作らない。`tokio::spawn` を使わないので、`current_thread` でも `multi_thread` でも動く。

### conformance モジュール

```rust
pub mod conformance {
    /// Runs every case against a fresh, empty store from `make_store` and panics with the
    /// names and messages of all failed cases.
    ///
    /// `make_store` is called once per case. Each store must be empty (no rows) and must
    /// not share data with stores returned by earlier calls.
    pub async fn run_store_conformance<F, Fut>(make_store: F)
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Arc<dyn UnitOfWorkFactory>>;

    /// The individual cases, for adapters that want one test per case.
    pub fn store_cases() -> &'static [StoreCase];

    #[non_exhaustive]
    pub struct StoreCase {
        pub name: &'static str,
        pub run: fn(Arc<dyn UnitOfWorkFactory>) -> BoxFuture<'static, Result<(), CaseFailure>>,
    }

    /// Why a case failed; `Display` gives a one-line message.
    #[derive(Debug)]
    pub struct CaseFailure { /* message: String */ }
    impl CaseFailure {
        pub fn new(message: impl Into<String>) -> Self;
    }
    impl std::fmt::Display for CaseFailure { /* message */ }
}
```

- `BoxFuture` は `komainu_application::BoxFuture`。
- `run_store_conformance` はケースを `store_cases()` の順に 1 つずつ（並行させずに）実行し、失敗をすべて集めてから、1 件以上あれば `panic!("{n} of {total} store conformance cases failed:\n- {name}: {message}\n...")` する。全部通れば何もしない。
- ケースの中で起きた `StoreError` は `CaseFailure` に変換して返す（panic しない）。ケース自身の panic はそのまま伝わる。

## データ

ケースが書き込む値の固定値（時刻、ID、ハッシュ）は `conformance` の内部 fixture に持つ。時刻は `OffsetDateTime::from_unix_timestamp(1_800_000_000 + n)`（今の Pg テストの `common::t` と同じ）を使い、`Clock` には依存しない（store だけを相手にする）。

## 振る舞い

### ケース一覧

今の `crates/adapter-postgres/tests/postgres.rs` のうち、store の契約を確かめるものを移す。名前は `StoreCase::name` の値。

| name | 移す元 | 確かめること |
|---|---|---|
| `client_user_session_roundtrip` | 同名 | クライアント・ユーザー・ログインセッションの insert / find / update / list が往復で値を保つ |
| `authorization_flow_records_roundtrip` | 同名 | 認可リクエスト・認可コード・同意・grant・トークンの往復 |
| `audit_append_commits` | `audit_append_is_stored` の前半 | 監査イベントの `append` と `commit` がエラーにならない（port に読み出しがないので、保存されたかは確かめない。Pg 側の `audit_append_is_stored` はそのまま残す） |
| `dropped_uow_is_rolled_back` | 同名 | commit せずに drop した UoW の書き込みが見えない |
| `unique_violation_is_conflict` | 同名 | 一意制約の違反が `StoreError::Conflict` になる |
| `client_duplicate_id_is_conflict` | 同名 | 同じ client_id の insert が `StoreError::Conflict` になる |
| `purge_expired_deletes_only_expired_rows` | 同名 | 期限切れの行だけを消し、件数を正しく返す |
| `purge_audit_events_deletes_old_events` | 同名 | 保持期間より古い監査イベントだけを消す |
| `concurrent_code_redemption_has_one_winner` | 同名 | 同じ認可コードを 2 つの UoW で同時に使うと、成功は 1 つだけ |

Pg 固有のものとして `postgres.rs` に残すのは `migrate_twice_succeeds`、`corrupted_enum_value_is_other`、`tokens_are_stored_hashed_only`、`audit_append_is_stored`（sqlx で件数を数える）、`concurrent_code_exchange_issues_tokens_once` と `concurrent_refresh_rotates_once`（TokenService を通す結合テストで、sqlx で行を確かめるので store の契約ではない）の 6 つ。移したケースは `postgres.rs` から消す。

- 同時実行のケース（`concurrent_code_redemption_has_one_winner`）は、今の 10 タスクの `tokio::spawn` をやめ、2 つの future を `tokio::join!` で同じタスク上で並べる（並列数を 10 から 2 に減らす）。各 future は自分の中で `begin` → `find_for_update` → `redeem` → 成功なら `grants().insert` と `update` → `commit` を行う（先に 2 つとも `begin` してから進める書き方にはしない）。インメモリ store は await で中断しないので 1 つ目の future が commit まで終わってから 2 つ目が始まり、Pg では行ロックで 2 つ目が待つ。どちらでも「成功は 1 つだけ」になる。
- 楽観ロックの store のために、`find_for_update`・`update`・`commit` のどれかが `StoreError::Conflict` を返した future は「負け」として数える（ケースの失敗にしない）。ほかの `StoreError` はケースの失敗。勝ちがちょうど 1 つでなければ失敗。
- 各ケースのアサーションは、今の Pg テストのアサーションをそのまま `CaseFailure` を返す形に書き換えたものにする（確かめる内容を増やさない・減らさない）。Pg 固有の SQL（`sqlx::query` での直接確認）を使っているアサーションは、store の port を通した確認に置き換えるか、置き換えられなければ Pg 側に残す。

### Pg での実行

`crates/adapter-postgres/tests/conformance.rs`（`#![cfg(feature = "pg-tests")]`）で、`mod common;` で既存の `crates/adapter-postgres/tests/common/mod.rs` を共有し、`common::start_raw()` でコンテナを 1 つだけ起動する。`make_store` は連番を持つクロージャで、呼ばれるたびに `n` を増やし、`db.pool` で `CREATE DATABASE conformance_{n}` を実行し、`db.url` の末尾 `/postgres` を `/conformance_{n}` に置き換えた URL で `PgStoreConfig` を作って `connect`・`migrate` し、その `PgUnitOfWorkFactory` を返す（URL と `n` は `async move` の前に clone する）。

## エラー

| 状況 | 返すもの | 呼び出し側の扱い |
|---|---|---|
| 1 件以上のケースが失敗 | `run_store_conformance` が panic（失敗した全ケースの名前と理由） | テストの失敗として表示される |
| ケース内の `StoreError` | `Err(CaseFailure)` | 同上 |

## 設定

なし。

## 受け入れ条件

- `crates/testkit/tests/in_memory_conformance.rs` で `run_store_conformance(|| async { Arc::new(InMemoryUnitOfWorkFactory::new()) as Arc<dyn UnitOfWorkFactory> })` が通る。
- わざと壊した store（`InMemoryUnitOfWorkFactory` を包む factory。`begin` は内側の UoW を包んだ UoW を返し、その UoW は `clients()` 以外の 10 個のアクセサーと `commit` を内側にそのまま委譲する。`clients()` が返すリポジトリは `insert` だけ、内側が `Conflict` を返したら `Ok(())` に変え、ほかのメソッドは内側に委譲する）を渡したとき、panic のメッセージに `client_duplicate_id_is_conflict` が含まれる。
- `cargo test -p komainu-adapter-postgres --features pg-tests` で `conformance.rs` が通り、`postgres.rs` には上の 6 ケースだけが残る。
- `store_cases()` の件数は 9、名前は上の表と一致する。

## 実装メモ

- 移す元のテストは `crates/adapter-postgres/tests/postgres.rs` と、fixture は `crates/adapter-postgres/tests/common/mod.rs`（`t`・`hash`・`cid`・`subject` など）。fixture は `conformance` の内部モジュールに移し、Pg 側のテストは必要なら testkit の fixture を使わずに今の `common` を使い続けてよい。
- 壊れた store のテスト用ラッパーは `crates/testkit/tests/` の中に置き、公開 API にはしない。
