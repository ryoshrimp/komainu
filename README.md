# komainu

Rust の Cargo workspace を使ったモノレポです。

## 構成

```text
.
├── Cargo.toml                 # workspace と共通のパッケージ設定
├── crates/
│   ├── komainu-domain/         # ドメインモデル・ルール
│   ├── komainu-application/    # ユースケース
│   ├── komainu-adapter-web/    # Web アダプター
│   ├── komainu-adapter-sqlite/ # SQLite アダプター
│   └── komainu-server/        # サーバーバイナリ
├── rust-toolchain.toml        # stable / rustfmt / clippy
├── LICENSE-MIT
└── LICENSE-APACHE
```

各ライブラリは実装用の空の雛形です。サーバーは現時点では `komainu-server` と
表示するだけで、HTTP の待ち受けや SQLite への接続は行いません。外部クレートへの依存はなく、
クレート間の依存も必要になった時点で追加します。誤公開を防ぐため、各クレートは
`publish = false` にしています。

## 開発

[rustup](https://rustup.rs/) をインストールしてください。
リポジトリ内では `rust-toolchain.toml` に従って stable ツールチェーンを使用します。

```sh
cargo build --workspace --locked
cargo run -p komainu-server --locked
cargo test --workspace --all-features --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

`Cargo.lock` は再現可能な依存解決のため Git で管理します。
GitHub Actions でもフォーマット・Clippy・テスト・ビルドを実行します。

## クレートの追加

```sh
cargo new crates/komainu-example --lib
```

`crates/*` は自動的に workspace のメンバーになります。
追加したクレートの `Cargo.toml` でも、既存クレート同様に以下を設定してください。

```toml
[package]
name = "komainu-example"
version.workspace = true
edition.workspace = true
license.workspace = true
publish = false

[lints]
workspace = true
```

## ライセンス

このプロジェクトは、利用者の選択により以下のいずれかのライセンスで利用できます。

- MIT License（[LICENSE-MIT](LICENSE-MIT)）
- Apache License, Version 2.0（[LICENSE-APACHE](LICENSE-APACHE)）

SPDX 識別子: `MIT OR Apache-2.0`
