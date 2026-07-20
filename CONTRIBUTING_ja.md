# Mayu への貢献

[English](CONTRIBUTING.md)

Mayu への貢献に興味を持っていただきありがとうございます！このガイドでは、開発環境のセットアップからテストの実行、変更の提出までを説明します。

> **注意:** このガイドは mayu のソースコードに貢献する**開発者**向けです。
> mayu を使用するだけであれば、[GitHub Releases](https://github.com/kato83/mayu/releases) からビルド済みバイナリをダウンロードしてください — Go のインストールは不要です。使い方は [README_ja.md](README_ja.md) を参照してください。

## 前提条件

- [Go 1.26+](https://go.dev/)（[asdf](https://asdf-vm.com/) で管理 — `.tool-versions` 参照）
- [Docker](https://www.docker.com/) & Docker Compose
- [golang-migrate](https://github.com/golang-migrate/migrate) CLI
- [lefthook](https://github.com/evilmartians/lefthook)（pre-commit フック）
- [golangci-lint](https://golangci-lint.run/) v2.12+

## 開発環境のセットアップ

```bash
# リポジトリのクローン
git clone https://github.com/kato83/mayu.git
cd mayu

# asdf で Go をインストール
asdf install

# PostgreSQL を起動
make docker-up

# データベースマイグレーション実行
make migrate-up

# CLI をビルド
make build

# 動作確認
./bin/mayu version
```

## 開発コマンド

| コマンド | 説明 |
|----------|------|
| `make build` | デバッグシンボル付きバイナリをビルド → `bin/mayu` |
| `make build-release` | リリース用バイナリをビルド（シンボル削除、約30%軽量） |
| `make build-embed` | Web UI 埋め込みバイナリをビルド |
| `make test` | ユニットテスト実行 |
| `make test-integration` | 統合テスト実行（PostgreSQL が必要） |
| `make fmt` | コードフォーマット（`go fmt`） |
| `make lint` | golangci-lint 実行 |
| `make clean` | バイナリ削除・キャッシュクリア |
| `make docker-up` | PostgreSQL 起動 |
| `make docker-down` | PostgreSQL 停止 |
| `make docker-clean` | PostgreSQL 停止・ボリューム削除 |
| `make migrate-up` | マイグレーション実行 |
| `make migrate-down` | マイグレーションのロールバック |
| `make migrate-create` | 新しいマイグレーションファイル作成（対話式） |

## プロジェクト構成

```
mayu/
├── cmd/mayu/              # CLI エントリポイント (ingest, search, serve, version)
├── internal/
│   ├── fetcher/           # GCS データダウンロード (OSV zip, 変換ソース)
│   ├── parser/            # OSV JSON パース
│   ├── store/             # PostgreSQL 永続化 (database/sql + pgx stdlib)
│   ├── model/             # OSV スキーマ Go 構造体
│   ├── server/            # HTTP/REST API サーバー (go-chi)
│   ├── ingest/            # パイプラインオーケストレーター
│   ├── cvss/              # CVSS スコアパースユーティリティ
│   ├── purl/              # Package URL パース
│   └── validate/          # 入力バリデーションヘルパー
├── migrations/            # golang-migrate SQL ファイル
├── testdata/              # テストフィクスチャ (OSV JSON サンプル)
├── docs/                  # ドキュメント (PLAN.md)
├── .github/workflows/     # CI (lint, test, build)
├── compose.yml            # 開発用 PostgreSQL 17
├── lefthook.yml           # Pre-commit フック (fmt, lint)
├── .tool-versions         # asdf: golang 1.26.5
├── go.mod / go.sum
└── Makefile
```

## アーキテクチャ

```mermaid
graph TD
    CLI["CLI (cmd/mayu)"]
    CLI --> Ingest[ingest]
    CLI --> Search[search]
    CLI --> Serve[serve]

    Ingest --> Fetcher["Fetcher (GCS)"]
    Ingest --> Parser["Parser (OSV)"]
    Ingest --> IngestPipeline["Ingest (Pipeline)"]
    Search --> Store["Store (PG)"]
    Serve --> Server["Server (HTTP/REST)"]
    Server --> Store
    IngestPipeline --> Store

    Store --> DB[(PostgreSQL)]
```

## コーディング規約

### 全般

- [Standard Go Project Layout](https://github.com/golang-standards/project-layout) に従う（`cmd/`, `internal/`）
- `database/sql` 標準インターフェースを pgx ドライバー（stdlib モード）で使用
- 外部依存は最小限に。Go 標準ライブラリを優先
- CLI フレームワーク不使用 — Go 標準 `flag` パッケージを使用
- パッケージは責務を1つに絞る

### スタイル

- 命名: Go の慣例に従う（MixedCaps、snake_case は使わない）
- エクスポートされた関数にはドキュメントコメントを必須とする
- エラーハンドリング: ライブラリコードでは panic せず、エラーを返す
- キャンセルとタイムアウトには `context.Context` を使用

### テスト

- 実装と並行してテストを書く（TDD 推奨）
- ユニットテスト: 同じパッケージ内の `*_test.go`
- 統合テスト: ビルドタグ `//go:build integration` を使用
- テストフィクスチャ: `testdata/` ディレクトリに配置
- テーブル駆動テストを適宜活用
- HTTP モックには `net/http/httptest` を使用

### データベース

- マイグレーションは golang-migrate で連番ファイルを使用
- up/down の両方を必ず用意する
- 命名規則: `{番号}_{説明}.up.sql` / `{番号}_{説明}.down.sql`
- 柔軟なデータ格納には JSONB を使用

## テストの実行

```bash
# ユニットテストのみ（外部依存なし）
make test

# 統合テスト（PostgreSQL が必要）
make docker-up
make migrate-up
make test-integration
```

## Pre-commit フック

このプロジェクトでは [lefthook](https://github.com/evilmartians/lefthook) を使用しており、ステージされた `.go` ファイルに対して自動的に `make fmt` と `make lint` が実行されます。

```bash
# lefthook のインストール（未インストールの場合）
go install github.com/evilmartians/lefthook@latest

# フックのインストール
lefthook install
```

## CI パイプライン

GitHub Actions が `main` へのプッシュ/PR ごとに実行されます:

1. **Lint** — golangci-lint v2.12.2
2. **Test** — PostgreSQL 17 に対してユニットテスト + 統合テスト
3. **Build** — バイナリのコンパイルと `mayu version` の検証

PR を提出する前に、ローカルで全チェックが通ることを確認してください。

## 変更の提出

1. リポジトリをフォークし、`main` からブランチを作成
2. ブランチ命名規則: `{type}/{short-description}`（例: `feature/kev-source`, `fix/search-crash`）
3. 明確でアトミックなコミットで変更を加える
4. テストの追加・更新を適切に行う
5. プッシュ前に `make fmt && make lint && make test` を実行
6. `main` に対して Pull Request を作成

## 設定

| 環境変数 | 説明 | デフォルト |
|----------|------|-----------|
| `DATABASE_URL` | PostgreSQL 接続文字列 | `postgres://mayu:mayu@localhost:5432/mayu?sslmode=disable` |

> [!WARNING]
> デフォルトの `DATABASE_URL` は `sslmode=disable` を使用しています。
> これは同梱の Docker PostgreSQL に対するローカル開発でのみ適切です。
> リモートまたは本番データベースに接続する場合は、`sslmode=require`
> （証明書検証まで行う場合は `verify-full`）を設定して TLS を強制してください。

## Web UI (Angular)

### 前提条件

- [Node.js 24+](https://nodejs.org/)（asdf で管理 — `.tool-versions` 参照）
- [pnpm 11+](https://pnpm.io/)

### 開発コマンド

| コマンド | 説明 |
|----------|------|
| `make ui-dev` | 開発サーバー起動（/api を :8080 にプロキシ） |
| `make ui-build` | プロダクションビルド |
| `make ui-test` | Vitest ユニットテスト実行 |
| `make ui-lint` | リンター実行 |

### 国際化 (i18n)

Web UI では [Angular 組み込みの i18n](https://angular.dev/guide/i18n) を使用して、全てのユーザー向けテキストを管理しています。

**ルール:**

1. **テンプレート内の全ての固定テキストに `i18n` を付与する** — i18n 属性なしのハードコードされたユーザー向け文字列は禁止
2. **カスタム ID を使用する** — 安定性のため常に `@@` 構文を使用: `i18n="@@component.purpose"`
3. **ID の命名規則** — `{component}.{purpose}` の camelCase 形式（例: `@@sidebar.appName`, `@@vulnList.clearFilters`）
4. **属性の場合** — `i18n-{attr}` を使用（例: `i18n-placeholder="@@vulnList.filterIdPlaceholder"`, `i18n-aria-label="@@header.openMenu"`）
5. **TypeScript 内の文字列** — `$localize` タグ付きテンプレートを使用: `` $localize`:@@id:text` ``
6. **テキストの追加・変更後** — `make ui-i18n-extract` で XLF を再生成し、`src/locale/messages.ja.xlf` を更新する
7. **ソースロケールは英語** — テンプレートのテキスト自体が英語版として機能する
8. **固有名詞** — ブランド名（Mayu, NVD, MITRE, CVSS）も i18n マークは付けるが、翻訳しなくてよい

**翻訳可能テキストの追加ワークフロー:**

```bash
# 1. テンプレートに i18n 属性を追加（または TS に $localize）
# 2. メッセージ抽出
make ui-i18n-extract

# 3. 日本語翻訳ファイルを更新
#    src/locale/messages.xlf の新しい <trans-unit> を src/locale/messages.ja.xlf にコピーし
#    <target> 要素に日本語翻訳を追加

# 4. ビルド確認
make ui-build
```

## ロードマップ

詳細は [docs/PLAN.md](docs/PLAN.md) を参照してください。

- [x] Phase 1: データパイプライン（OSV 取り込み）
- [x] Phase 2: CLI（ingest + search）
- [x] Phase 3: CI/CD（GitHub Actions）
- [x] Phase 4: API サーバー（REST）
- [x] Phase 5: Web UI（Angular）
- [x] Phase 6: 追加データソース（KEV, EPSS, MITRE CVE）
