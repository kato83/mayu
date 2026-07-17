# Mayu - Implementation Plan

A unified vulnerability intelligence tool that aggregates multiple sources (OSV, NVD, etc.) for cross-platform lookup via CLI, API, and Web UI.

## Overview

世の中に公開されている脆弱性情報を集約し、横断検索・トリアージを可能にする統合脆弱性インテリジェンスツール。

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend (CLI, API) | Go 1.26.x |
| Frontend (Web UI) | Angular (後回し) |
| Database | PostgreSQL 17 |
| Migration | golang-migrate/migrate |
| DB Driver | database/sql + pgx (stdlib) |
| Container | Docker Compose (dev) |
| Version Manager | asdf |
| CI | GitHub Actions |

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Interfaces                          │
├──────────────┬──────────────────┬───────────────────────┤
│  CLI         │  API Server      │  Web UI (Angular)     │
│  cmd/mayu    │  cmd/mayu-server │  (future)             │
└──────┬───────┴────────┬─────────┴───────────────────────┘
       │                │
┌──────┴────────────────┴─────────────────────────────────┐
│                    Core (internal/)                     │
├─────────┬──────────┬─────────┬──────────┬───────────────┤
│ Fetcher │  Parser  │  Store  │  Query   │  Ingest       │
│ (GCS)   │  (OSV)   │  (PG)   │ (Search) │ (Pipeline)    │
└─────────┴──────────┴────┬────┴──────────┴───────────────┘
                          │
                    ┌─────┴───────┐
                    │ PostgreSQL  │
                    └─────────────┘

Data Sources:
  - OSV (osv.dev) ← Primary
  - NVD (via OSV conversion)
  - KEV (future)
  - MITRE CVE (future)
  - EPSS (future)
```

## Data Strategy

- **Primary Source**: OSV GCS Bucket (`gs://osv-vulnerabilities/`)
- **Converted Sources**: NVD (`gs://cve-osv-conversion/osv-output/`), Debian (`gs://debian-osv/debian-cve-osv/`)
- **Schema**: OSV Schema v1.8.0 をそのまま正規化スキーマとして採用
- **Reversibility**: 生JSON全体を `raw_json` (JSONB) として保持し、可逆性を担保
- **Ingestion**: バッチ型（GCSからダンプ取り込み）
- **Delta Sync**: `modified_id.csv` で差分取得（逆時系列ソート済み）
- **Converted Source Ingestion**: GCS XML APIでバケット内ファイル一覧を取得し、個別JSONをダウンロード
- **Ecosystem**: まずGoから、最終的には全エコシステム対応
- **Future Sources**: KEV, EPSS は専用テーブルとして追加

## Project Structure

```
mayu/
├── cmd/
│   ├── mayu/              # CLI entrypoint
│   └── mayu-server/       # API server entrypoint (future)
├── internal/
│   ├── fetcher/           # GCS data download
│   ├── parser/            # OSV JSON parsing
│   ├── store/             # PostgreSQL persistence
│   ├── model/             # OSV schema Go structs
│   ├── query/             # Search logic
│   └── ingest/            # Pipeline orchestrator
├── migrations/            # DB migration files
├── testdata/              # Test fixtures (OSV JSON samples)
├── docs/                  # Documentation
│   └── PLAN.md            # This file
├── docker-compose.yml     # Dev environment (PostgreSQL)
├── .tool-versions         # asdf (Go 1.26.5)
├── .kiro/                 # Kiro configuration
│   └── steering/          # Kiro steering docs
├── .github/
│   └── workflows/         # CI (GitHub Actions)
├── .gitignore
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

## Roadmap

### Phase 1: Data Pipeline (Tasks 1-7)

目的: OSVデータをGCSから取り込み、PostgreSQLに正規化して格納するパイプラインを構築する。

| Task | Description | Dependencies |
|------|-------------|--------------|
| 1 | プロジェクト初期化と開発環境セットアップ | - |
| 2 | OSVスキーマのGoモデル定義 | Task 1 |
| 3 | DBスキーマ設計とマイグレーション | Task 1 |
| 4 | データストア層の実装（CRUD） | Task 2, 3 |
| 5 | GCSからのデータ取得（Fetcher） | Task 1 |
| 6 | OSV JSONパーサーとデータ正規化 | Task 2 |
| 7 | データ取り込みパイプラインの統合 | Task 4, 5, 6 |

### Phase 2: CLI (Tasks 8-9)

目的: CLIからデータ取り込みと脆弱性検索ができるようにする。

| Task | Description | Dependencies |
|------|-------------|--------------|
| 8 | CLIコマンド実装 - ingestコマンド | Task 7 |
| 9 | CLIコマンド実装 - searchコマンド | Task 4 |

### Phase 3: CI/CD (Task 10)

| Task | Description | Dependencies |
|------|-------------|--------------|
| 10 | CI/CD (GitHub Actions) セットアップ | Task 1 |

### Phase 4: API Server (Future)

- REST API サーバー実装
- 認証・認可

### Phase 5: Web UI (Future)

- Angular フロントエンド
- ダッシュボード
- トリアージワークフロー

### Phase 6: Additional Data Sources (Future)

- ✅ NVD CVE (OSV変換済み、`gs://cve-osv-conversion/osv-output/`) - `mayu ingest --source nvd`
- ✅ Debian Security Advisories (`gs://debian-osv/debian-cve-osv/`) - `mayu ingest --source debian`
- KEV (Known Exploited Vulnerabilities) 対応
- EPSS (Exploit Prediction Scoring System) 対応
- 各ソース専用テーブル追加

## Task Details

### Task 1: プロジェクト初期化と開発環境セットアップ

- `.tool-versions` に `golang 1.26.5` を記載
- `go mod init github.com/kato83/mayu` でモジュール初期化
- ディレクトリ構成作成 (`cmd/mayu/`, `internal/`, `migrations/`)
- `docker-compose.yml` でPostgreSQL 17コンテナ定義
- `Makefile` に基本ターゲット (`build`, `test`, `lint`, `migrate-up`, `migrate-down`, `docker-up`, `docker-down`)
- `cmd/mayu/main.go` に最小限のエントリポイント（`mayu version` が動く）
- `.gitignore` 作成
- **Done**: `go build ./...` が通り、`mayu version` でバージョンが表示される

### Task 2: OSVスキーマのGoモデル定義

- `internal/model/osv.go` にOSV Schema v1.8.0の全フィールドをGo構造体で定義
- JSONタグ付与
- `database_specific`, `ecosystem_specific` は `json.RawMessage` で保持（可逆性）
- `testdata/` にサンプルOSV JSONを配置
- `internal/model/osv_test.go` でJSON往復変換テスト（roundtrip）
- **Done**: `go test ./internal/model/...` が全パス

### Task 3: DBスキーマ設計とマイグレーション

- `golang-migrate/migrate` 導入
- テーブル: `vulnerabilities`, `affected_packages`, `affected_ranges`, `references`, `severity`, `sync_state`
- `vulnerabilities.raw_json` (JSONB) で生データ保持
- インデックス: id, ecosystem, package name, purl
- **Done**: `make migrate-up` → `migrate-down` → `migrate-up` がエラーなく通る

### Task 4: データストア層の実装（CRUD）

- `internal/store/store.go` に `Store` インターフェース定義
- `internal/store/postgres.go` に `database/sql` + pgx (stdlib) 実装
- バルクインサート対応
- `internal/store/postgres_test.go` で統合テスト
- **Done**: Insert → GetByID で同一データが返るテストがパス

### Task 5: GCSからのデータ取得（Fetcher）

- HTTPクライアントで `https://storage.googleapis.com/osv-vulnerabilities/{ecosystem}/all.zip` ダウンロード
- zip展開処理
- `modified_id.csv` パースと差分判定ロジック
- 個別JSONファイル取得対応
- テスト: `net/http/httptest` でモック
- **Done**: モックサーバー経由でデータ取得フローがテストでパス

### Task 6: OSV JSONパーサーとデータ正規化

- `internal/parser/parser.go` に変換ロジック
- OSV JSON → model → Store用データへの変換
- 生JSON全体を `raw_json` として保持
- バリデーション・エラーハンドリング
- **Done**: 正常/異常パターンのユニットテストがパス

### Task 7: データ取り込みパイプラインの統合

- `internal/ingest/ingest.go` にパイプラインオーケストレーター
- フルインポート / 差分インポート対応
- `sync_state` テーブル更新
- エラーリカバリ（リトライ/スキップ）
- **Done**: 統合テスト（モックHTTP + 実PostgreSQL）でフルインポート・差分インポートが動作

### Task 8: CLIコマンド実装 - ingestコマンド

- `mayu ingest --ecosystem go` - フルインポート
- `mayu ingest --ecosystem go --update` - 差分インポート
- `mayu ingest --all` - 全エコシステム取り込み
- DB接続設定: 環境変数 or `--db-url` フラグ
- プログレス表示
- **Done**: `mayu ingest --ecosystem go` で脆弱性データがPostgreSQLに取り込まれる

### Task 9: CLIコマンド実装 - searchコマンド

- `mayu search <query>` - キーワード検索
- `mayu search --id CVE-2024-XXXX` - ID指定
- `mayu search --package golang.org/x/crypto` - パッケージ名検索
- `mayu search --ecosystem go --severity HIGH` - フィルタ
- 出力フォーマット: テーブル（デフォルト）、JSON (`--format json`)
- **Done**: 検索結果が正しく表示される

### Task 10: CI/CD (GitHub Actions) セットアップ

- `.github/workflows/ci.yml` 作成
- checkout → Go setup → lint (`golangci-lint`) → build → test（PostgreSQLサービスコンテナ付き）
- テストカバレッジレポート
- **Done**: push時にCIが走り全テストがパス

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Primary data source | OSV | OSVフォーマットでNVDも含む多数のソースが統一的に取得可能 |
| Internal schema | OSV Schema v1.8.0 | 標準的で構造化されたフォーマット。変換コスト不要 |
| Raw data retention | JSONB (`raw_json`) | 可逆性担保。元データの完全な復元が可能 |
| DB access | database/sql + pgx stdlib | Go標準APIで操作。外部ライブラリ最小限 |
| Migration tool | golang-migrate/migrate | 定番。メンテナンス継続中 |
| Project layout | Standard Go Project Layout | Go初学者にとって学習リソースが豊富 |
| First ecosystem | Go | 自分たちが使うエコシステムからスモールスタート |
| Build order | Data Pipeline → CLI → API → Web UI | データ層を先に固めることで各インターフェースが薄くなる |
