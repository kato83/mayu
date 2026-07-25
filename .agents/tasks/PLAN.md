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
│  cmd/mayu    │  internal/server │  ui/                  │
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
  - NVD (via OSV conversion) ← OSS関連CVEのみ (~25%)
  - NVD JSON Feed 2.0 / API 2.0 ← 全CVE (future)
  - Debian (via OSV conversion)
  - MITRE CVE (cvelistV5)
  - EPSS (FIRST bulk CSV)
  - KEV (CISA Known Exploited Vulnerabilities)
  - LEV (NIST CSWP 41, computed from EPSS + KEV)
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
- **Supplemental Sources**: KEV, EPSS, LEV は専用テーブルとして管理（実装済み）

## Project Structure

```
mayu/
├── cmd/
│   └── mayu/              # CLI entrypoint (ingest, search, serve)
├── internal/
│   ├── fetcher/           # GCS data download
│   ├── parser/            # OSV JSON parsing
│   ├── store/             # PostgreSQL persistence
│   ├── model/             # OSV schema Go structs
│   ├── server/            # HTTP API server (chi router, REST handlers)
│   ├── purl/              # Package URL parsing
│   ├── cvss/              # CVSS score computation
│   └── ingest/            # Pipeline orchestrator
├── migrations/            # DB migration files
├── testdata/              # Test fixtures (OSV JSON samples)
├── docs/                  # Documentation
│   ├── PLAN.md            # This file
│   └── openapi.yaml       # OpenAPI 3.1 specification
├── compose.yml            # Dev environment (PostgreSQL)
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

- ✅ REST API サーバー実装 (`mayu serve`)
- ✅ OpenAPI 3.1 仕様書 (`docs/openapi.yaml`, `GET /openapi.yaml`)
- ✅ 検索API (`GET /api/v1/vulnerabilities`)
- ✅ 個別取得API (`GET /api/v1/vulnerabilities/{id}`)
- ✅ ヘルスチェック (`GET /healthz`)
- ✅ CORS対応
- 認証・認可 (future)

### Phase 5: Web UI

- ✅ Angular v22 フロントエンド (`ui/`)
- ✅ 脆弱性一覧（フィルタ、ページネーション）
- ✅ 脆弱性詳細ページ（OSV + NVD + MITRE + EPSS + KEV + LEV）
- ✅ ダークモード切り替え
- ✅ 外部リンククッション画面
- ✅ i18n対応（en/ja）
- トリアージワークフロー (future)

### Phase 6: Additional Data Sources (Future)

- ✅ NVD CVE (OSV変換済み、`gs://cve-osv-conversion/osv-output/`) - `mayu ingest --source nvd`
  - ⚠️ OSV変換済みデータはNVD全体の約25%のみ（OSSに関連し、Gitリポジトリ＋バージョン情報が解決可能なCVEに限定）
- ✅ Debian Security Advisories (`gs://debian-osv/debian-cve-osv/`) - `mayu ingest --source debian`

#### Phase 6a: NVD 全件取り込み（JSON Feed 2.0 / API 2.0）

NVDが提供する全CVE（367,000件超）をネイティブスキーマで取り込む。OSV変換データでは
カバーされないクローズドソース製品のCVEも含めて横断検索可能にする。

**データ取得方式:**

| 方式 | 用途 | URL パターン |
|------|------|-------------|
| JSON Feed 2.0 (年別) | 初回フルインポート | `https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz` |
| JSON Feed 2.0 (modified) | 差分更新（2時間ごと更新、過去8日分） | `https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz` |
| JSON Feed 2.0 (recent) | 新規追加の確認 | `https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz` |
| CVE API 2.0 | 個別CVE取得、細かいクエリ | `https://services.nvd.nist.gov/rest/json/cves/2.0` |
| META ファイル | フィード更新判定（sha256比較） | `*.meta` |

**スキーマ:** NVD API 2.0 スキーマ (`cve_api_json_2.0.schema`)。API とフィードで同一形式。

**実装タスク:**
- [x] NVD 2.0 スキーマの Go モデル定義 (`internal/model/nvd.go`)
- [x] NVD JSON Feed fetcher (`internal/fetcher/nvd.go`) — 年別gz一括DL + META差分判定
- [x] NVD JSON パーサー (`internal/parser/nvd.go`)
- [x] NVD 専用テーブル群のマイグレーション (`nvd_entries`, `nvd_configurations`, `nvd_cpe_matches`, `nvd_weaknesses`)
- [x] `vulnerabilities` テーブルへの統合（CVE ID で OSV エントリとマージ）
- [x] CLI: `mayu ingest --source nvd --native` （JSON Feed 2.0 経由のフルインポート）
- [x] 差分更新: `modified` フィード + META ファイルの sha256 比較
- [ ] API 2.0 クライアント（オプション: APIキー対応、レートリミット制御）

**NVD固有のデータ構造（OSVに無いもの）:**
- CPE Match Criteria（ベンダー/プロダクト/バージョンのツリー構造）
- CWE（脆弱性タイプ分類）
- CVSS スコアソース区別（NVD vs CNA）
- CVE Status（Analyzed, Modified, Rejected 等）

#### Phase 6b: NVD 固有の検索機能

- [ ] CPE ベースの検索（ベンダー、プロダクト、バージョン）
- [ ] CWE フィルタ
- [ ] CVSS スコアソース（NVD / CNA）の区別表示
- [ ] CVE ステータスフィルタ

#### Phase 6c: KEV / EPSS / LEV

- ✅ KEV (Known Exploited Vulnerabilities) 対応 — `mayu ingest --source kev`
- ✅ EPSS (Exploit Prediction Scoring System) 対応 — `mayu ingest --source epss`
- ✅ LEV (Likely Exploited Vulnerabilities, NIST CSWP 41) 対応 — computed from EPSS + KEV
- 各ソース専用テーブル追加

#### Phase 6d: GitHub Advisory 直接取り込み強化

OSV に未到達の GitHub Security Advisory を、URLやGHSA IDを指定するだけで直接取り込めるようにする。

**現状（実装済み）:**
- [x] `mayu ingest --file` でローカル OSV JSON ファイルの取り込み
- [x] GitHub REST API 形式の自動検出・OSV 形式への自動変換
- [x] `wget` + `--file` の2ステップでの取り込みフロー

**将来タスク:**
- [ ] `mayu ingest --ghsa GHSA-xxxx-xxxx-xxxx` — GHSA ID を指定して直接 GitHub API から取得・変換・取り込み
- [ ] `mayu ingest --ghsa-url https://github.com/{owner}/{repo}/security/advisories/GHSA-xxxx` — URL 指定での取り込み
- [ ] GitHub Advisory Database リポジトリ (`github/advisory-database`) からの一括同期
- [ ] GitHub GraphQL API 対応（より詳細なデータ取得）
- [ ] `--file` でのディレクトリ指定・glob パターン対応

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
- DB接続設定: 環境変数 or `--config` で設定ファイル指定
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
