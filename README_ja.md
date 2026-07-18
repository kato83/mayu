# Mayu

[English](README.md)

複数の脆弱性情報ソース（OSV、NVDなど）を集約し、CLI・API・Web UI から横断検索・トリアージを可能にする統合脆弱性インテリジェンスツールです。

## 概要

Mayu は [OSV](https://osv.dev/) エコシステムから脆弱性データをローカルの PostgreSQL に取り込み、高速な横断検索とトリアージを実現します。

**現在の機能:**
- OSV GCS バケットからの脆弱性データのフルインポート・差分インポート
- CLI による脆弱性検索（ID、パッケージ名、エコシステム、エイリアス）
- 全 OSV エコシステム対応（Go, PyPI, npm, Maven, crates.io 等）
- 元の OSV JSON を完全保持（データの可逆性を担保）

## 名前の由来

**Mayu** は、蚕が身を守るために紡ぐ「繭（まゆ）」に由来します。脆弱性インテリジェンスによって、あなたの環境を優しく、かつ強固に包み込んで守る、というツールのコンセプトを表しています。小文字で収まりの良いアルファベット4文字の名前であり、モダンな CLI・API・Web UI のツールチェーン（`mayu`, `mayu-server` など）にも馴染みます。

## クイックスタート

### 前提条件

- [Go 1.26+](https://go.dev/)（[asdf](https://asdf-vm.com/) で管理）
- [Docker](https://www.docker.com/) & Docker Compose
- [golang-migrate](https://github.com/golang-migrate/migrate) CLI

### セットアップ

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
```

### 脆弱性データの取り込み

```bash
# Go エコシステムの脆弱性を全件インポート
./bin/mayu ingest --ecosystem Go

# 差分更新（前回同期以降の新規・更新分のみ）
./bin/mayu ingest --ecosystem Go --update

# 全エコシステムをインポート（各エコシステムの all.zip を個別にダウンロード）
./bin/mayu ingest --all

# トップレベル all.zip (~1.3GB) から一括インポート（全エコシステムを1ファイルで）
./bin/mayu ingest --all --bulk
```

### 脆弱性の検索

```bash
# 脆弱性IDで検索
./bin/mayu search --id GO-2024-2687

# パッケージ名で検索
./bin/mayu search --package golang.org/x/crypto

# エコシステムでフィルタ
./bin/mayu search --ecosystem Go --limit 10

# CVE エイリアスで検索
./bin/mayu search --alias CVE-2024-24790

# Package URL (purl) で検索
./bin/mayu search --purl pkg:npm/%40angular/core

# 位置引数（IDかエイリアスを自動判定）
./bin/mayu search CVE-2024-24790

# JSON 出力（スクリプト連携用）
./bin/mayu search --id GO-2024-2687 --format json
```

## CLI リファレンス

### `mayu ingest`

OSV から脆弱性データをローカルデータベースにインポートします。

| フラグ | 説明 | デフォルト |
|--------|------|-----------|
| `--ecosystem` | インポートするエコシステム（例: Go, PyPI, npm） | — |
| `--all` | 全エコシステムをインポート（GCS から動的取得） | `false` |
| `--bulk` | トップレベル all.zip で一括インポート（`--all` と併用） | `false` |
| `--update` | フルインポートの代わりに差分更新を実行 | `false` |
| `--source` | 変換ソースからインポート（nvd, debian） | — |
| `--db-url` | PostgreSQL 接続URL | `$DATABASE_URL` または `localhost` |
| `--batch-size` | バッチインサートの件数 | `100` |

### `mayu search`

ローカルデータベースから脆弱性を検索します。

| フラグ | 説明 | デフォルト |
|--------|------|-----------|
| `--id` | 脆弱性IDで検索 | — |
| `--package` | パッケージ名で検索 | — |
| `--ecosystem` | エコシステムでフィルタ | — |
| `--alias` | エイリアスで検索（例: CVE ID） | — |
| `--purl` | Package URL で検索（例: `pkg:npm/%40angular/core`） | — |
| `--format` | 出力形式: `table`, `json` | `table` |
| `--limit` | 最大結果数 | `20` |
| `--db-url` | PostgreSQL 接続URL | `$DATABASE_URL` または `localhost` |

### `mayu version`

バージョン情報を表示します。

## アーキテクチャ

```mermaid
graph TD
    CLI["CLI (cmd/mayu)"]
    CLI --> Ingest[ingest]
    CLI --> Search[search]

    Ingest --> Fetcher["Fetcher (GCS)"]
    Ingest --> Parser["Parser (OSV)"]
    Ingest --> IngestPipeline["Ingest (Pipeline)"]
    Search --> Store["Store (PG)"]
    IngestPipeline --> Store

    Store --> DB[(PostgreSQL)]
```

## データソース

| ソース | ステータス | 取得方法 |
|--------|-----------|---------|
| [OSV](https://osv.dev/) | ✅ 対応済み | GCS バケット (`gs://osv-vulnerabilities/`) |
| NVD (OSV 経由) | ✅ 対応済み | OSV データに含まれる |
| [NVD CVE (変換済み)](https://storage.googleapis.com/cve-osv-conversion/index.html?prefix=osv-output/) | ✅ 対応済み | `mayu ingest --source nvd` |
| [Debian Security Advisories](https://storage.googleapis.com/debian-osv/index.html) | ✅ 対応済み | `mayu ingest --source debian` |

> **注意:** 変換ソース（NVD、Debian）は50,000件以上のエントリを含み、一括アーカイブが提供されていないため個別にダウンロードします。取り込みにはかなりの時間がかかります。並列ダウンロードの最適化は将来リリースで対応予定です。

| ソース | ステータス | 取得方法 |
|--------|-----------|---------|
| KEV | 🔜 予定 | — |
| EPSS | 🔜 予定 | — |

## 開発

```bash
# ユニットテスト実行
make test

# 統合テスト実行（PostgreSQL が必要）
make docker-up && make migrate-up
make test-integration

# Lint
make lint

# PostgreSQL 停止
make docker-down
```

## 設定

| 環境変数 | 説明 | デフォルト |
|----------|------|-----------|
| `DATABASE_URL` | PostgreSQL 接続文字列 | `postgres://mayu:mayu@localhost:5432/mayu?sslmode=disable` |

> [!WARNING]
> デフォルトの接続文字列は `sslmode=disable` を使用しています。
> これは同梱の Docker PostgreSQL に対するローカル開発でのみ適切です。
> リモートまたは本番データベースに接続する場合は、`sslmode=require`
> （証明書検証まで行う場合は `verify-full`）を設定して **TLS を強制** してください。
> 例: `postgres://user:pass@db.example.com:5432/mayu?sslmode=verify-full`
> Mayu は非ローカルホストへの接続で TLS が強制されていない場合、警告を出力します。

## ライセンス

[MIT](LICENSE)

## ロードマップ

詳細は [docs/PLAN.md](docs/PLAN.md) を参照してください。

- [x] Phase 1: データパイプライン（OSV 取り込み）
- [x] Phase 2: CLI（ingest + search）
- [x] Phase 3: CI/CD（GitHub Actions）
- [ ] Phase 4: API サーバー（REST）
- [ ] Phase 5: Web UI（Angular）
- [ ] Phase 6: 追加データソース（KEV, EPSS, MITRE CVE）
