# Mayu

[English](README.md)

複数の脆弱性情報ソース（OSV、NVDなど）を集約し、CLI・API・Web UI から横断検索・トリアージを可能にする統合脆弱性インテリジェンスツールです。

## 概要

Mayu は [OSV](https://osv.dev/) エコシステムから脆弱性データをローカルの PostgreSQL に取り込み、高速な横断検索とトリアージを実現します。

**現在の機能:**
- OSV GCS バケットからの脆弱性データのフルインポート・差分インポート
- CLI による脆弱性検索（ID、パッケージ名、エコシステム、エイリアス）
- REST API サーバー（OpenAPI 3.1 対応）
- 全 OSV エコシステム対応（Go, PyPI, npm, Maven, crates.io 等）
- 元の OSV JSON を完全保持（データの可逆性を担保）

## 名前の由来

**Mayu** は、蚕が身を守るために紡ぐ「繭（まゆ）」に由来します。脆弱性インテリジェンスによって、あなたの環境を優しく、かつ強固に包み込んで守る、というツールのコンセプトを表しています。

## クイックスタート

### 前提条件

- [Go 1.26+](https://go.dev/)
- PostgreSQL 17+

### ソースからビルド

```bash
git clone https://github.com/kato83/mayu.git
cd mayu
go build -o bin/mayu ./cmd/mayu
```

### 脆弱性データの取り込み

```bash
# Go エコシステムの脆弱性を全件インポート
./bin/mayu ingest --ecosystem Go

# 差分更新（前回同期以降の新規・更新分のみ）
./bin/mayu ingest --ecosystem Go --update

# 全エコシステムをインポート
./bin/mayu ingest --all

# 並列度を指定して全エコシステムをインポート
./bin/mayu ingest --all --concurrency 5 --store-workers 8

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

# 深刻度でフィルタ
./bin/mayu search --severity critical --ecosystem Go

# 日付でフィルタ（指定日以降の更新分）
./bin/mayu search --since 2024-01-01 --ecosystem npm

# 影響バージョンでフィルタ
./bin/mayu search --package golang.org/x/crypto --version 0.17.0

# ページネーション
./bin/mayu search --ecosystem Go --limit 10 --offset 20

# 件数のみ表示
./bin/mayu search --ecosystem Go --count

# 詳細表示（全フィールド）
./bin/mayu search --id GO-2024-2687 --detail

# JSON 出力（スクリプト連携用）
./bin/mayu search --id GO-2024-2687 --format json

# CSV エクスポート
./bin/mayu search --ecosystem Go --format csv > vulns.csv
```

### API サーバーの起動

```bash
# API サーバーを起動（デフォルトポート: 8080）
./bin/mayu serve

# カスタムポートで起動
./bin/mayu serve --addr :3000

# OpenAPI 仕様書: http://localhost:8080/openapi.yaml
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
| `--concurrency` | 並列インポートするエコシステム数（`--all` と併用） | `3` |
| `--store-workers` | エコシステムごとの並列DB書き込みワーカー数 | CPUコア数 - 1 |
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
| `--severity` | CVSS 深刻度でフィルタ（critical, high, medium, low, none） | — |
| `--since` | 更新日でフィルタ（YYYY-MM-DD または RFC3339） | — |
| `--version` | 影響バージョンでフィルタ | — |
| `--format` | 出力形式: `table`, `json`, `csv` | `table` |
| `--limit` | 最大結果数 | `20` |
| `--offset` | ページネーション用オフセット | `0` |
| `--count` | 結果件数のみ表示 | `false` |
| `--detail` | 各結果の詳細情報を表示 | `false` |
| `--db-url` | PostgreSQL 接続URL | `$DATABASE_URL` または `localhost` |

### `mayu serve`

API サーバーを起動します。

| フラグ | 説明 | デフォルト |
|--------|------|-----------|
| `--addr` | リッスンするアドレス（host:port） | `:8080` |
| `--db-url` | PostgreSQL 接続URL | `$DATABASE_URL` または `localhost` |

**エンドポイント:**

| メソッド | パス | 説明 |
|----------|------|------|
| GET | `/api/v1/vulnerabilities` | 脆弱性検索（CLI の search と同じパラメータ） |
| GET | `/api/v1/vulnerabilities/{id}` | OSV ID で単一の脆弱性を取得 |
| GET | `/healthz` | ヘルスチェック |
| GET | `/openapi.yaml` | OpenAPI 3.1 仕様書 |

**例:**

```bash
curl "http://localhost:8080/api/v1/vulnerabilities?ecosystem=Go&limit=5"
curl "http://localhost:8080/api/v1/vulnerabilities/GO-2024-2687"
curl "http://localhost:8080/api/v1/vulnerabilities?package=golang.org/x/crypto"
curl "http://localhost:8080/api/v1/vulnerabilities?severity=critical"
curl "http://localhost:8080/api/v1/vulnerabilities?purl=pkg:golang/golang.org/x/crypto"
```

### `mayu version`

バージョン情報を表示します。

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

## データソース

| ソース | ステータス | 取得方法 |
|--------|-----------|---------|
| [OSV](https://osv.dev/) | ✅ 対応済み | GCS バケット (`gs://osv-vulnerabilities/`) |
| NVD (OSV 経由) | ✅ 対応済み | OSV データに含まれる |
| [NVD CVE (変換済み)](https://storage.googleapis.com/cve-osv-conversion/index.html?prefix=osv-output/) | ✅ 対応済み | `mayu ingest --source nvd` |
| [Debian Security Advisories](https://storage.googleapis.com/debian-osv/index.html) | ✅ 対応済み | `mayu ingest --source debian` |

> **注意:** 変換ソース（NVD、Debian）は50,000件以上のエントリを含み、一括アーカイブが提供されていないため個別にダウンロードします。取り込みにはかなりの時間がかかります。

| ソース | ステータス | 取得方法 |
|--------|-----------|---------|
| KEV | 🔜 予定 | — |
| EPSS | 🔜 予定 | — |

## コントリビュート

開発環境のセットアップ、コーディング規約、変更の提出方法については [CONTRIBUTING_ja.md](CONTRIBUTING_ja.md) を参照してください。

## ライセンス

[MIT](LICENSE)

## ロードマップ

詳細は [docs/PLAN.md](docs/PLAN.md) を参照してください。

- [x] Phase 1: データパイプライン（OSV 取り込み）
- [x] Phase 2: CLI（ingest + search）
- [x] Phase 3: CI/CD（GitHub Actions）
- [x] Phase 4: API サーバー（REST）
- [ ] Phase 5: Web UI（Angular）
- [ ] Phase 6: 追加データソース（KEV, EPSS, MITRE CVE）
