# Mayu

[![CI](https://github.com/kato83/mayu/actions/workflows/ci.yml/badge.svg)](https://github.com/kato83/mayu/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/github/go-mod/go-version/kato83/mayu)](https://github.com/kato83/mayu/blob/main/go.mod)


[English](README.md)

複数の脆弱性情報ソース（OSV、NVDなど）を集約し、CLI・API・Web UI から横断検索・トリアージを可能にする統合脆弱性インテリジェンスツールです。

## 概要

Mayu は [OSV](https://osv.dev/) エコシステムから脆弱性データをローカルの PostgreSQL に取り込み、高速な横断検索とトリアージを実現します。

**現在の機能:**
- OSV GCS バケットからの脆弱性データのフルインポート・差分インポート
- GitHub Security Advisory の直接取り込み — OSV に未登録でも、API レスポンスを `wget` して mayu に食わせるだけで即座にインポート可能
- SBOM 脆弱性監査 — CycloneDX / SPDX 形式の SBOM を食わせるだけで、ローカルデータに基づく脆弱性レポートを生成
- CLI による脆弱性検索（ID、パッケージ名、エコシステム、エイリアス）
- REST API サーバー（OpenAPI 3.1 対応）
- 全 OSV エコシステム対応（Go, PyPI, npm, Maven, crates.io 等）
- 元の OSV JSON を完全保持（データの可逆性を担保）

![](./docs/readme_pic01.jpg)

## 名前の由来

**Mayu** は、蚕が身を守るために紡ぐ「繭（まゆ）」に由来します。脆弱性インテリジェンスによって、あなたの環境を優しく、かつ強固に包み込んで守る、というツールのコンセプトを表しています。

## なぜ Mayu？

優れた脆弱性インテリジェンスツールは数多くありますが、Mayu は以下の特徴を単一のセルフホスト型ツールに統合している点でユニークなポジションにあります：

| | クラウド依存型 CVE CLI | CVE 監視プラットフォーム | **Mayu** |
|---|---|---|---|
| データの所有 | クラウド API 依存 | セルフホストまたは SaaS | **完全ローカル（PostgreSQL）** |
| オフライン / エアギャップ | ❌ | 一部対応（セルフホスト時） | **✅ 初回同期後は完全オフライン** |
| REST API 内蔵 | ❌（クライアントのみ） | ✅ | **✅** |
| Web UI 内蔵 | ❌ | ✅ | **✅** |
| CLI | ✅ | 限定的 | **✅** |
| OSV エコシステム対応 | ❌（CVE/CPE のみ） | ❌（CVE/CPE のみ） | **✅ 46エコシステム（パッケージレベル）** |
| パッケージ名検索 | ❌ | ❌ | **✅** |
| EPSS / KEV / LEV | EPSS + KEV | EPSS + KEV | **EPSS + KEV + LEV** |
| カスタムデータ取り込み | ❌ | ❌ | **✅（ローカル JSON ファイル）** |
| 生データの保持 | ❌ | 一部 | **✅ 完全な可逆性** |
| アカウント / API キー | 必要 | 必要（SaaS） | **❌ 不要** |

**要約すると：**

- クラウド依存型 CLI とは異なり、mayu は**全データをローカルに所有**し、REST API と Web UI を内蔵しています。外部サービスへの依存や API キーは一切不要です。
- ベンダー/製品（CPE）マッチングとアラートに特化した CVE 監視プラットフォームとは異なり、mayu は**全 OSV エコシステム（Go, npm, PyPI, Maven, crates.io 等）でのパッケージレベル検索**をサポートし、悪用推定確率の **LEV スコア**を計算します。
- Mayu は**脆弱性インテリジェンスバックエンド**として設計されています — 個人の検索ツールとしても、組織全体の脆弱性データ API としても機能する単一バイナリです。

## インストール

### ビルド済みバイナリ（推奨）

[GitHub Releases](https://github.com/kato83/mayu/releases) から最新リリースをダウンロードしてください。
リリースバイナリには Web UI が組み込まれています — `mayu serve` を実行するだけで `http://localhost:8080/` から UI にアクセスできます。

| プラットフォーム | アーキテクチャ | ファイル名 |
|----------------|--------------|-----------|
| Linux | x86_64 | `mayu_*_linux_amd64.tar.gz` |
| Linux | ARM64 | `mayu_*_linux_arm64.tar.gz` |
| macOS | x86_64 (Intel) | `mayu_*_darwin_amd64.tar.gz` |
| macOS | ARM64 (Apple Silicon) | `mayu_*_darwin_arm64.tar.gz` |
| Windows | x86_64 | `mayu_*_windows_amd64.zip` |
| Windows | ARM64 | `mayu_*_windows_arm64.zip` |

```bash
# 例: Linux x86_64
curl -LO https://github.com/kato83/mayu/releases/latest/download/mayu_0.0.1-alpha.1_linux_amd64.tar.gz
tar xzf mayu_0.0.1-alpha.1_linux_amd64.tar.gz
sudo mv mayu /usr/local/bin/

# インストールの確認
mayu version
```

### ソースからビルド

<details>
<summary>ソースからビルド</summary>

必要なもの:
- [Go 1.26+](https://go.dev/)
- [Node.js 24+](https://nodejs.org/)（Web UI ビルド用）
- [pnpm 11+](https://pnpm.io/)（Web UI の依存管理用）

```bash
git clone https://github.com/kato83/mayu.git
cd mayu

# Web UI 埋め込みビルド（推奨 — リリースバイナリと同等）
make build-embed

# 実行 — UI は / で自動配信
./bin/mayu serve
```

> [!TIP]
> Web UI なしで CLI/API のみ使用する場合は、Go だけでビルドできます：
> ```bash
> go build -o bin/mayu ./cmd/mayu
> ```
> この場合、Web UI を配信するには `--ui-dir` で別途ビルドしたディレクトリを指定してください。

</details>

## クイックスタート

### 前提条件

- PostgreSQL 17+

> [!TIP]
> 手軽に試したい場合は、Docker で PostgreSQL を起動できます：
> ```bash
> docker run -d --name mayu-pg -e POSTGRES_USER=mayu -e POSTGRES_PASSWORD=mayu -e POSTGRES_DB=mayu -p 5432:5432 postgres:17
> ```

### セットアップ

```bash
# データベースマイグレーション実行
mayu migrate
```

### 脆弱性データの取り込み

```bash
# Go エコシステムの脆弱性を全件インポート
mayu ingest --ecosystem Go
# 差分更新（前回同期以降の新規・更新分のみ）
mayu ingest --ecosystem Go --update
# 全エコシステムをインポート
mayu ingest --all
# 並列度を指定して全エコシステムをインポート
mayu ingest --all --concurrency 5 --store-workers 8
# トップレベル all.zip (~1.3GB) から一括インポート（全エコシステムを1ファイルで）
mayu ingest --all --bulk
# NVD JSON Feed 2.0 から直接 CVE データをインポート
mayu ingest --source nvd --native
# 特定の年度のみインポート
mayu ingest --source nvd --native --year 2024
# NVD modified フィードから差分更新
mayu ingest --source nvd --native --update
# MITRE CVE データを cvelistV5 GitHub Releases からインポート
mayu ingest --source mitre
# 毎時リリースから差分更新
mayu ingest --source mitre --update
# EPSS スコア（悪用予測スコアリングシステム）をインポート
mayu ingest --source epss
# EPSS スコアを更新（日次リフレッシュ、未更新時のみ）
mayu ingest --source epss --update
# EPSS 日次ヒストリカルデータをバックフィル（LEV 計算に必要）
mayu ingest --source epss --backfill
# 特定の期間を指定してバックフィル
mayu ingest --source epss --backfill --from 2024-01-01 --to 2025-07-19
# CISA KEV カタログ（既知の悪用された脆弱性）をインポート
mayu ingest --source kev
# KEV カタログを更新（未更新時のみ）
mayu ingest --source kev --update
# ローカルの OSV JSON ファイルを直接取り込み（手動構築した GHSA 等）
mayu ingest --file GHSA-xxxx-xxxx-xxxx.json GHSA-yyyy-yyyy-yyyy.json
```

### 脆弱性の検索

```bash
# 脆弱性IDで検索
mayu search --id GO-2024-2687
# パッケージ名で検索
mayu search --package golang.org/x/crypto
# エコシステムでフィルタ
mayu search --ecosystem Go --limit 10
# CVE エイリアスで検索
mayu search --id CVE-2024-24790
# Package URL (purl) で検索
mayu search --purl pkg:npm/%40angular/core
# 位置引数（--id の省略形）
mayu search CVE-2024-24790
# 深刻度でフィルタ
mayu search --severity critical --ecosystem Go
# 日付でフィルタ（指定日以降の更新分）
mayu search --since 2024-01-01 --ecosystem npm
# 影響バージョンでフィルタ
mayu search --package golang.org/x/crypto --version 0.17.0
# ページネーション
mayu search --ecosystem Go --limit 10 --offset 20
# カーソルベースページネーション（前回出力のNextTokenを使用）
mayu search --ecosystem Go --limit 10 --starting-token <token>
# 件数のみ表示
mayu search --ecosystem Go --count
# 詳細表示（全フィールド）
mayu search --id GO-2024-2687 --detail
# JSON 出力（スクリプト連携用）
mayu search --id GO-2024-2687 --format json
# CSV エクスポート
mayu search --ecosystem Go --format csv > vulns.csv
```

### SBOM 監査

```bash
# CycloneDX SBOM の脆弱性監査
mayu audit --sbom ./sbom.cdx.json
# SPDX SBOM の監査
mayu audit --sbom ./sbom.spdx.json
# 開発依存を含めて監査
mayu audit --sbom ./sbom.cdx.json --include-dev
# バージョンチェックをスキップ（パッケージ名マッチのみ）
mayu audit --sbom ./sbom.cdx.json --no-version-check
# JSON 出力
mayu audit --sbom ./sbom.cdx.json --format json
# CSV 出力
mayu audit --sbom ./sbom.cdx.json --format csv
```

### サーバーの起動

```bash
# サーバーを起動（API + Web UI、デフォルトポート: 8080）
mayu serve
# カスタムポートで起動
mayu serve --addr :3000
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
| `--backfill` | ヒストリカルデータをバックフィル（`--source epss` と併用） | `false` |
| `--from` | バックフィルの開始日（YYYY-MM-DD） | `2023-03-07`（EPSS v3） |
| `--to` | バックフィルの終了日（YYYY-MM-DD） | 本日 |
| `--source` | ソースからインポート（nvd, debian, mitre, epss, kev） | — |
| `--native` | ネイティブデータソースフィードを使用（`--source nvd` と併用） | `false` |
| `--year` | 特定の年度のNVDフィードのみインポート（`--source nvd --native` と併用） | — |
| `--file` | ローカルの OSV JSON ファイルを取り込み（パスを位置引数で指定） | `false` |
| `--concurrency` | 並列インポートするエコシステム数（`--all` と併用） | `3` |
| `--store-workers` | エコシステムごとの並列DB書き込みワーカー数 | CPUコア数 - 1 |
| `--batch-size` | バッチインサートの件数 | `100` |

> [!TIP]
> 利用可能なエコシステムの一覧は [`ecosystems.txt`](https://www.googleapis.com/download/storage/v1/b/osv-vulnerabilities/o/ecosystems.txt) で公開されています。

### `mayu audit`

SBOM の脆弱性監査を実行します。

| フラグ | 説明 | デフォルト |
|------|------|---------|
| `--sbom` | SBOM ファイルパス（CycloneDX 1.7 または SPDX 2.3 JSON） | （必須） |
| `--format` | 出力フォーマット: `table`, `json`, `csv` | `table` |
| `--include-dev` | 開発依存もaudit対象に含める | `false` |
| `--no-version-check` | バージョンチェックをスキップし、パッケージ名マッチのみで報告 | `false` |

**終了コード:**

| コード | 意味 |
|------|------|
| 0 | 脆弱性なし |
| 1 | 1件以上の脆弱性あり |
| 2 | エラー（不正な入力、DB接続失敗など） |

**対応SBOMフォーマット:**
- CycloneDX 1.7 (JSON) — `scope` および `cdx:npm:package:development` プロパティで開発依存を検出
- SPDX 2.3 (JSON) — 全パッケージを本番依存として扱う（SPDXにはdev/prod区別なし）

### `mayu search`

ローカルデータベースから脆弱性を検索します。

| フラグ | 説明 | デフォルト |
|--------|------|-----------|
| `--id` | 脆弱性IDまたはエイリアスで検索（例: CVE-2024-1234, GO-2024-2687, GHSA-xxxx） | — |
| `--package` | パッケージ名で検索 | — |
| `--ecosystem` | エコシステムでフィルタ | — |
| `--purl` | Package URL で検索（例: `pkg:npm/%40angular/core`） | — |
| `--severity` | CVSS 深刻度でフィルタ（critical, high, medium, low, none） | — |
| `--since` | 更新日でフィルタ（YYYY-MM-DD または RFC3339） | — |
| `--version` | 影響バージョンでフィルタ | — |
| `--format` | 出力形式: `table`, `json`, `csv` | `table` |
| `--limit` | 最大結果数 | `20` |
| `--offset` | ページネーション用オフセット（非推奨: `--starting-token` を使用） | `0` |
| `--starting-token` | ページネーション用カーソルトークン（前回出力の `NextToken` を指定） | — |
| `--count` | 結果件数のみ表示 | `false` |
| `--detail` | 各結果の詳細情報を表示 | `false` |

### `mayu serve`

サーバーを起動します（API + Web UI）。

| フラグ | 説明 | デフォルト |
|--------|------|-----------|
| `--addr` | リッスンするアドレス（host:port） | `:8080` |
| `--ui-dir` | SPA 静的ファイルディレクトリのパス（Web UI ホスティング用） | — |

**エンドポイント:**

API の全仕様は [`internal/server/openapi.yaml`](internal/server/openapi.yaml) を参照するか、サーバー起動中に `http://localhost:8080/openapi.yaml` にアクセスしてください。

### `mayu migrate`

データベースマイグレーションを実行します（バイナリに埋め込み済み）。

| フラグ | 説明 | デフォルト |
|--------|------|-----------|
| `--steps` | 適用するマイグレーション数（0 = 全て、負数でロールバック） | `0` |

**サブコマンド:**

| サブコマンド | 説明 |
|------------|------|
| `up` | 未適用のマイグレーションを全て適用（デフォルト） |
| `down` | 1つロールバック（`--steps N` で複数） |
| `status` | 現在のマイグレーションバージョンを表示 |

**使用例:**

```bash
mayu migrate              # 未適用のマイグレーションを全て適用
mayu migrate up
mayu migrate down
mayu migrate down --steps 3
mayu migrate status
```

### `mayu version`

バージョン情報を表示します。

## 設定

### 設定ファイル

Mayu は YAML 形式の設定ファイルに対応しています。デフォルトのパスは以下です：

```
$HOME/.config/mayu/config.yaml
```

`--config` グローバルオプションで任意のパスを指定できます：

```bash
mayu --config /path/to/config.yaml search --id CVE-2024-1234
```

デフォルトの設定ファイルが存在しない場合、mayu はエラーを出さず環境変数・デフォルト値にフォールバックします。`--config` で明示的に指定されたファイルが存在しない場合はエラーになります。

**`config.yaml` の例：**

```yaml
database_url: postgres://mayu:mayu@localhost:5432/mayu?sslmode=disable
```

**優先順位**（高い順）：

1. 環境変数 (`DATABASE_URL`)
2. 設定ファイル (`config.yaml` — `--config` でパスを指定)
3. デフォルト値

### 環境変数

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
| [NVD CVE (変換済み)](https://storage.googleapis.com/cve-osv-conversion/index.html?prefix=osv-output/) | ✅ 対応済み | `mayu ingest --source nvd` |
| [NVD CVE (ネイティブ)](https://nvd.nist.gov/vuln/data-feeds) | ✅ 対応済み | `mayu ingest --source nvd --native` |
| [Debian Security Advisories](https://storage.googleapis.com/debian-osv/index.html) | ✅ 対応済み | `mayu ingest --source debian` |
| [MITRE CVE (cvelistV5)](https://github.com/CVEProject/cvelistV5) | ✅ 対応済み | `mayu ingest --source mitre` |

> [!NOTE]
> 変換ソース（NVD、Debian）は50,000件以上のエントリを含み、一括アーカイブが提供されていないため個別にダウンロードします。取り込みにはかなりの時間がかかります。

| ソース | ステータス | 取得方法 |
|--------|-----------|---------|
| KEV | ✅ 対応済み | `mayu ingest --source kev` |
| EPSS | ✅ 対応済み | `mayu ingest --source epss` |
| LEV | ✅ 対応済み | EPSS + KEV から自動計算（後述） |

## LEV（Likely Exploited Vulnerabilities：悪用推定確率）

Mayu は [LEV](https://doi.org/10.6028/NIST.CSWP.41) スコアを計算します。LEV は NIST（CSWP 41）が提案する確率的メトリクスで、CVE が**過去に実際に悪用された確率**を推定します。

### 仕組み

LEV は mayu に既に取り込まれている2つのデータソースを組み合わせます：

| データソース | 役割 | 時間的視点 |
|-------------|------|-----------|
| **EPSS** | 日次の悪用確率（P30） | 未来（今後30日間） |
| **CISA KEV** | 確認済みの悪用 | 過去（既知の悪用） |
| **LEV** | 過去の悪用確率 | 過去（推定） |

**アルゴリズム**（NIST CSWP 41 の厳密な手法）：

```
P1  = 1 - (1 - P30)^(1/30)       # EPSS 30日確率 → 日次確率に変換
LEV = 1 - ∏(1 - P1_i)             # 全履歴日数分を複合計算
```

CVE が CISA KEV カタログに含まれている場合、LEV は自動的に **1.0**（悪用確認済み）に設定されます。

> [!NOTE]
> この実装は厳密な P30→P1 変換を使用しています。論文中の `P30/30` 近似は高い EPSS スコアに対して不正確なため、採用していません。

### LEV のセットアップ

LEV の計算には EPSS の日次ヒストリカルデータが必要です。バックフィルコマンドで時系列データを蓄積してください：

```bash
# 1. CISA KEV カタログをインポート
mayu ingest --source kev
# 2. EPSS v3 リリース日（2023-03-07）から今日までの日次スコアをバックフィル
mayu ingest --source epss --backfill
# カスタム期間を指定する場合
mayu ingest --source epss --backfill --from 2024-01-01 --to 2025-07-19
# 3. 初回バックフィル後は、日次更新で EPSS を最新に保つ
mayu ingest --source epss --update
```

> [!TIP]
> バックフィルは1日あたり約 5-7 MB（約20万CVEスコア）をダウンロードします。2023-03-07 からのフルバックフィルは約860日分です。既にインポート済みの日付は再実行時に自動スキップされます。

### LEV スコアの表示

LEV は `--detail` 表示および API の `?detail=true` レスポンスで自動的に表示されます：

```bash
mayu search --id CVE-2023-38831 --detail
```

出力には EPSS、KEV、LEV セクションが含まれます：

```
EPSS:
  Score:      0.94218 (94.2%)
  Percentile: 0.99923 (99.9%)
  Score Date: 2026-07-19
KEV (CISA Known Exploited Vulnerabilities):
  Vendor/Project: WinRAR
  Product:        WinRAR
  Vuln Name:      RARLAB WinRAR Code Execution Vulnerability
  Date Added:     2023-08-24
  Due Date:       2023-09-14
  Ransomware Use: Known
LEV (Likely Exploited Vulnerabilities - NIST CSWP 41):
  Score:       1.00000 (100.0%)
  In KEV:      true
  EPSS Days:   730
  First EPSS:  2023-03-07
  Last EPSS:   2025-07-19
```

API での例：

```bash
curl "http://localhost:8080/api/v1/vulnerabilities/CVE-2023-38831?detail=true" | jq '.lev'
```

```json
{
  "lev": 1.0,
  "in_kev": true,
  "epss_score_count": 730,
  "first_epss_date": "2023-03-07",
  "last_epss_date": "2025-07-19",
  "computed_at": "2026-07-19T12:00:00Z"
}
```

### LEV スコアの解釈

| LEV 範囲 | 解釈 |
|----------|------|
| 0.95 – 1.0 | ほぼ確実に悪用済み（またはKEVで確認済み） |
| 0.70 – 0.95 | 悪用された可能性が非常に高い |
| 0.30 – 0.70 | 悪用された可能性がある |
| 0.05 – 0.30 | 過去に悪用された確率は低い |
| 0.00 – 0.05 | 悪用された可能性は低い |

> [!IMPORTANT]
> LEV は確率的な推定値であり、確定的な事実ではありません。脆弱性の優先順位付けには KEV、EPSS、CVSS など他のシグナルと組み合わせて使用してください。

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
- [x] Phase 5: Web UI（Angular）
- [x] Phase 6: 追加データソース（EPSS, KEV, LEV）
- [ ] EPSS 推移グラフ・LEV 可視化
- [ ] トリアージ機能の拡張
- [ ] ダッシュボード・レポート機能
- [ ] 通知機能（Webhook、メール）
- [ ] [endoflife.date](https://endoflife.date/) 連携
- [ ] SBOM 機能拡張（依存グラフ、継続的モニタリング）
