# Mayu

[![CI](https://github.com/kato83/mayu/actions/workflows/ci.yml/badge.svg)](https://github.com/kato83/mayu/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/github/go-mod/go-version/kato83/mayu)](https://github.com/kato83/mayu/blob/main/go.mod)

[English](README.md)

複数のソース（OSV、NVDなど）を集約し、CLI、API、Web UIによるクロスプラットフォーム検索を提供する統合脆弱性インテリジェンスツール。

## 概要

Mayuは[OSV](https://osv.dev/)エコシステムの脆弱性データをローカルのPostgreSQLデータベースに取り込み、既知の脆弱性の高速なクロスプラットフォーム検索とトリアージを可能にします。

**現在の機能:**
- GCSバケットからのOSV脆弱性データのフルインポートおよびデルタインポート
- GitHub Security Advisoriesの直接インポート — `--source ghsa --repo` でGitHub APIから直接取得
- SBOM脆弱性監査 — CycloneDXまたはSPDX SBOMを入力し、ローカルデータに対する完全な脆弱性レポートを取得
- ロックファイルスキャン — SBOM生成なしでgo.sum、package-lock.json、yarn.lock、Cargo.lockなどを直接スキャン
- SBOM継続監視 — SBOMのアップロード、検出結果ステータスの追跡、新しい脆弱性データによる自動再スキャン
- ID、パッケージ名、エコシステム、エイリアスによるCLIベースの脆弱性検索（全文検索対応）
- OpenAPI 3.1仕様のREST APIサーバー（78以上のエンドポイント）
- ダッシュボード、EPSSトレンド、LEV可視化、SBOM管理を備えたWeb UI
- すべてのOSVエコシステムをサポート（Go、PyPI、npm、Maven、crates.ioなど）
- VEX（Vulnerability Exploitability eXchange）のインポート/エクスポート
- ポリシーベースのゲーティングとライセンスコンプライアンスチェック
- チーム管理とウォッチリストベースの通知（webhook + メール）
- 完全なデータ可逆性のためにOSV JSON生データを保存

![](./docs/readme_pic01.jpg)

## 命名

**Mayu**は日本語の*繭（まゆ）*に由来します。蚕が自らを守るために紡ぐ保護ケースです。この名前は、脆弱性インテリジェンスを使って環境を穏やかでありながら回復力のある保護層で包むというツールの目的を反映しています。

## なぜMayu？

優れた脆弱性インテリジェンスツールはいくつかあります。Mayuは以下の特性を単一の自己完結型ツールに組み合わせることで、ユニークなポジションを占めています：

| | クラウドベースCVE CLI | CVE監視プラットフォーム | **Mayu** |
|---|---|---|---|
| データ所有権 | クラウドAPI依存 | セルフホストまたはSaaS | **完全ローカル（PostgreSQL）** |
| オフライン / エアギャップ | ❌ | 部分的（セルフホスト） | **✅ 初回同期後** |
| REST API内蔵 | ❌（クライアントのみ） | ✅ | **✅（78以上のエンドポイント）** |
| Web UI内蔵 | ❌ | ✅ | **✅（ダッシュボード、SBOM管理）** |
| CLI | ✅ | 限定的 | **✅（フル機能）** |
| OSVエコシステムカバレッジ | ❌（CVE/CPEのみ） | ❌（CVE/CPEのみ） | **✅ 全OSVエコシステム（パッケージレベル）** |
| パッケージ名検索 | ❌ | ❌ | **✅** |
| EPSS / KEV / LEV | EPSS + KEV | EPSS + KEV | **EPSS + KEV + LEV + Exploit-DB** |
| ロックファイルスキャン | 部分的 | ❌ | **✅（10以上のロックファイル形式）** |
| SBOM監査 + 監視 | ❌ | 部分的 | **✅（CycloneDX、SPDX、継続監視）** |
| VEX / ポリシーゲーティング | ❌ | ❌ | **✅（OpenVEXインポート/エクスポート、ポリシーYAML）** |
| カスタムデータインポート | ❌ | ❌ | **✅（ローカルJSONファイル）** |
| 生データ保存 | ❌ | 部分的 | **✅ 完全な可逆性** |
| アカウント / APIキー必須 | ✅ | ✅（SaaS） | **❌** |

**要約:**

- クラウドベースのCLIツールとは異なり、mayuは**すべてのデータをローカルで所有**し、REST APIとWeb UIを内蔵 — 外部サービスの依存やAPIキーは不要。
- ベンダー/製品（CPE）マッチングとアラートに焦点を当てたCVE監視プラットフォームとは異なり、mayuは**すべてのOSVエコシステム**（Go、npm、PyPI、Maven、crates.ioなど）での**パッケージレベル検索**をサポートし、悪用可能性推定のための**LEVスコア**を計算。
- Mayuは**脆弱性インテリジェンスバックエンド**として設計 — 個人の検索ツールとしても、組織全体の脆弱性データAPIとしても機能する単一バイナリ。

## インストール

### ビルド済みバイナリ（推奨）

最新のリリースを[GitHub Releases](https://github.com/kato83/mayu/releases)からダウンロードしてください。
リリースバイナリにはWeb UIが組み込まれています — `mayu serve` を実行して `http://localhost:8080/` でUIにアクセスできます。

| プラットフォーム | アーキテクチャ | ダウンロード |
|----------|-------------|----------|
| Linux | x86_64 | `mayu_*_linux_amd64.tar.gz` |
| Linux | ARM64 | `mayu_*_linux_arm64.tar.gz` |
| macOS | x86_64 (Intel) | `mayu_*_darwin_amd64.tar.gz` |
| macOS | ARM64 (Apple Silicon) | `mayu_*_darwin_arm64.tar.gz` |
| Windows | x86_64 | `mayu_*_windows_amd64.zip` |
| Windows | ARM64 | `mayu_*_windows_arm64.zip` |

```bash
# 例: Linux x86_64
curl -LO https://github.com/kato83/mayu/releases/latest/download/mayu_0.0.27_linux_amd64.tar.gz
tar xzf mayu_0.0.27_linux_amd64.tar.gz
sudo mv mayu /usr/local/bin/

# インストールの確認
mayu version
```

### ソースからビルド

<details>
<summary>ソースからビルド</summary>

必要なもの:
- [Go 1.26+](https://go.dev/)
- [Node.js 24+](https://nodejs.org/)（Web UIビルド用）
- [pnpm 11+](https://pnpm.io/)（Web UI依存関係管理用）

```bash
git clone https://github.com/kato83/mayu.git
cd mayu

# 組み込みWeb UIでビルド（推奨 — リリースバイナリと同じ）
make build

# 実行 — UIは / で自動的に配信されます
./bin/mayu serve
```

> [!TIP]
> Web UIなしでCLI/APIのみが必要な場合、Goだけでビルドできます:
> ```bash
> make build-no-ui
> ```
> この場合、`--ui-dir` を使用して別途ビルドしたディレクトリからWeb UIを配信します。

</details>

## クイックスタート

### 前提条件

- PostgreSQL 17+

> [!TIP]
> mayuを素早く試したい場合は、DockerでPostgreSQLを実行できます:
> ```bash
> docker run -d --name mayu-pg -e POSTGRES_USER=mayu -e POSTGRES_PASSWORD=mayu -e POSTGRES_DB=mayu -p 5432:5432 postgres:17
> ```

### セットアップ

```bash
# データベースマイグレーションの実行
mayu migrate
```

### 脆弱性データのインポート

```bash
# Goエコシステムのすべての脆弱性をインポート（フル同期）
mayu ingest --ecosystem Go
# デルタ更新でインポート（前回の同期以降の新規/変更のみ）
mayu ingest --ecosystem Go --update
# すべてのOSVエコシステムをインポート
mayu ingest --source osv
# カスタム並列度ですべてのエコシステムをインポート
mayu ingest --source osv --concurrency 5 --store-workers 8
# NVD CVEデータをインポート（GCSからのOSV変換形式）
mayu ingest --source osv --type nvd
# Debianセキュリティアドバイザリをインポート（GCSからのOSV変換形式）
mayu ingest --source osv --type debian
# NVD CVEデータをNVD JSON Feed 2.0から直接インポート
mayu ingest --source nvd
# 特定の年のNVDデータのみインポート
mayu ingest --source nvd --year 2024
# MITRE CVEデータをcvelistV5 GitHub Releasesからインポート
mayu ingest --source mitre
# 毎時MITREリリースからデルタ更新
mayu ingest --source mitre --update
# EPSSスコアをインポート（Exploit Prediction Scoring System）
mayu ingest --source epss
# EPSSスコアを更新（古い場合に日次リフレッシュ）
mayu ingest --source epss --update
# EPSS過去データのバックフィル（LEV計算に必要）
mayu ingest --source epss --backfill
# 特定の日付範囲でEPSSをバックフィル
mayu ingest --source epss --backfill --from 2024-01-01 --to 2025-07-19
# CISA KEVカタログをインポート（Known Exploited Vulnerabilities）
mayu ingest --source kev
# KEVカタログを更新（古い場合にリフレッシュ）
mayu ingest --source kev --update
# Exploit-DBエントリをインポート（公式GitLab CSVから）
mayu ingest --source exploitdb
# Exploit-DBを更新（古い場合にリフレッシュ）
mayu ingest --source exploitdb --update
# endoflife.date製品ライフサイクルデータをインポート（EOL日付、LTSステータス）
mayu ingest --source eol
# endoflife.dateデータを更新（最終同期から24時間以上経過した場合にリフレッシュ）
mayu ingest --source eol --update
# GitHubリポジトリのセキュリティアドバイザリをAPI経由でインポート
mayu ingest --source ghsa --repo WordPress/wordpress-develop
# 認証付き（レート制限またはプライベートリポジトリ用）
GITHUB_TOKEN=ghp_xxx mayu ingest --source ghsa --repo owner/repo
# インジェストジョブ履歴の表示
mayu ingest history
# 特定のジョブの詳細を表示（失敗したIDを含む）
mayu ingest history --job-id 42
```

### 脆弱性の検索

```bash
# 脆弱性IDで検索
mayu search --id GO-2024-2687
# パッケージ名で検索
mayu search --package golang.org/x/crypto
# エコシステムで検索
mayu search --ecosystem Go --limit 10
# CVEエイリアスで検索
mayu search --id CVE-2024-24790
# Package URL（purl）で検索
mayu search --purl pkg:npm/%40angular/core
# 位置引数（--idの省略形）
mayu search CVE-2024-24790
# 重大度レベルでフィルタ
mayu search --severity critical --ecosystem Go
# 日付でフィルタ（指定日以降に変更されたもの）
mayu search --since 2024-01-01 --ecosystem npm
# 影響を受けるバージョンでフィルタ
mayu search --package golang.org/x/crypto --version 0.17.0
# KEV（Known Exploited Vulnerabilities）でフィルタ
mayu search --kev --limit 10
# EPSSスコアでソート
mayu search --ecosystem Go --sort epss_desc --limit 10
# 全文検索（最初に--initが必要）
mayu search --init
mayu search --query "remote code execution" --ecosystem Go
# ページネーション
mayu search --ecosystem Go --limit 10 --offset 20
# カーソルベースのページネーション（前回の出力のNextTokenを使用）
mayu search --ecosystem Go --limit 10 --starting-token <token>
# 結果数のみ表示
mayu search --ecosystem Go --count
# 詳細表示（全フィールド）
mayu search --id GO-2024-2687 --detail
# スクリプト用JSON出力
mayu search --id GO-2024-2687 --format json
# CSVエクスポート
mayu search --ecosystem Go --format csv > vulns.csv
```

### SBOM監査

```bash
# CycloneDX SBOMの脆弱性監査
mayu audit --sbom ./sbom.cdx.json
# SPDX SBOMの監査
mayu audit --sbom ./sbom.spdx.json
# 開発依存関係を含める
mayu audit --sbom ./sbom.cdx.json --include-dev
# バージョンマッチングをスキップ（マッチしたパッケージのすべての脆弱性を表示）
mayu audit --sbom ./sbom.cdx.json --no-version-check
# JSON出力
mayu audit --sbom ./sbom.cdx.json --format json
# CSV出力
mayu audit --sbom ./sbom.cdx.json --format csv
# SARIF出力（GitHub Code Scanning / GitLab SAST用）
mayu audit --sbom ./sbom.cdx.json --format sarif > results.sarif
# CriticalとHighの重大度の検出結果のみ失敗
mayu audit --sbom ./sbom.cdx.json --fail-on critical,high
# 受容済み脆弱性を抑制
mayu audit --sbom ./sbom.cdx.json --ignore .mayu-ignore
# VEX抑制の適用
mayu audit --sbom ./sbom.cdx.json --vex product.vex.json
# ポリシーベースのゲーティングを適用
mayu audit --sbom ./sbom.cdx.json --policy policy.yaml
# ライセンスコンプライアンスチェック
mayu audit --sbom ./sbom.cdx.json --license-policy license-policy.yaml
# CI/CDゲート: すべてのオプションを組み合わせ
mayu audit --sbom bom.json --fail-on critical,high --ignore .mayu-ignore --format sarif > results.sarif
# エンリッチドSBOM生成（入力SBOM + 脆弱性検出結果 + EPSS/LEV/KEVデータ）
mayu audit --sbom ./sbom.cdx.json --output-sbom enriched.cdx.json
```

### サーバーの起動

```bash
# サーバーを起動（API + Web UI、デフォルトポート: 8080）
mayu serve
# カスタムポートで起動
mayu serve --addr :3000
```

## CLIリファレンス

### `mayu ingest`

OSVからローカルデータベースに脆弱性データをインポートします。

| フラグ | 説明 | デフォルト |
|------|-------------|---------|
| `--ecosystem` | インポートするエコシステム（例: Go、PyPI、npm） | — |
| `--source` | ソースからインポート（`osv`、`nvd`、`mitre`、`epss`、`kev`、`exploitdb`、`eol`、`ghsa`） | — |
| `--type` | `--source osv` のサブタイプ（nvd、debian）でOSV変換データをインポート | — |
| `--update` | フルインポートの代わりにデルタ更新を実行 | `false` |
| `--backfill` | 過去データのバックフィル（`--source epss` と併用） | `false` |
| `--from` | バックフィルの開始日（YYYY-MM-DD） | `2023-03-07`（EPSS v3） |
| `--to` | バックフィルの終了日（YYYY-MM-DD） | 今日 |
| `--repo` | GitHubリポジトリ（owner/repo）`--source ghsa` 用 | — |
| `--year` | 特定の年のNVDフィードのみインポート（`--source nvd` と併用） | — |
| `--concurrency` | 並列インポートするエコシステム数（`--source osv` と併用） | `3` |
| `--store-workers` | エコシステムごとの並列DBストアワーカー数 | CPUコア数 - 1 |
| `--batch-size` | バッチインサートごとの脆弱性数 | `100` |

> [!TIP]
> 利用可能なエコシステムのリストは [`ecosystems.txt`](https://www.googleapis.com/download/storage/v1/b/osv-vulnerabilities/o/ecosystems.txt) で公開されています。

### `mayu ingest history`

インジェストジョブの実行履歴を表示します。すべての `ingest` コマンドは、オプション、タイミング、ステータス、失敗した脆弱性IDとともに自動的に記録されます。

| フラグ | 説明 | デフォルト |
|------|-------------|---------|
| `--limit` | 表示する最近のジョブ数 | `20` |
| `--job-id` | 特定のジョブIDの詳細を表示（失敗リストを含む） | — |
| `--format` | 出力形式: `table`、`json` | `table` |

**例:**

```bash
# 最近のインジェストジョブを一覧表示
mayu ingest history

# 直近5件のジョブを表示
mayu ingest history --limit 5

# ジョブ#42の詳細を表示（失敗したCVE/OSV IDを含む）
mayu ingest history --job-id 42

# スクリプト用JSON出力
mayu ingest history --format json
```

**ジョブごとの記録情報:**
- 使用されたコマンドオプション（エコシステム、ソース、更新モードなど）
- 開始・終了タイムスタンプ
- ステータス: `success`、`failed`、`partial`（一部失敗）
- カウント: total、success、failure
- 各失敗: 脆弱性ID、エラータイプ、エラーメッセージ、スタックトレース

> [!NOTE]
> 直近100件のジョブのみ保持されます。古いジョブは自動的に削除されます。

### `mayu audit`

SBOMの既知の脆弱性を監査します。

| フラグ | 説明 | デフォルト |
|------|-------------|---------|
| `--sbom` | SBOMファイルのパス（CycloneDX 1.7またはSPDX 2.3 JSON） | （必須） |
| `--format` | 出力形式: `table`、`json`、`csv`、`sarif` | `table` |
| `--include-dev` | 開発依存関係を監査に含める | `false` |
| `--no-version-check` | バージョンマッチングをスキップし、パッケージ名のすべての脆弱性を報告 | `false` |
| `--fail-on` | 指定した重大度以上の検出結果のみ失敗（カンマ区切り: `critical`、`high`、`medium`、`low`、`none`） | （すべての検出結果で失敗） |
| `--ignore` | 抑制する脆弱性IDを含む無視ファイルのパス（1行1ID、`#` でコメント） | - |
| `--vex` | `not_affected` の検出結果を抑制するOpenVEXファイルのパス | — |
| `--policy` | カスタムゲーティング用ポリシーYAMLファイルのパス（block/warn/suppress） | — |
| `--license-policy` | ライセンスコンプライアンスチェック用ライセンスポリシーYAMLファイルのパス | — |
| `--output-sbom` | 脆弱性セクション付きエンリッチドSBOMの出力先パス（CycloneDX形式） | — |

**終了コード:**

| コード | 意味 |
|------|---------|
| 0 | 脆弱性未検出（または `--fail-on` しきい値を超えるものなし） |
| 1 | しきい値を超える検出結果あり（または `--fail-on` 未設定時に検出結果あり） |
| 2 | エラー（無効な入力、データベース接続失敗など） |

**サポートされるSBOM形式:**
- CycloneDX 1.7 (JSON) -- `scope` および `cdx:npm:package:development` プロパティで開発依存関係を検出
- SPDX 2.3 (JSON) -- すべてのパッケージをプロダクションとして扱う（SPDXにはdev/prodの区別がない）

**無視ファイルの形式 (`.mayu-ignore`):**

```
# Accepted risks
CVE-2024-1234    # reason: no impact on our usage
GHSA-xxxx-yyyy   # suppressed until 2025-03-01
```

**CI/CD連携例（GitHub Actions）:**

```yaml
- name: 依存関係の監査
  run: |
    mayu audit --sbom bom.json --fail-on critical,high --ignore .mayu-ignore --format sarif > results.sarif

- name: SARIFのアップロード
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### `mayu sbom` 認証

> [!WARNING]
> `mayu sbom` サブコマンドは**実験的**です。CLIインターフェース、APIレスポンス、データベーススキーマへの破壊的変更が予告なく行われる可能性があります。データベースに保存されたSBOMスキャン結果は、将来のリリースでのスキーママイグレーション時にリセットされる場合があります。

すべての `mayu sbom` サブコマンドには認証が必要です。以下のいずれかの方法で認証できます:

1. **APIキー（CI/CD推奨）:** `MAYU_API_KEY` 環境変数を設定。
2. **セッショントークン:** `mayu login` を実行してセッションをローカルに保存。

```bash
# 方法1: APIキー
export MAYU_API_KEY=your-api-key

# 方法2: セッションベースのログイン
mayu login
```

### `mayu sbom upload`

SBOMファイルをアップロードし、脆弱性スキャンを実行します。

| フラグ | 説明 | デフォルト |
|------|-------------|---------|
| `--project` | プロジェクト名 | （必須） |
| `--version` | SBOMバージョンラベル | （必須） |
| `--sbom` | SBOMファイルのパス（CycloneDXまたはSPDX JSON） | （必須） |
| `--environment` | 環境ラベル（例: `production`、`staging`） | — |

**例:**

```bash
export MAYU_API_KEY=your-api-key
mayu sbom upload --project my-app --version 1.0.0 --sbom bom.json
mayu sbom upload --project my-app --version 2.0.0 --sbom bom.json --environment production
```

### `mayu sbom scan`

最新の脆弱性データベースを使用して、既存のSBOMバージョンを再スキャンします。

| フラグ | 説明 | デフォルト |
|------|-------------|---------|
| `--project` | プロジェクト名 | （必須） |
| `--version` | スキャンするバージョン（省略時は最新バージョンをスキャン） | — |

**例:**

```bash
export MAYU_API_KEY=your-api-key
mayu sbom scan --project my-app
mayu sbom scan --project my-app --version 1.0.0
```

### `mayu sbom list`

SBOMプロジェクトまたはプロジェクト内のバージョンを一覧表示します。

| フラグ | 説明 | デフォルト |
|------|-------------|---------|
| `--project` | プロジェクト名（省略時はすべてのプロジェクトを一覧表示） | — |

**例:**

```bash
export MAYU_API_KEY=your-api-key
mayu sbom list                    # すべてのプロジェクトを一覧表示
mayu sbom list --project my-app   # プロジェクトのバージョンを一覧表示
```

### `mayu search`

ローカルデータベースで脆弱性を検索します。

| フラグ | 説明 | デフォルト |
|------|-------------|---------|
| `--id` | 脆弱性IDまたはエイリアスで検索（例: CVE-2024-1234、GO-2024-2687、GHSA-xxxx） | — |
| `--package` | パッケージ名で検索 | — |
| `--ecosystem` | エコシステムでフィルタ | — |
| `--purl` | Package URLで検索（例: `pkg:npm/%40angular/core`） | — |
| `--severity` | CVSS重大度レベルでフィルタ（critical、high、medium、low、none） | — |
| `--since` | 変更日でフィルタ（YYYY-MM-DDまたはRFC3339） | — |
| `--version` | 影響を受けるバージョンでフィルタ | — |
| `--kev` | KEV（Known Exploited Vulnerabilities）エントリのみにフィルタ | `false` |
| `--sort` | ソート順: `modified_desc`、`modified_asc`、`published_desc`、`published_asc`、`epss_desc`、`epss_asc` | `modified_desc` |
| `--query` | 全文検索クエリ（config.yamlで `search.engine` の設定が必要） | — |
| `--format` | 出力形式: `table`、`json`、`csv` | `table` |
| `--limit` | 最大結果数 | `20` |
| `--offset` | ページネーション用オフセット（非推奨: `--starting-token` を使用） | `0` |
| `--starting-token` | ページネーション用カーソルトークン（前回の `NextToken` 出力から） | — |
| `--count` | 結果数のみ表示 | `false` |
| `--detail` | 各結果の詳細情報を表示 | `false` |
| `--init` | 全文検索インデックスの初期化（最初の `--query` 使用前に必要） | `false` |

### `mayu serve`

脆弱性データアクセス用のサーバー（REST API + Web UI）を起動します。

| フラグ | 説明 | デフォルト |
|------|-------------|---------|
| `--addr` | リッスンするアドレス（host:port） | `:8080` |
| `--ui-dir` | Web UIホスティング用SPAスタティックファイルディレクトリのパス | — |

**エンドポイント:**

API仕様の全容は [`internal/server/openapi.yaml`](internal/server/openapi.yaml) を参照するか、サーバー実行中に `http://localhost:8080/openapi.yaml` にアクセスしてください。

### `mayu migrate`

データベースマイグレーションを実行します（バイナリに組み込み済み）。

| フラグ | 説明 | デフォルト |
|------|-------------|---------|
| `--steps` | 適用するマイグレーション数（0 = すべて、負の値でロールバック） | `0` |

**サブコマンド:**

| サブコマンド | 説明 |
|------------|-------------|
| `up` | 保留中のすべてのマイグレーションを適用（デフォルト） |
| `down` | 1つのマイグレーションをロールバック（または `--steps N`） |
| `status` | 現在のマイグレーションバージョンを表示 |

**例:**

```bash
mayu migrate              # 保留中のすべてのマイグレーションを適用
mayu migrate up
mayu migrate down
mayu migrate down --steps 3
mayu migrate status
```

### `mayu user create`

新しいユーザーアカウントを作成します。

| フラグ | 説明 | デフォルト |
|------|-------------|---------|
| `--email` | ユーザーメールアドレス（必須） | — |
| `--name` | ユーザー表示名 | — |
| `--role` | ユーザーロール: `admin` または `viewer` | `viewer` |
| `--password` | ユーザーパスワード（必須） | — |

**例:**

```bash
mayu user create --email admin@example.com --name Admin --role admin --password secret
mayu user create --email viewer@example.com --role viewer --password mypass
```

### `mayu user update`

既存ユーザーのロールを更新します。

| フラグ | 説明 | デフォルト |
|------|-------------|---------|
| `--email` | 更新するユーザーのメールアドレス（必須） | — |
| `--role` | 新しいロール: `admin` または `viewer`（必須） | — |

**例:**

```bash
mayu user update --email user@example.com --role admin
mayu user update --email user@example.com --role viewer
```

### `mayu user list`

すべてのユーザーをテーブル形式で一覧表示します（ID、Email、Name、Role）。

**例:**

```bash
mayu user list
```

### `mayu user reset-password`

ユーザーのパスワードをリセットします（管理者操作）。`auth.mode=local` の場合のみ利用可能です。

| フラグ | 説明 | デフォルト |
|------|-------------|---------|
| `--email` | ユーザーメールアドレス（必須） | — |
| `--password` | 新しいパスワード（必須） | — |

**例:**

```bash
mayu user reset-password --email user@example.com --password newpassword
```

> [!NOTE]
> `auth.mode` が `local` でない場合（つまり `none` または `oidc`）、このコマンドはエラーで終了します。

### `mayu apikey create`

ユーザー用の新しいAPIキーを作成します。生成されたキーは一度だけ表示され、復元できません。

| フラグ | 説明 | デフォルト |
|------|-------------|---------|
| `--user-email` | キーを関連付けるユーザーのメールアドレス（必須） | — |
| `--name` | APIキーの説明/名前 | — |
| `--expires` | 有効期限（例: `90d`、`1y`、`24h`） | —（有効期限なし） |

**例:**

```bash
mayu apikey create --user-email admin@example.com --name 'CI Pipeline'
mayu apikey create --user-email admin@example.com --name 'Temp Key' --expires 90d
```

### `mayu webhook` 認証

すべての `mayu webhook` サブコマンドには認証が必要です。以下のいずれかの方法で認証できます:

1. **APIキー（CI/CD推奨）:** `MAYU_API_KEY` 環境変数を設定。
2. **セッショントークン:** `mayu login` を実行してセッションをローカルに保存。

Webhookはユーザーごとにスコープされます -- 各ユーザーは自分のWebhookのみ管理できます。

```bash
# 方法1: APIキー
export MAYU_API_KEY=your-api-key

# 方法2: セッションベースのログイン
mayu login
```

### `mayu webhook create`

通知用の新しいWebhookを作成します。

> [!TIP]
> テンプレート変数、イベント、署名検証、配信動作の詳細なドキュメントは [docs/webhooks.ja.md](docs/webhooks.ja.md) を参照してください。

| フラグ | 説明 | デフォルト |
|------|-------------|---------|
| `--name` | Webhook名（必須） | — |
| `--url` | Webhook URL（必須） | — |
| `--events` | サブスクライブするイベントのカンマ区切りリスト（必須） | — |
| `--content-type` | Webhookリクエストのコンテントタイプヘッダー | `application/json` |
| `--body-template` | リクエストボディのMustacheテンプレート | — |
| `--secret` | Webhook署名検証用HMACシークレット | — |
| `--enabled` | Webhookを有効にするかどうか | `true` |

**例:**

```bash
export MAYU_API_KEY=your-api-key
mayu webhook create --name "security-team-slack" --url "https://hooks.slack.com/services/T00/B00/xxxx" --events "new_critical,new_high" --body-template '{"text": "{{ID}} ({{Severity}}) - {{Summary}}"}'
mayu webhook create --name "all-vulns" --url "https://example.com/webhook" --events "*"
```

### `mayu webhook list`

認証済みユーザーのWebhookをテーブル形式で一覧表示します（ID、Name、URL、Events、Enabled）。

**例:**

```bash
export MAYU_API_KEY=your-api-key
mayu webhook list
```

### `mayu webhook test`

接続性を確認するためにWebhookにテストペイロードを送信します。

| フラグ | 説明 | デフォルト |
|------|-------------|---------|
| `--id` | テストするWebhook ID（必須） | — |

**例:**

```bash
export MAYU_API_KEY=your-api-key
mayu webhook test --id 1
```

### `mayu scan`

SBOMを生成せずにロックファイルの既知の脆弱性をスキャンします。

| フラグ | 説明 | デフォルト |
|------|-------------|---------|
| `--lockfile` | スキャンするロックファイルのパス | — |
| `--dir` | ロックファイルをスキャンするディレクトリ | — |
| `--format` | 出力形式: `table`、`json`、`csv`、`sarif` | `table` |
| `--fail-on` | 指定した重大度以上の検出結果のみ終了コード1で失敗 | — |
| `--ignore` | 抑制する脆弱性IDを含む無視ファイルのパス | — |
| `--include-dev` | 開発依存関係をスキャンに含める | `false` |
| `--no-version-check` | バージョンマッチングをスキップ | `false` |
| `--policy` | カスタムゲーティング用ポリシーYAMLファイルのパス | — |
| `--reachability` | Goプロジェクトで到達可能性分析を実行 | `false` |

**サポートされるロックファイル形式:**
- go.sum (Go)
- package-lock.json (npm)
- yarn.lock (Yarn)
- pnpm-lock.yaml (pnpm)
- Pipfile.lock (Python/pipenv)
- poetry.lock (Python/poetry)
- Gemfile.lock (Ruby)
- Cargo.lock (Rust)
- requirements.txt (Python/pip)
- composer.lock (PHP)

**例:**

```bash
mayu scan --lockfile ./go.sum
mayu scan --dir .
mayu scan --lockfile ./package-lock.json --format json
mayu scan --dir . --fail-on critical,high
mayu scan --lockfile ./Cargo.lock --ignore .mayu-ignore
mayu scan --lockfile ./go.sum --reachability
```

### `mayu status`

データソースの同期状態とEPSSカバレッジを表示します。

| フラグ | 説明 | デフォルト |
|------|-------------|---------|
| `--format` | 出力形式: `table`、`json` | `table` |

**例:**

```bash
mayu status
mayu status --format json
```

### `mayu watch`

新しい脆弱性が条件に一致した際の自動通知用ウォッチリストを管理します。

**サブコマンド:** `add`、`list`、`remove`、`check`

#### `mayu watch add`

| フラグ | 説明 | デフォルト |
|------|-------------|---------|
| `--name` | ウォッチリストエントリ名（必須） | — |
| `--type` | マッチタイプ: `package`、`purl`、`cpe`、`ecosystem`（必須） | — |
| `--ecosystem` | エコシステム名（package/ecosystemマッチタイプ用） | — |
| `--package` | パッケージ名（packageマッチタイプ用） | — |
| `--purl` | プレフィックスマッチング用Purlパターン（purlマッチタイプ用） | — |
| `--cpe` | プレフィックスマッチング用CPEパターン（cpeマッチタイプ用） | — |
| `--severity-min` | 最小重大度: critical、high、medium、low、none | — |
| `--epss-threshold` | 最小EPSSスコアしきい値（0.0-1.0） | — |
| `--user-email` | このウォッチリストを所有するユーザーのメールアドレス（必須） | — |

#### `mayu watch list`

| フラグ | 説明 | デフォルト |
|------|-------------|---------|
| `--user-email` | ユーザーのメールアドレス（必須） | — |

#### `mayu watch remove`

| フラグ | 説明 | デフォルト |
|------|-------------|---------|
| `--id` | ウォッチリストエントリID（必須） | — |
| `--user-email` | ユーザーのメールアドレス（必須） | — |

#### `mayu watch check`

| フラグ | 説明 | デフォルト |
|------|-------------|---------|
| `--dry-run` | 通知を送信せずにマッチをプレビュー | `false` |

**例:**

```bash
mayu watch add --name 'Go crypto' --type package --ecosystem Go --package golang.org/x/crypto --user-email admin@example.com
mayu watch add --name 'Express' --type purl --purl pkg:npm/express --user-email admin@example.com
mayu watch add --name 'Apache HTTPD' --type cpe --cpe 'cpe:2.3:a:apache:http_server' --user-email admin@example.com
mayu watch add --name 'Go Critical' --type ecosystem --ecosystem Go --severity-min critical --user-email admin@example.com
mayu watch list --user-email admin@example.com
mayu watch remove --id 1 --user-email admin@example.com
mayu watch check --dry-run
```

### `mayu team`

共同脆弱性追跡と共有リソース（ウォッチリスト、Webhook、SBOMプロジェクト）のためのチームを管理します。

**サブコマンド:** `create`、`list`、`add-member`、`remove-member`、`members`

#### `mayu team create`

| フラグ | 説明 | デフォルト |
|------|-------------|---------|
| `--name` | チーム名（必須） | — |
| `--description` | チームの説明 | — |

#### `mayu team list`

フラグなし。すべてのチームを一覧表示します。

#### `mayu team add-member`

| フラグ | 説明 | デフォルト |
|------|-------------|---------|
| `--team` | チーム名（必須） | — |
| `--email` | 追加するユーザーのメールアドレス（必須） | — |
| `--role` | メンバーロール: `owner` または `member` | `member` |

#### `mayu team remove-member`

| フラグ | 説明 | デフォルト |
|------|-------------|---------|
| `--team` | チーム名（必須） | — |
| `--email` | 削除するユーザーのメールアドレス（必須） | — |

#### `mayu team members`

| フラグ | 説明 | デフォルト |
|------|-------------|---------|
| `--team` | チーム名（必須） | — |

**例:**

```bash
mayu team create --name "platform-team" --description "Platform engineering team"
mayu team list
mayu team add-member --team platform-team --email user@example.com --role owner
mayu team add-member --team platform-team --email dev@example.com
mayu team remove-member --team platform-team --email dev@example.com
mayu team members --team platform-team
```

### `mayu vex`

SBOM検出結果ステータス管理用のOpenVEXドキュメントをインポートおよびエクスポートします。

**サブコマンド:** `export`、`import`

すべての `mayu vex` サブコマンドには認証が必要です（`MAYU_API_KEY` を設定するか `mayu login` を実行）。

#### `mayu vex export`

| フラグ | 説明 | デフォルト |
|------|-------------|---------|
| `--project` | プロジェクト名（必須） | — |
| `--version` | バージョン（デフォルト: 最新） | — |
| `--author` | ドキュメント作成者 | `mayu` |
| `--id` | ドキュメントID（デフォルト: 自動生成） | — |

#### `mayu vex import`

| フラグ | 説明 | デフォルト |
|------|-------------|---------|
| `--project` | プロジェクト名（必須） | — |
| `--version` | バージョン（デフォルト: 最新） | — |
| `--file` | OpenVEXファイルのパス（必須） | — |

**例:**

```bash
export MAYU_API_KEY=your-api-key
mayu vex export --project my-app --version 1.0.0 > product.vex.json
mayu vex export --project my-app --author security-team@example.com
mayu vex import --project my-app --file product.vex.json
```

### `mayu policy`

監査ゲーティング用ポリシーファイルの検証と管理を行います。

**サブコマンド:** `validate`

#### `mayu policy validate`

| フラグ | 説明 | デフォルト |
|------|-------------|---------|
| `--file` | ポリシーYAMLファイルのパス（必須） | — |

**例:**

```bash
mayu policy validate --file policy.yaml
```

### `mayu notification`

通知チャンネルとテンプレートを管理します。

**サブコマンド:** `templates`、`test-email`

#### `mayu notification templates`

| フラグ | 説明 | デフォルト |
|------|-------------|---------|
| `--format` | 出力形式: `table`、`json` | `table` |
| `--name` | 特定のテンプレートの完全な内容を表示（slack、teams、email） | — |

#### `mayu notification test-email`

| フラグ | 説明 | デフォルト |
|------|-------------|---------|
| `--to` | 受信者メールアドレス（必須） | — |
| `--subject` | メール件名 | `Mayu Test Email Notification` |

**例:**

```bash
mayu notification templates
mayu notification templates --name slack
mayu notification test-email --to admin@example.com
```

### `mayu sbom generate`

ロックファイルからCycloneDXまたはSPDX形式のSBOMを生成します。認証不要（ローカル操作のみ）。

| フラグ | 説明 | デフォルト |
|------|-------------|---------|
| `--lockfile` | ロックファイルのパス | — |
| `--dir` | ロックファイルをスキャンするディレクトリ | — |
| `--format` | 出力形式: `cyclonedx` または `spdx` | `cyclonedx` |
| `--name` | プロジェクト/コンポーネント名 | — |
| `--version` | プロジェクトバージョン | — |
| `--output` | 出力ファイルパス（デフォルト: 標準出力） | — |

**例:**

```bash
mayu sbom generate --lockfile ./go.sum --format cyclonedx --name my-app --version 1.0.0
mayu sbom generate --dir . --format spdx --name my-app
mayu sbom generate --lockfile ./package-lock.json --output sbom.cdx.json
```

### `mayu sbom suppress`

検出結果を抑制します（このコンテキストでは該当しないとマーク）。認証が必要です。

| フラグ | 説明 | デフォルト |
|------|-------------|---------|
| `--project` | プロジェクト名（必須） | — |
| `--version` | バージョン（デフォルト: 最新） | — |
| `--vuln` | 脆弱性ID（必須） | — |
| `--purl` | Package URL（省略時は最初にマッチする検出結果に適用） | — |
| `--reason` | 正当化理由 | — |
| `--expires` | 有効期限（例: 90d、1y） | — |

**例:**

```bash
export MAYU_API_KEY=your-api-key
mayu sbom suppress --project my-app --vuln CVE-2024-1234 --reason "not applicable"
```

### `mayu sbom accept`

検出結果のリスクを受容します（パッチできない既知の脆弱性）。認証が必要です。

| フラグ | 説明 | デフォルト |
|------|-------------|---------|
| `--project` | プロジェクト名（必須） | — |
| `--version` | バージョン（デフォルト: 最新） | — |
| `--vuln` | 脆弱性ID（必須） | — |
| `--purl` | Package URL（省略時は最初にマッチする検出結果に適用） | — |
| `--reason` | 正当化理由（必須） | — |
| `--expires` | 有効期限（例: 90d、1y） | — |

**例:**

```bash
export MAYU_API_KEY=your-api-key
mayu sbom accept --project my-app --vuln CVE-2024-1234 --reason "isolated environment" --expires 90d
```

### `mayu sbom status`

SBOMバージョンの検出結果ステータスの表示またはリセットを行います。認証が必要です。

| フラグ | 説明 | デフォルト |
|------|-------------|---------|
| `--project` | プロジェクト名（必須） | — |
| `--version` | バージョン（デフォルト: 最新） | — |
| `--filter` | ステータスでフィルタ（カンマ区切り: open、in_triage、suppressed、false_positive、risk_accepted、resolved） | — |
| `--reset` | 脆弱性IDのステータスをリセット | — |
| `--purl` | リセット操作用Package URL | — |

**例:**

```bash
export MAYU_API_KEY=your-api-key
mayu sbom status --project my-app
mayu sbom status --project my-app --filter suppressed,risk_accepted
mayu sbom status --project my-app --reset CVE-2024-1234 --purl pkg:npm/example@1.0.0
```

### `mayu login`

mayuサーバーで認証し、セッション認証情報をローカルに保存します。認証情報は `~/.config/mayu/credentials.json` に `0600` パーミッションで保存されます。

| フラグ | 説明 | デフォルト |
|------|-------------|---------|
| `--oidc` | OIDCブラウザベースのログインを使用 | `false` |
| `--server` | サーバーURL | `http://localhost:8080` |

**モード:**

- **対話型（デフォルト）:** ターミナルでメールアドレスとパスワードの入力を求めます。
- **OIDC（`--oidc`）:** OIDC認証用にデフォルトブラウザを開きます。コールバックを受信するためにランダムポートで一時的なローカルHTTPサーバーが起動されます。

**認証の優先順位**（`mayu sbom`、`mayu webhook`、その他の認証が必要なコマンドで使用）:

1. `MAYU_API_KEY` 環境変数（CI/CD推奨）
2. `mayu login` からの保存済みセッショントークン（`~/.config/mayu/credentials.json`）
3. `mayu login` または `MAYU_API_KEY` の設定を提案するメッセージ付きエラー

**例:**

```bash
# 対話型メール/パスワードログイン
mayu login

# サーバーURLを指定
mayu login --server http://example.com:8080

# OIDCブラウザベースのログイン（設定でauth.mode=oidcが必要）
mayu login --oidc

# カスタムサーバーでのOIDCログイン
mayu login --oidc --server http://example.com:8080
```

### `mayu logout`

保存済みセッション認証情報を削除します。オプションでサーバー上のセッションを無効化します（ベストエフォート；サーバーに到達できない場合でも失敗しません）。

**例:**

```bash
mayu logout
```

### `mayu version`

バージョン情報を表示します。

## 設定

### 設定ファイル

MayuはYAML設定ファイルをサポートしています。デフォルトのパスは:

```
$HOME/.config/mayu/config.yaml
```

`--config` グローバルオプションでカスタムパスを指定できます:

```bash
mayu --config /path/to/config.yaml search --id CVE-2024-1234
```

デフォルトの設定ファイルが存在しない場合、mayuは環境変数とデフォルト値にサイレントにフォールバックします。`--config` が明示的に指定され、ファイルが存在しない場合、mayuはエラーを報告します。

**`config.yaml` の例:**

```yaml
# Database connection
database_url: postgres://mayu:mayu@localhost:5432/mayu?sslmode=disable

# Authentication settings
auth:
  # mode: none | local | oidc (default: none)
  mode: none

# EPSS data retention (default: 365 days, counted from yesterday)
# Set to -1 to retain all historical data indefinitely (required for full LEV accuracy)
epss:
  retention_days: 365
```

**ローカル認証の例:**

```yaml
database_url: postgres://mayu:mayu@localhost:5432/mayu?sslmode=disable

auth:
  mode: local
  session_secret: "your-random-secret-key"
  session_max_age: 86400  # seconds (default: 86400 = 24h)
```

**OIDC認証の例:**

```yaml
database_url: postgres://mayu:mayu@localhost:5432/mayu?sslmode=disable

auth:
  mode: oidc
  session_secret: "your-random-secret-key"
  session_max_age: 86400
  oidc:
    issuer: "https://accounts.google.com"
    client_id: "your-client-id.apps.googleusercontent.com"
    client_secret: "your-client-secret"
    redirect_url: "http://localhost:8080/auth/callback"
    scopes:
      - openid
      - email
      - profile
```

**優先順位**（高い順）:

1. 環境変数（`DATABASE_URL`）
2. 設定ファイル（`config.yaml` — `--config` でパスを指定）
3. デフォルト値

### 環境変数

| 環境変数 | 説明 | デフォルト |
|---------------------|-------------|---------|
| `DATABASE_URL` | PostgreSQL接続文字列 | `postgres://mayu:mayu@localhost:5432/mayu?sslmode=disable` |

> [!WARNING]
> デフォルトの接続文字列は `sslmode=disable` を使用しており、これは
> バンドルされたDocker PostgreSQLに対するローカル開発でのみ適切です。
> リモートまたは本番データベースの場合、`sslmode=require`（または証明書検証用の
> `verify-full`）を設定して**TLSを強制**してください。例:
> `postgres://user:pass@db.example.com:5432/mayu?sslmode=verify-full`
> Mayuは非ローカルホストへのTLS未強制接続を検出すると警告を出力します。

## データソース

| ソース | ステータス | 方法 |
|--------|--------|--------|
| [OSV](https://osv.dev/) | ✅ 対応済み | GCSバケット（`gs://osv-vulnerabilities/`） |
| [NVD CVE（変換版）](https://storage.googleapis.com/cve-osv-conversion/index.html?prefix=osv-output/) | ✅ 対応済み | `mayu ingest --source osv --type nvd` |
| [NVD CVE（ネイティブ）](https://nvd.nist.gov/vuln/data-feeds) | ✅ 対応済み | `mayu ingest --source nvd` |
| [Debianセキュリティアドバイザリ](https://storage.googleapis.com/debian-osv/index.html) | ✅ 対応済み | `mayu ingest --source osv --type debian` |
| [MITRE CVE (cvelistV5)](https://github.com/CVEProject/cvelistV5) | ✅ 対応済み | `mayu ingest --source mitre` |
| [GitHub Security Advisories](https://docs.github.com/en/rest/security-advisories/repository-advisories) | ✅ 対応済み | `mayu ingest --source ghsa --repo owner/repo` |

> [!NOTE]
> 変換ソース（NVD、Debian）は50,000件以上のエントリを含み、一括アーカイブが利用できないため個別にダウンロードされます。これにはかなりの時間がかかる場合があります。

> [!TIP]
> 2つのNVDインポート方法（ネイティブ vs. OSV変換）の詳細な比較については、[docs/nvd-import-comparison.ja.md](docs/nvd-import-comparison.ja.md) を参照してください。

| ソース | ステータス | 方法 |
|--------|--------|--------|
| KEV | ✅ 対応済み | `mayu ingest --source kev` |
| EPSS | ✅ 対応済み | `mayu ingest --source epss` |
| LEV | ✅ 対応済み | EPSS + KEVから計算（下記参照） |
| [Exploit-DB](https://gitlab.com/exploit-database/exploitdb) | ✅ 対応済み | `mayu ingest --source exploitdb` |
| [endoflife.date](https://endoflife.date/) | ✅ 対応済み | `mayu ingest --source eol` |

## LEV (Likely Exploited Vulnerabilities)

Mayuは[LEV](https://doi.org/10.6028/NIST.CSWP.41)スコアを計算します — NIST（CSWP 41）が提案した確率論的指標で、CVEが**すでに実際に悪用された**可能性を推定します。

### 仕組み

LEVはmayuにすでにある2つのデータソースを組み合わせます:

| データソース | 役割 | 時間の視点 |
|-------------|------|-----------------|
| **EPSS** | 日次悪用確率（P30） | 未来（今後30日） |
| **CISA KEV** | 確認済み悪用 | 過去（既知の悪用） |
| **LEV** | 過去の悪用確率 | 過去（推定） |

**アルゴリズム**（NIST CSWP 41の厳密なアプローチ）:

```
P1  = 1 - (1 - P30)^(1/30)       # EPSS 30日確率 → 日次確率に変換
LEV = 1 - ∏(1 - P1_i)             # すべての過去の日にわたって複合
```

CVEがCISA KEVカタログに含まれている場合、LEVは自動的に**1.0**（確認済み悪用）に設定されます。

> [!NOTE]
> この実装はP30→P1の厳密な変換を使用しており、高いEPSSスコアでは不正確な論文の `P30/30` 近似は使用していません。

### LEVのセットアップ

LEVには過去のEPSS日次データが必要です。バックフィルコマンドを使用して時系列を構築します:

```bash
# 1. CISA KEVカタログのインポート
mayu ingest --source kev
# 2. EPSS v3リリース（2023-03-07）から今日までのEPSS日次スコアをバックフィル
mayu ingest --source epss --backfill
# または特定の日付範囲を指定
mayu ingest --source epss --backfill --from 2024-01-01 --to 2025-07-19
# 3. 初回バックフィル後、EPSSを日次更新で最新に保つ
mayu ingest --source epss --update
```

> [!TIP]
> バックフィルは1日あたり約5-7 MB（約200,000件のCVEスコア）をダウンロードします。2023-03-07からの完全なバックフィルは約860日をカバーします。既にインポート済みの日付は再実行時に自動的にスキップされます。

> [!IMPORTANT]
> デフォルトでは、mayuは365日分のEPSS履歴を保持します。LEVの精度は過去データが多いほど向上します。最大精度のためには、`config.yaml` で `epss.retention_days: -1` を設定してすべてのデータを無期限に保持してください。各EPSSインジェスト後、保持期間を超えたデータは自動的にクリーンアップされます。

### LEVスコアの確認

LEVは `--detail` ビューとAPI `?detail=true` レスポンスで自動的に表示されます:

```bash
mayu search --id CVE-2023-38831 --detail
```

出力にはEPSS、KEV、LEVのセクションが含まれます:

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

API例:

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

### LEVスコアの解釈

| LEV範囲 | 解釈 |
|-----------|---------------|
| 0.95 – 1.0 | ほぼ確実に悪用済み（またはKEVで確認済み） |
| 0.70 – 0.95 | 悪用された可能性が非常に高い |
| 0.30 – 0.70 | 悪用された可能性あり |
| 0.05 – 0.30 | 過去に悪用された確率は低い |
| 0.00 – 0.05 | 悪用されたとは考えにくい |

> [!IMPORTANT]
> LEVは確率論的推定であり、確認された事実ではありません。脆弱性の優先順位付けには、他のシグナル（KEV、EPSS、CVSS）と併せて使用してください。

## コントリビュート

開発環境のセットアップ、コーディング規約、変更の提出方法については [CONTRIBUTING_ja.md](CONTRIBUTING_ja.md) を参照してください。

## ライセンス

[MIT](LICENSE)

## ロードマップ

完全な実装計画については [.agents/tasks/PLAN.md](.agents/tasks/PLAN.md) を参照してください。

- [x] Phase 1: データパイプライン（OSVインジェスション）
- [x] Phase 2: CLI（ingest + search）
- [x] Phase 3: CI/CD（GitHub Actions）
- [x] Phase 4: APIサーバー（REST）
- [x] Phase 5: Web UI（Angular）
- [x] Phase 6: 追加データソース（EPSS、KEV、LEV）
- [x] EPSSトレンドグラフ & LEV可視化
- [x] 高度なトリアージワークフロー（SSVC意思決定支援）
- [x] ダッシュボード & レポーティング
- [x] 通知（webhook）
- [x] 通知（メール）
- [x] [endoflife.date](https://endoflife.date/) 統合
- [x] SBOM機能（継続監視、検出結果ステータス管理）
- [x] ロックファイルスキャン（10以上の形式、到達可能性分析）
- [x] VEXインポート/エクスポート（OpenVEX）
- [x] ポリシーベースのゲーティング & ライセンスコンプライアンス
- [x] チーム管理 & ウォッチリスト
- [x] Exploit-DB統合
