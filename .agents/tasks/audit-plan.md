# `mayu audit` — SBOM Risk Analysis

## Problem Statement

SBOMファイルを入力として、ローカルDBに格納されている脆弱性データと照合し、SBOMに含まれるパッケージが抱えるリスク（脆弱性）を一覧表示するCLIコマンドを実装する。

## Requirements

- 新サブコマンド `mayu audit --sbom <path>` を追加
- CycloneDX 1.7 (JSON) と SPDX 2.3 (JSON) を自動判別してパース
- SBOMの各パッケージのpurlからエコシステム+パッケージ名+バージョンを抽出
- DBに対してパッケージ名+エコシステムでマッチする脆弱性を検索
- バージョン照合: OSV の `versions` 配列への完全一致 + `ranges`（SEMVER/ECOSYSTEM）のレンジ比較
- `--no-version-check` フラグでバージョン照合をスキップ（名前マッチのみ）
- `--include-dev` フラグでdevDependenciesも含める（デフォルト除外）
  - CycloneDX: `scope == "excluded"` or `cdx:npm:package:development == "true"` プロパティで判定
  - SPDX: dev判定手段がないため全パッケージが対象（制限事項として記載）
- 出力: パッケージ名 + CVE ID + severity のシンプル一覧
- `--format table|json|csv` の3形式対応
- exitコード: 脆弱性が見つかった場合は1、見つからなければ0

## Background

- 既存の `internal/purl` パッケージでpurl → エコシステム+パッケージ名変換が実装済み
- 既存の `store.Search()` はパッケージ名+エコシステム+バージョン(versions完全一致)で検索可能
- OSVのranges（SEMVER型 introduced/fixed）によるバージョンマッチングは未実装
- semverライブラリ（`Masterminds/semver/v3`）の追加が必要
- CycloneDXのコンポーネントには直接purlフィールドがある
- SPDXではexternalRefs内のpurlタイプから取得

## Directory Structure

```
internal/
├── sbom/           # NEW: SBOMパーサー (CycloneDX + SPDX)
│   ├── sbom.go         # 共通インターフェース + 自動フォーマット判別
│   ├── cyclonedx.go    # CycloneDX 1.7パーサー
│   ├── spdx.go         # SPDX 2.3パーサー
│   └── *_test.go
├── audit/          # NEW: audit ロジック（DB照合、バージョンマッチ）
│   ├── audit.go        # コア監査ロジック
│   ├── version.go      # SEMVER/ECOSYSTEMレンジ比較
│   └── *_test.go
cmd/mayu/
└── main.go         # audit サブコマンド追加
```

## CLI Interface

```bash
# Basic usage
mayu audit --sbom ./sbom.cdx.json

# Include dev dependencies
mayu audit --sbom ./sbom.cdx.json --include-dev

# Skip version checking (show all vulnerabilities for matched packages)
mayu audit --sbom ./sbom.cdx.json --no-version-check

# Output formats
mayu audit --sbom ./sbom.cdx.json --format json
mayu audit --sbom ./sbom.cdx.json --format csv

# Custom database (via config file)
mayu --config /path/to/config.yaml audit --sbom ./sbom.cdx.json
```

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--sbom` | Path to SBOM file (CycloneDX 1.7 or SPDX 2.3 JSON) | (required) |
| `--format` | Output format: `table`, `json`, `csv` | `table` |
| `--include-dev` | Include development dependencies in audit | `false` |
| `--no-version-check` | Skip version matching, report all vulnerabilities for package name | `false` |

### Output (table format)

```
PACKAGE                        VERSION   VULN ID          SEVERITY   SUMMARY
golang.org/x/crypto            0.17.0    CVE-2024-45337   HIGH       SSH server: unauthorized access via...
golang.org/x/net               0.19.0    CVE-2023-45288   MEDIUM     HTTP/2 CONTINUATION flood in net/http
```

### Exit Codes

- `0`: No vulnerabilities found
- `1`: One or more vulnerabilities found
- `2`: Error (invalid input, database connection failure, etc.)

## Task Breakdown

### Task 0: 計画ドキュメント出力

- `docs/audit-plan.md` に本計画を Markdown で書き出す

### Task 1: SBOMパーサーの共通インターフェースと CycloneDX パーサー

**Objective:** `internal/sbom` パッケージを作成し、CycloneDX 1.7 JSON をパースしてパッケージ一覧（purl、名前、バージョン、isDev）を抽出する

**Implementation:**
- `Component` 構造体: `Purl`, `Name`, `Version`, `Ecosystem`, `IsDev` フィールド
- `SBOM` 構造体: `Components []Component`, `Format string`
- `Parse(data []byte) (*SBOM, error)` — フォーマット自動判別
- `parseCycloneDX(data []byte) (*SBOM, error)` — CycloneDX固有パース
- dev判定: `scope == "excluded"` or `cdx:npm:package:development == "true"`
- `internal/purl.Parse()` を使ってエコシステム+パッケージ名を解決

**Tests:**
- 最小限のCycloneDX JSONフィクスチャで正常パース確認
- devDependencyの判定テスト
- purlなしコンポーネントのスキップテスト

### Task 2: SPDX 2.3 パーサー

**Objective:** SPDX 2.3 JSON をパースし、同じ `SBOM` 構造体で返す

**Implementation:**
- `parseSPDX(data []byte) (*SBOM, error)`
- `packages[].externalRefs[]` から `referenceType == "purl"` の `referenceLocator` を抽出
- SPDXではdev判定ができないため `IsDev = false` 固定
- フォーマット自動判別: `bomFormat == "CycloneDX"` → CycloneDX、`spdxVersion` フィールド存在 → SPDX

**Tests:**
- SPDX JSONフィクスチャで正常パース確認
- purlを持たないパッケージのスキップ
- フォーマット自動判別テスト

### Task 3: SEMVERバージョン比較ロジック

**Objective:** `internal/audit/version.go` にOSVのranges（SEMVER/ECOSYSTEM型）を評価してバージョンが影響範囲内かを判定する関数を実装

**Implementation:**
- `Masterminds/semver/v3` を依存追加
- `IsAffected(version string, affected model.Affected) bool` — バージョンが影響範囲内か判定
- ロジック:
  1. `affected.Versions` に完全一致があれば `true`
  2. `affected.Ranges` を走査、SEMVER/ECOSYSTEM型の場合 introduced/fixed/last_affected/limit でレンジ比較
  3. GIT型はスキップ（コミットハッシュベース比較不可）
- semverパース失敗時は安全側に倒してマッチ扱い（警告出力）

**Tests:**
- introduced/fixedの基本パターン
- introduced/last_affectedパターン
- 複数rangesの論理OR
- 不正バージョン文字列のフォールバック動作

### Task 4: auditコアロジック（DB照合）

**Objective:** `internal/audit/audit.go` にSBOMのコンポーネントリストをDBと照合し、脆弱性マッチ結果を返すロジックを実装

**Implementation:**
- `Finding` 構造体: `Component sbom.Component`, `VulnID string`, `Aliases []string`, `Severity string`, `SeverityLevel int`
- `Auditor` 構造体: `store store.Store`
- `Audit(ctx, components []sbom.Component, opts AuditOptions) ([]Finding, error)`
- `AuditOptions`: `IncludeDev bool`, `NoVersionCheck bool`
- パッケージごとに `store.SearchByPackages()` → 取得した脆弱性のaffected rangesに対してバージョンチェック
- バッチ化: 同一エコシステムのパッケージをまとめてクエリ効率化

**Tests:**
- モックstoreでの基本照合テスト
- IncludeDev=falseでdevパッケージがスキップされるテスト
- NoVersionCheck=trueで全マッチするテスト
- 脆弱性0件のケース

### Task 5: Store層への効率的なバッチ検索メソッド追加

**Objective:** audit用に複数パッケージの脆弱性を一括で取得する効率的なクエリを `Store` インターフェースに追加

**Implementation:**
- `SearchByPackages(ctx, packages []PackageQuery) (map[string][]*model.Vulnerability, error)` — キーは `ecosystem/name`
- `PackageQuery` 構造体: `Ecosystem`, `Name` フィールド
- 内部SQLは `(ecosystem, name) IN (...)` で一括取得し、affected packages含むfull dataを返す
- Storeインターフェースに追加

**Tests:**
- インテグレーションテスト（testcontainersでPostgreSQL）
- 0件クエリ
- 複数パッケージクエリ

### Task 6: CLI `mayu audit` サブコマンド配線

**Objective:** `cmd/mayu/main.go` に `audit` サブコマンドを追加し、全体を結合する

**Implementation:**
- `runAudit(args []string, cfg *config.Config) error`
- フラグ: `--sbom` (必須), `--format table|json|csv`, `--include-dev`, `--no-version-check`
- フロー: ファイル読み込み → sbom.Parse → audit.Audit → 結果出力
- table出力: `PACKAGE | VERSION | VULN ID | SEVERITY | SUMMARY`
- json出力: `{"findings": [...], "summary": {"total_packages": N, "vulnerable_packages": N, "total_findings": N}}`
- csv出力: ヘッダー付き
- exitコード: findings > 0 なら exit 1
- printUsageに `audit` コマンドを追加

**Tests:**
- main_test.go にauditサブコマンドのflag解析テスト

### Task 7: テストデータ・ドキュメント・仕上げ

**Objective:** testdataにSBOMフィクスチャを追加、README更新、全体テスト実行

**Implementation:**
- `testdata/sbom/` ディレクトリに最小限のCycloneDX/SPDXフィクスチャ
- README.md / README_ja.md に `mayu audit` のCLI Referenceセクション追加
- printUsageの更新
- `make test` 全パス確認
- `make lint` 全パス確認

## Limitations

- SPDX 2.3ではdev/production依存の区別がフォーマットレベルで定義されていないため、SPDXの場合は `--include-dev` フラグに関わらず全パッケージが対象となる
- GIT型のranges（コミットハッシュベース）はバージョン比較不可のためスキップ
- semverパース失敗時（非標準バージョン文字列）は安全側に倒してマッチ扱い
- REST API / Web UI は本フェーズのスコープ外（後続で追加予定）
