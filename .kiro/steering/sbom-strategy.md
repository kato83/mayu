# SBOM Strategy

## ポジショニング

mayuは「SBOM消費 + 脆弱性エンリッチメントプラットフォーム」である。
高品質なSBOM生成は専門ツール（Trivy, Syft, cdxgen）に委ね、
mayuはそれらの出力を受け取り、脆弱性インテリジェンスで価値を付加する「後段」に徹する。

**コアメッセージ**: 「mayuはSBOMを作るツールではない。SBOMに知性を与えるツールである。」

> "Trivy tells you what's vulnerable. Mayu tells you what to do about it."

### mayuが担う責務

- 外部生成SBOMの消費・パース（CycloneDX 1.6/1.7, SPDX 2.3）
- 脆弱性マッチング（OSV + NVD + MITRE横断）
- エンリッチメント（EPSS/LEV/KEV/CVSS/EOL/Exploit-DB付加）
- トリアージ支援（SSVC自動判定、ポリシーゲーティング）
- 継続監視（SBOM登録 → 新脆弱性検知 → 通知）
- VEXワークフロー（OpenVEX import/export）
- Enriched SBOM出力（入力SBOM + 脆弱性情報 → 出力SBOM）

### mayuが担わない責務

- ビルドシステム統合による精密SBOM生成（MVS, gradle dependency resolution等）
- コンテナイメージ解析
- ソースコードレベルの依存解決
- パッケージマネージャー固有ロジックの完全再実装

## 機能方針

| 機能 | 方針 | 備考 |
|------|------|------|
| `mayu sbom generate` | 縮小（convenience shortcut） | 推奨フローはTrivy/Syft→audit。品質改善への投資は行わない |
| `mayu audit --sbom` | 拡張（最重要） | enriched SBOM export、EOL統合が次の拡張方向 |
| `mayu sbom upload/scan/list` | 維持・拡張 | 継続監視のコア。トリアージ統合の深化 |
| `mayu sbom suppress/accept/status` | 維持 | Finding管理は安定。VEX連携で十分 |
| `mayu vex export/import` | 拡張 | CycloneDX VEX形式追加 |
| `mayu scan --lockfile/--dir` | 維持 | 「SBOMなしの簡易入口」として残す |

## 推奨ユーザーフロー

### 最推奨: 外部SBOM生成 + mayu audit

```bash
# 1. 専門ツールでSBOM生成
trivy fs --format cyclonedx --output sbom.cdx.json .

# 2. mayuで脆弱性エンリッチメント
mayu audit --sbom sbom.cdx.json --format sarif

# 3. (オプション) 継続監視に登録
mayu sbom upload --project my-app --version 1.0.0 --sbom sbom.cdx.json
```

### 簡易: ロックファイル直接スキャン（SBOM生成ツール不要）

```bash
mayu scan --dir . --fail-on critical,high
```

## 新機能ロードマップ（エンリッチメント方向）

### Priority High

1. **Enriched SBOM Export** — `mayu audit --sbom in.cdx.json --output-sbom enriched.cdx.json`
   - 入力SBOMにEPSS/LEV/KEV/EOL情報を付加したCycloneDX `vulnerabilities` セクション付きSBOMを出力
2. **SBOM Diff** — `mayu sbom diff --old v1.cdx.json --new v2.cdx.json`
   - 2つのSBOM間の差分を計算し、新規追加パッケージの脆弱性リスクを即座にエンリッチメント表示
3. **EOL-aware Audit Findings** — audit結果にEOLステータスを統合

### Priority Medium

4. **CycloneDX VEX形式対応** — CycloneDX組み込みVEX（`vulnerabilities[].analysis`）の入出力
5. **SBOM Quality Score** — 入力SBOMの品質評価（purlの欠落、バージョン情報なし等を報告）
6. **API-first Enrichment Endpoint** — `POST /api/v1/enrich` でSBOMをPOSTしてエンリッチメント結果を取得

### Priority Low

7. **CSAF VEX Import** — エンタープライズ環境でのベンダーVEX取り込み
8. **SBOM Attestation Verification** — in-toto/SLSA attestation付きSBOMの署名検証

## 他ツールとの連携

```
┌─────────────┐     ┌──────────────────────┐     ┌─────────────────┐
│  SBOM生成    │     │   mayu (enrich)       │     │  消費先          │
│  Trivy       │────▶│  ・脆弱性マッチング    │────▶│  GitHub SARIF    │
│  Syft        │     │  ・EPSS/LEV/KEVスコア  │     │  Jira チケット   │
│  cdxgen      │     │  ・トリアージ(SSVC)    │     │  Slack通知       │
│              │     │  ・ポリシーゲーティング  │     │  enriched SBOM  │
└─────────────┘     │  ・EOL警告            │     │  VEX文書        │
                    │  ・継続監視            │     └─────────────────┘
                    └──────────────────────┘
```

### CI/CDパイプライン例

```yaml
- name: Generate SBOM
  run: trivy fs --format cyclonedx --output sbom.cdx.json .

- name: Enrich & Gate
  run: |
    mayu audit --sbom sbom.cdx.json \
      --fail-on critical,high \
      --policy policy.yaml \
      --vex product.vex.json \
      --format sarif > results.sarif

- name: Continuous Monitoring
  run: mayu sbom upload --project $APP --version $VERSION --sbom sbom.cdx.json
```

## 開発ガイドライン

- `internal/lockfile` パーサーへの品質投資は最小限に留める（バグ修正のみ）
- `internal/sbom` パッケージのParse側（消費）は積極的に拡張する（新フォーマット対応等）
- `internal/sbom` パッケージのGenerate側は現状維持（バグ修正のみ）
- エンリッチメントロジックは `internal/audit` に集約する
- 新機能はenrichment/triage方向を優先する

## 対 Dependency-Track 差別化

| 観点 | Dependency-Track | mayu |
|------|-----------------|------|
| デプロイ | Java/Docker/K8s | シングルバイナリ + PostgreSQL |
| データソース | NVD + OSV | OSV + NVD + MITRE + EPSS + KEV + LEV + Exploit-DB + EOL |
| LEVスコア | ❌ | ✅（NIST CSWP 41準拠） |
| トリアージ | 手動のみ | SSVC自動 + 手動 |
| CLI | 限定的 | フル機能CLI |
| ポリシーゲーティング | ❌ | ✅ YAML定義 |
| オフライン | ❌ | ✅ 初回sync後完全オフライン |
