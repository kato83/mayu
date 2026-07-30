---
title: "GHSA JSON のインポート"
---
# GitHub Security Advisory JSON のインポート

リポジトリレベルの GitHub Security Advisory としてのみ存在し、まだ OSV に反映されていない脆弱性を mayu にインポートする方法。

## 推奨: API による直接インポート

GitHub Security Advisory をインポートする最も簡単な方法は、組み込みの API フェッチャーを使用することです:

```bash
# リポジトリの公開済みアドバイザリをすべてインポート
mayu ingest --source ghsa --repo WordPress/wordpress-develop

# 認証付き（レート制限対策として推奨）
export GITHUB_TOKEN=ghp_xxx
mayu ingest --source ghsa --repo owner/repo
```

これにより GitHub REST API 経由で公開済みアドバイザリを自動的に取得し、GitHub 形式から OSV 形式に変換してデータベースに保存します。

パブリックリポジトリでは認証不要です。レート制限の緩和やプライベートリポジトリのアドバイザリへのアクセスには `GITHUB_TOKEN` を設定してください。

以降のセクションでは、API アクセスが利用できない場合の手動インポート方法を説明します。

## 背景

GitHub Security Advisory（GHSA）は 2 段階で公開されます:

1. **リポジトリ Security Advisory** — メンテナがリポジトリ内で作成・公開（`/security/advisories/GHSA-xxxx`）
2. **GitHub Advisory Database** — GitHub のセキュリティチームがキュレーションし、グローバルアドバイザリデータベースに反映

OSV は GitHub Advisory Database から自動的に取り込みます。ステージ 1 のみのアドバイザリは OSV に**存在しません**。このギャップ（通常、数日〜数週間）は、OSV 形式の JSON を手動で構築し `mayu ingest --file` でインポートすることで埋められます。

## GHSA JSON の取得方法

### 方法 1: GitHub Advisory Database リポジトリ（OSV 形式 — 推奨）

GitHub はレビュー済みのすべてのアドバイザリを OSV 形式の JSON として [`github/advisory-database`](https://github.com/github/advisory-database) リポジトリで公開しています。

- ディレクトリ構成: `advisories/{github-reviewed|unreviewed}/{year}/{month}/{GHSA-ID}/{GHSA-ID}.json`

```bash
# 特定の GHSA を直接取得
curl -sL -o GHSA-xxxx-xxxx-xxxx.json \
  https://raw.githubusercontent.com/github/advisory-database/main/advisories/github-reviewed/2026/07/GHSA-xxxx-xxxx-xxxx/GHSA-xxxx-xxxx-xxxx.json

# mayu にインポート
./bin/mayu ingest --file GHSA-xxxx-xxxx-xxxx.json
```

> **注意**: グローバル Advisory Database にまだ反映されていない場合は 404 が返されます。その場合は方法 3 を使用してください。

### 方法 2: GitHub REST API（GitHub ネイティブ形式）

```bash
# グローバル Advisory API（認証不要、レート制限あり）
curl -sH "Accept: application/vnd.github+json" \
  https://api.github.com/advisories/GHSA-xxxx-xxxx-xxxx

# リポジトリ Advisory API（トークン必要）
curl -sH "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  https://api.github.com/repos/{owner}/{repo}/security-advisories/GHSA-xxxx-xxxx-xxxx
```

> **注意**: REST API のレスポンスは GitHub 独自形式であり、OSV 形式ではありません。`mayu ingest --file` はこの形式を**受け付けません**（OSV 形式のみ対応）。GitHub API からの自動変換インポートには `mayu ingest --source ghsa --repo owner/repo` を使用してください。

### 方法 3: OSV JSON の手動構築

リポジトリの Security Advisory ページ（例: `https://github.com/{owner}/{repo}/security/advisories/GHSA-xxxx`）の情報を読み取り、OSV 形式の JSON を手動で構築します。

必須フィールド:
- `id` — GHSA ID
- `modified` — 最終更新タイムスタンプ（ISO 8601）

推奨フィールド:
- `schema_version` — `"1.6.0"`
- `published` — 公開タイムスタンプ
- `aliases` — CVE ID 等
- `summary` — 一行の概要
- `details` — 詳細な説明
- `severity` — CVSS ベクトル
- `affected` — 影響を受けるパッケージとバージョン範囲
- `references` — 参照リンク
- `credits` — 報告者/発見者

テンプレート:

```json
{
    "schema_version": "1.6.0",
    "id": "GHSA-xxxx-xxxx-xxxx",
    "published": "2026-01-01T00:00:00Z",
    "modified": "2026-01-01T00:00:00Z",
    "aliases": [
        "CVE-2026-XXXXX"
    ],
    "summary": "脆弱性の一行概要",
    "details": "脆弱性とその影響の詳細な説明。",
    "severity": [
        {
            "type": "CVSS_V3",
            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        }
    ],
    "affected": [
        {
            "package": {
                "ecosystem": "Ecosystem",
                "name": "package-name"
            },
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "1.0.0"},
                        {"fixed": "1.0.1"}
                    ]
                }
            ]
        }
    ],
    "references": [
        {
            "type": "ADVISORY",
            "url": "https://github.com/{owner}/{repo}/security/advisories/GHSA-xxxx-xxxx-xxxx"
        },
        {
            "type": "WEB",
            "url": "https://example.com/release-notes"
        }
    ],
    "credits": [
        {
            "name": "研究者名",
            "type": "FINDER"
        }
    ]
}
```

## mayu へのインポート

> **重要**: `mayu ingest --file` は **OSV 形式の JSON のみ**を受け付けます。GitHub REST API のレスポンス（GitHub ネイティブ形式）は直接インポートできません。自動変換インポートには `mayu ingest --source ghsa --repo owner/repo` を使用してください。

```bash
# 単一ファイル（OSV 形式であること）
./bin/mayu ingest --file GHSA-xxxx-xxxx-xxxx.json

# 複数ファイル
./bin/mayu ingest --file vuln1.json vuln2.json vuln3.json

# カスタム DB URL（設定ファイル経由）
./bin/mayu --config /path/to/config.yaml ingest --file vuln1.json
```

## 実例: WordPress CVE-2026-60137 / CVE-2026-63030

WordPress 7.0.2（2026年7月17日）で公開された 2 つの重大な脆弱性。リポジトリ Security Advisory は存在していたが、GitHub Advisory Database や OSV にはまだ伝播していなかった。

### 情報ソース

| ソース | URL | 取得情報 |
|--------|-----|----------|
| WordPress リリースノート | https://wordpress.org/news/2026/07/wordpress-7-0-2-release/ | 影響バージョン、バックポート、CVE/GHSA マッピング |
| リポジトリ Advisory (SQLi) | https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-fpp7-x2x2-2mjf | 影響バージョン、概要、深刻度 |
| リポジトリ Advisory (RCE) | https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ff9f-jf42-662q | 影響バージョン、概要、深刻度 |
| NVD（mayu DB 経由） | `mayu search --id CVE-2026-60137` | CVSS、CWE |
| MITRE（mayu DB 経由） | 直接 DB クエリ | SSVC 評価、CISA-ADP CVSS |

### 作成した OSV JSON ファイル

<details>
<summary>GHSA-fpp7-x2x2-2mjf.json (CVE-2026-60137 — SQL インジェクション)</summary>

```json
{
    "schema_version": "1.6.0",
    "id": "GHSA-fpp7-x2x2-2mjf",
    "published": "2026-07-17T19:14:12Z",
    "modified": "2026-07-17T19:14:12Z",
    "aliases": ["CVE-2026-60137"],
    "summary": "Facilitated SQL injection vulnerability in the author__not_in parameter of WP_Query",
    "details": "WordPress versions 6.8 and higher are vulnerable to an SQL injection issue. In WordPress versions 6.9 and higher, this combined with a REST API batch-route confusion issue (GHSA-ff9f-jf42-662q) leads to Remote Code Execution.",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
    "affected": [{
        "package": {"ecosystem": "WordPress", "name": "wordpress"},
        "ranges": [
            {"type": "ECOSYSTEM", "events": [{"introduced": "6.8.0"}, {"fixed": "6.8.6"}]},
            {"type": "ECOSYSTEM", "events": [{"introduced": "6.9.0"}, {"fixed": "6.9.5"}]},
            {"type": "ECOSYSTEM", "events": [{"introduced": "7.0.0"}, {"fixed": "7.0.2"}]}
        ]
    }],
    "references": [
        {"type": "ADVISORY", "url": "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-fpp7-x2x2-2mjf"},
        {"type": "WEB", "url": "https://wordpress.org/news/2026/07/wordpress-7-0-2-release/"}
    ],
    "credits": [{"name": "TF1T, dtro, and haongo", "type": "FINDER"}]
}
```

</details>

<details>
<summary>GHSA-ff9f-jf42-662q.json (CVE-2026-63030 — ルート混同による RCE)</summary>

```json
{
    "schema_version": "1.6.0",
    "id": "GHSA-ff9f-jf42-662q",
    "published": "2026-07-17T19:14:12Z",
    "modified": "2026-07-17T19:14:12Z",
    "aliases": ["CVE-2026-63030"],
    "summary": "REST API batch-route confusion and SQL injection issue leading to Remote Code Execution",
    "details": "WordPress versions 6.9 and higher are vulnerable to a REST API batch-route confusion weakness, which combined with an SQL injection issue (GHSA-fpp7-x2x2-2mjf) leads to Remote Code Execution.",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "affected": [{
        "package": {"ecosystem": "WordPress", "name": "wordpress"},
        "ranges": [
            {"type": "ECOSYSTEM", "events": [{"introduced": "6.9.0"}, {"fixed": "6.9.5"}]},
            {"type": "ECOSYSTEM", "events": [{"introduced": "7.0.0"}, {"fixed": "7.0.2"}]}
        ]
    }],
    "references": [
        {"type": "ADVISORY", "url": "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ff9f-jf42-662q"},
        {"type": "WEB", "url": "https://wordpress.org/news/2026/07/wordpress-7-0-2-release/"}
    ],
    "credits": [{"name": "Adam Kues (Assetnote / Searchlight Cyber)", "type": "FINDER"}]
}
```

</details>

### インポート実行

```bash
./bin/mayu ingest --file \
  /tmp/mayu-import/GHSA-fpp7-x2x2-2mjf.json \
  /tmp/mayu-import/GHSA-ff9f-jf42-662q.json
```

```
=== Importing 2 local OSV JSON file(s) ===
  ✓ /tmp/mayu-import/GHSA-fpp7-x2x2-2mjf.json (id=GHSA-fpp7-x2x2-2mjf, aliases=[CVE-2026-60137])
  ✓ /tmp/mayu-import/GHSA-ff9f-jf42-662q.json (id=GHSA-ff9f-jf42-662q, aliases=[CVE-2026-63030])

Done: 2 imported, 0 failed
```

## 注意事項

- 手動で作成した JSON は、公式データソースが更新された際に上書きされます（OSV の upsert ルール）
- GitHub Advisory Database に反映された後は、`mayu ingest --all` で自動的に最新データが取得されます
- `ecosystem` フィールドは OSV の公式エコシステムリストにない値（例: `WordPress`）も受け付けますが、公式サポートが追加されるまで検索動作が制限される場合があります
- OSV の `id` フィールドにはユニーク制約があり、同じ GHSA ID を再インポートすると既存データが上書きされます

## 関連リソース

- [OSV スキーマ仕様](https://ossf.github.io/osv-schema/)
- [GitHub Advisory Database リポジトリ](https://github.com/github/advisory-database)
- [GitHub Security Advisories REST API](https://docs.github.com/en/rest/security-advisories)
- [WP Sec Adv (Wordfence → Composer)](https://github.com/typisttech/wpsecadv) — Composer 向け WordPress セキュリティアドバイザリ
