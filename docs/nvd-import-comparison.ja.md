# NVD インポート方式: ネイティブ vs OSV変換

## 背景

Mayu は NVD（National Vulnerability Database）の CVE データを取り込む方法を2つサポートしています：

| コマンド | データソース | フォーマット |
|---------|-------------|-------------|
| `mayu ingest --source nvd --native` | NVD 直接（nvd.nist.gov） | NVD JSON Feed 2.0 |
| `mayu ingest --source nvd` | Google OSV 変換バケット | OSV JSON |

このドキュメントでは、[OSV 変換ツール](https://github.com/google/osv.dev/tree/master/vulnfeeds/cmd/converters/cve/nvd-cve-osv)のソースコード分析と実際の変換出力の調査に基づき、2つの方式の違いを説明します。

## OSV 変換ツールが行っていること

OSV プロジェクトの `nvd-cve-osv` ツールは**単純なフォーマット変換ではなく**、大規模なエンリッチメントを行っています：

### 1. CPE → Git リポジトリの解決

CPE のベンダー名/製品名を GitHub リポジトリにマッピングする `cpe_product_to_repo.json` 辞書を使用。また、CVE の参照リンクからもリポジトリ URL を推定します。

```
CPE: cpe:2.3:a:microsoft:.net:*:*:*:*:*:*:*:*
  → リポジトリ: https://github.com/dotnet/core
```

### 2. Git コミットレンジの生成（最大の付加価値）

最も重要なエンリッチメント：NVD の CPE バージョン範囲情報を、リポジトリのタグ情報と照合して**実際の Git コミットハッシュ**に解決します。

```json
{
  "ranges": [{
    "type": "GIT",
    "repo": "https://github.com/dotnet/core",
    "events": [
      {"introduced": "63772e2191a750dd3cafa75914cacdb038c7520c"},
      {"fixed": "acd462c1e06e83a766b2385970316348765025d3"}
    ]
  }]
}
```

これにより、中央パッケージレジストリを持たない C/C++ エコシステムでもコミットハッシュベースの脆弱性マッチングが可能になります。詳細は [OSV ブログ記事](https://osv.dev/blog/posts/introducing-broad-c-c++-support/)を参照。

### 3. テキストからのバージョン情報抽出

CPE バージョンデータが不十分な場合、CVE の説明文からバージョン情報の抽出を試みます。

### 4. 付与されないもの

- **`package` フィールド（ecosystem, name, purl）は付与されない** — 50件以上のサンプルで確認済み
- **ECOSYSTEM タイプのレンジは生成されない** — GIT タイプのレンジのみ
- NVD が提供する以上の追加 CVSS スコアリングはなし

## 比較表

| 観点 | OSV変換版（`--source nvd`） | NVDネイティブ（`--source nvd --native`） |
|------|---------------------------|---------------------------------------|
| **カバレッジ** | 部分的（年ごとの変換成功率 52〜82%） | 完全（全CVE） |
| **Git コミットレンジ** | ✅ タグ解決により追加 | ❌ NVD には存在しない |
| **CPE コンフィギュレーション** | ❌ 失われる（AND/OR ロジック非保持） | ✅ 完全な CPE マッチロジックを保持 |
| **パッケージ情報（purl/ecosystem）** | ❌ 付与されない | ❌ NVD にも存在しない |
| **CVSS/重大度** | ✅ 保持 | ✅ 完全（全メトリクスバージョン） |
| **CWE 情報** | ❌ 含まれない | ✅ 保持 |
| **バージョン範囲** | `database_specific.extracted_events` に格納 | `nvd_cpe_matches` テーブルに格納 |
| **元データの可逆性** | OSV JSON（派生データ） | NVD JSON（権威あるソース） |
| **データ鮮度** | OSV パイプラインのスケジュールに依存 | NVD から直接取得 |
| **差分更新** | ❌ 差分メカニズムなし | ✅ Modified フィード利用可能 |

## 変換成功率（OSV ログより）

OSV 変換ツールが報告する年別メトリクス：

| 年度 | 成功率 |
|------|--------|
| 2016 | 81.6% |
| 2017 | 77.1% |
| 2018 | 64.2% |
| 2019 | 71.3% |
| 2020 | 73.5% |
| 2021 | 74.3% |
| 2022 | 75.3% |
| 2023 | 73.0% |
| 2024 | 52.3% |

「成功」とは、CPE データを Git コミットレンジに解決できたことを意味します。残りの CVE はスコープ外（対応する Git リポジトリなし）か、バージョン解決に失敗したものです。

## 変換結果の分類

ツールは各 CVE を以下のいずれかに分類します：

- **Successful** — Git コミットレンジを解決できた
- **NoRepos** — CPE に対応する Git リポジトリが見つからない
- **NoRanges** — リポジトリは見つかったがバージョン→コミットの解決に失敗
- **FixUnresolvable** — 修正コミットを特定できない
- **Rejected** — CVE が却下/無効

## Mayu への影響

### NVD ネイティブで十分なケース

Mayu の主要な用途 — CVE ID・パッケージ名・エコシステム・CVSS 重大度・CPE ベースの検索 — には、NVD ネイティブインポートが以下を提供します：

- **完全なカバレッジ**: 全 CVE がインポートされる（変換成功した 52〜82% だけではない）
- **完全な CPE ロジック**: AND/OR コンフィギュレーションノードが正確な製品マッチングのために保持される
- **CWE データ**: 弱点列挙がフィルタリング/表示に利用可能
- **差分更新**: 変更された CVE のみを再取得
- **権威あるソース**: NIST から直接取得（派生データではない）

### OSV 変換版が望ましいケース

OSV 変換データの独自の価値は **Git コミットレベルの affected ranges** です。これが重要になるのは、Mayu が以下を実装する場合のみ：

- Git コミットハッシュによる C/C++ 脆弱性マッチング（OSV-Scanner 相当の機能）
- サブモジュール/ベンダリングされた依存関係のコミットレベルスキャン

現時点で Mayu はこの機能を実装していません。

## 推奨事項

以下の理由から：
1. NVD ネイティブは完全な CVE カバレッジを提供（OSV 変換版は部分的）
2. Mayu は既に CPE 分解を含む完全な NVD ネイティブインポートに対応済み
3. OSV 変換は purl/ecosystem/package 情報を付加しない
4. 主要なエンリッチメント（Git コミットレンジ）は Mayu が現在実装していない用途向け
5. `--source nvd` に `--native` ありなしの2モードが存在することがユーザーの混乱を招く

**`--native` フラグを廃止し、`--source nvd` で常に NVD ネイティブフィードを直接参照するべきです。** これにより、現在使用している機能を失うことなく CLI インターフェースが簡素化されます。

将来的に Git コミットレベルの C/C++ マッチングが必要になった場合は、別のデータソース（例: `--source osv-nvd`）として明確な目的と制限のドキュメント付きで再導入できます。

## 参考資料

- [OSV NVD-CVE-OSV Converter ソースコード](https://github.com/google/osv.dev/tree/master/vulnfeeds/cmd/converters/cve/nvd-cve-osv)
- [OSV ブログ: Introducing broad C/C++ vulnerability management support](https://osv.dev/blog/posts/introducing-broad-c-c++-support/)
- [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities)
- [OSV 変換済み NVD データ（GCS）](https://storage.googleapis.com/cve-osv-conversion/index.html?prefix=osv-output/)
- [OSV Schema 仕様](https://ossf.github.io/osv-schema/)
