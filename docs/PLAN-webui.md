# Mayu Web UI - Implementation Plan (Phase 5)

## Problem Statement

Mayu の脆弱性データをブラウザから一覧・詳細表示できる Web UI を構築する。左サイドバー式の admin theme ライクなレイアウトで、既存の `mayu serve` REST API を活用する。

## Requirements

- Angular v22 + TailwindCSS v4 + Angular CDK
- Vitest（Angular v22 デフォルト）によるユニットテスト
- 左サイドバー式 admin theme レイアウト
- 脆弱性一覧ページ（全フィルタ対応: ecosystem, package, severity, since, version, purl, alias, id）
- 脆弱性詳細ページ（`?detail=true` による OSV/NVD/MITRE 統合表示）
- 開発時 proxy 設定（`localhost:4200/api/**` → `localhost:8080`）
- 認証認可は不要
- ディレクトリ: `ui/`

## Background

- API は `/api/v1/vulnerabilities`（検索）と `/api/v1/vulnerabilities/{id}`（個別取得, `?detail=true` で enriched）を提供
- SearchResponse: `{ vulnerabilities: [], total, limit, offset }`
- VulnerabilityDetail: OSV base + NVD enrichment + MITRE enrichment
- Angular v22 は Vite ベースのビルドシステムがデフォルト
- TailwindCSS v4 は `ng add tailwindcss` で自動設定可能
- Proxy は `proxy.conf.json` + angular.json の `proxyConfig` で設定

## Directory Structure

```
ui/
├── src/
│   ├── app/
│   │   ├── layout/              # サイドバー + ヘッダー + メインコンテンツ
│   │   ├── pages/
│   │   │   ├── vulnerabilities/ # 一覧ページ
│   │   │   └── vulnerability-detail/ # 詳細ページ
│   │   ├── services/            # API通信サービス
│   │   ├── models/              # TypeScript型定義
│   │   └── shared/              # 共有コンポーネント（ページネーション等）
│   ├── proxy.conf.json
│   └── styles.css               # TailwindCSS import
├── angular.json
├── package.json
└── tsconfig.json
```

## Task Breakdown

### Task 1: Angular プロジェクト初期化とツールチェーン設定

**目的:** `ui/` に Angular v22 プロジェクトを作成し、開発環境を整備する

**実装ガイダンス:**

- `.tool-versions` に `nodejs` と `pnpm` を追加
- ユーザーが手動で以下を実行（CLI インタラクティブ操作が必要）:
  ```bash
  pnpm dlx @angular/cli@latest new ui --package-manager pnpm --style css --ssr false --routing true
  ```
- プロジェクト作成後、TailwindCSS v4 を `ng add tailwindcss` でセットアップ
- Angular CDK を追加: `pnpm add @angular/cdk`
- `ui/src/proxy.conf.json` を作成:
  ```json
  {
    "/api/**": {
      "target": "http://localhost:8080",
      "secure": false
    }
  }
  ```
- `angular.json` の `serve` ターゲットに `"proxyConfig": "src/proxy.conf.json"` を追加
- Makefile に `ui-dev`, `ui-build`, `ui-test`, `ui-lint` ターゲットを追加

**テスト:** `pnpm --prefix ui run build` が成功、`pnpm --prefix ui test` が成功

**Demo:** `ng serve` でデフォルトの Angular welcome ページが表示される。`/api/v1/vulnerabilities?ecosystem=Go&limit=1` へのプロキシが動作する

---

### Task 2: TypeScript 型定義と API サービス

**目的:** API レスポンスの型定義と HttpClient ベースの API サービスを作成する

**実装ガイダンス:**

- `ui/src/app/models/vulnerability.model.ts` — OSV Vulnerability 型、SearchResponse 型、VulnerabilityDetail 型（NVD/MITRE 含む）を定義
- `ui/src/app/models/search-params.model.ts` — 検索パラメータのインターフェース
- `ui/src/app/services/vulnerability.service.ts` — HttpClient を使った API サービス:
  - `search(params: SearchParams): Observable<SearchResponse>`
  - `getById(id: string): Observable<Vulnerability>`
  - `getDetail(id: string): Observable<VulnerabilityDetail>`
- `provideHttpClient()` を app.config.ts に追加

**テスト:** VulnerabilityService のユニットテスト（HttpClient モック使用、各メソッドの正常系・エラー系）

**Demo:** テストが全パスし、サービスが正しいURLにリクエストを送ることが検証される

---

### Task 3: レイアウトコンポーネント（左サイドバー + ヘッダー）

**目的:** admin theme ライクな左サイドバー式レイアウトを構築する

**実装ガイダンス:**

- `ui/src/app/layout/sidebar/sidebar.component.ts` — ナビゲーションリンク（Vulnerabilities）、将来拡張可能な構造
- `ui/src/app/layout/header/header.component.ts` — アプリ名「Mayu」、ページタイトル表示
- `ui/src/app/layout/layout.component.ts` — サイドバー + メインコンテンツエリアの組み合わせ
- TailwindCSS でスタイリング:
  - サイドバー: 固定幅（w-64）、左側固定、ダークカラー
  - メインコンテンツ: `ml-64` でサイドバー分のオフセット
  - レスポンシブ対応: モバイルではサイドバー非表示 + ハンバーガーメニュー（CDK overlay 活用）
- ルーティング: `app.routes.ts` でレイアウト内にネストされたルート定義

**テスト:** レイアウトコンポーネントのレンダリングテスト、ナビゲーションリンクの存在確認

**Demo:** `ng serve` でサイドバー付きレイアウトが表示される。サイドバーの「Vulnerabilities」リンクが機能する

---

### Task 4: 脆弱性一覧ページ（基本表示 + ページネーション）

**目的:** 脆弱性の一覧を表示し、ページネーションで大量データをナビゲートできるようにする

**実装ガイダンス:**

- `ui/src/app/pages/vulnerabilities/vulnerabilities.component.ts` — 一覧ページ
- テーブル表示: ID, Summary, Ecosystem, Severity, Modified の列
- ページネーション: offset/limit ベース（`ui/src/app/shared/pagination/pagination.component.ts`）
- Total count の表示
- ローディング状態の表示
- エラーハンドリング（API エラー時のメッセージ表示）
- デフォルトで ecosystem=Go, limit=20 で初期表示
- URL にクエリパラメータを反映（ブラウザバック対応）

**テスト:** コンポーネントテスト（データ表示、ページネーション操作、ローディング/エラー状態）

**Demo:** `mayu serve` 起動中に、一覧ページに脆弱性リストが表示され、ページネーションで次のページに遷移できる

---

### Task 5: 脆弱性一覧ページ（フィルタ機能）

**目的:** 全検索フィルタ（ecosystem, package, severity, since, version, purl, alias, id）を UI として提供する

**実装ガイダンス:**

- フィルタパネル（テーブル上部）:
  - テキスト入力: ID, Package, Alias, Purl, Version
  - ドロップダウン: Ecosystem（主要エコシステムリスト）, Severity（critical/high/medium/low/none）
  - 日付入力: Since（date picker）
- フィルタ変更時に自動再検索（debounce 300ms）
- URL クエリパラメータとフィルタ状態の同期（URL から初期値復元）
- フィルタクリアボタン
- レスポンシブ対応: モバイルではフィルタ折りたたみ

**テスト:** フィルタ操作 → API呼び出しパラメータの検証、URLパラメータ同期のテスト

**Demo:** ecosystem を「npm」に変更すると一覧が即座に絞り込まれ、ブラウザのURLにもパラメータが反映される

---

### Task 6: 脆弱性詳細ページ

**目的:** 単一の脆弱性の全情報（OSV + NVD + MITRE）を見やすく表示する

**実装ガイダンス:**

- `ui/src/app/pages/vulnerability-detail/vulnerability-detail.component.ts`
- `/vulnerabilities/:id` ルート、`VulnerabilityService.getDetail(id)` を使用
- セクション分け:
  - 基本情報: ID, Summary, Details, Published/Modified, Aliases
  - Severity: CVSS スコアバッジ（色分け）
  - Affected Packages: パッケージ名、バージョン範囲、エコシステム
  - References: リンクリスト（タイプ別アイコン）
  - Credits: 発見者情報
  - NVD セクション（存在する場合）: Description, Metrics, Weaknesses (CWE), References
  - MITRE セクション（存在する場合）: State, Assigner, Metrics, Problem Types, Credits, SSVC
- 一覧ページへの「戻る」リンク（フィルタ状態保持）
- 404 ハンドリング

**テスト:** 詳細ページのレンダリングテスト（NVD/MITREありなし両パターン）、404ケース

**Demo:** 一覧ページから脆弱性 ID をクリックすると詳細ページに遷移し、OSV/NVD/MITRE の情報がセクション別に表示される

---

### Task 7: UI 仕上げとビルド最適化

**目的:** 全体の UI を磨き上げ、本番ビルドを整備する

**実装ガイダンス:**

- Severity バッジのカラースキーム統一（Critical=赤, High=橙, Medium=黄, Low=青, None=灰）
- 空状態の表示（検索結果なし）
- 一覧ページの列ソート表示（modified 日付降順がデフォルト）
- TailwindCSS のダークモード対応（`prefers-color-scheme` ベース）
- `pnpm --prefix ui run build` で production ビルドが成功すること確認
- `ui/` の `.gitignore` 整備（node_modules, dist 等）
- README.md / README_ja.md の Phase 5 セクション更新

**テスト:** 全テストパス、production ビルド成功、Lighthouse で基本的なアクセシビリティスコア確認

**Demo:** ダークモードとライトモードの切り替え、空状態の表示、production ビルドの成功
