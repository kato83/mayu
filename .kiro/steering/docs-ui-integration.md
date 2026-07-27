# Docs → Angular UI Integration Guide

> **When to read this:** `docs/` 配下のファイルを追加・リネーム・削除する場合

## Overview

`docs/` 配下のmarkdownファイルは Angular Web UI の `/docs` ページで閲覧できるようにする。
ビルド時に `ui/public/docs/docs/` へコピーされ、SPAの静的アセットとして配信される。

## 新規ドキュメント追加時のチェックリスト

### 1. Frontmatter の追加

ドキュメント先頭に YAML frontmatter で `title` を付ける（UIのサイドバー/ページタイトルに使用）。

```markdown
---
title: "Your Document Title"
---
# Your Document Title
```

日本語版も同様:

```markdown
---
title: "ドキュメントタイトル"
---
# ドキュメントタイトル
```

### 2. `ui/package.json` の `copy-docs` スクリプトを更新

`cp` コマンドの引数に新しいファイルを追加:

```json
"copy-docs": "mkdir -p public/docs/docs && cp ../README.md public/docs/ && ... && cp ../docs/your-new-doc.md ../docs/your-new-doc.ja.md public/docs/docs/ && ..."
```

### 3. `ui/src/app/pages/docs/docs-manifest.ts` にエントリ追加

```typescript
export const DOCS_MANIFEST: DocEntry[] = [
  // ...existing entries...
  { slug: 'your-slug', title: 'Your Title', filename: 'docs/docs/your-new-doc.md', filenameJa: 'docs/docs/your-new-doc.ja.md' },
];
```

- `slug`: URLパスに使用（`/docs/your-slug`）
- `title`: フォールバック用タイトル（frontmatterの`title`がUIで優先される場合もある）
- `filename`: ビルド後の相対パス（`docs/docs/` prefix）
- `filenameJa`: 日本語版（省略可、なければ英語版にフォールバック）

### 4. ビルド確認

```bash
cd ui && pnpm run build
# ビルド成果物に含まれるか確認:
find dist -name "your-new-doc*"
```

## ファイル命名規則

| 言語 | ファイル名 |
|------|-----------|
| English | `docs/your-doc.md` |
| Japanese | `docs/your-doc.ja.md` |

## 既存ドキュメントのリネーム・削除時

1. `ui/package.json` の `copy-docs` から旧ファイル名を削除/変更
2. `docs-manifest.ts` のエントリを更新/削除
3. `ui/public/docs/docs/` のキャッシュが残る場合は手動削除（`.gitignore` 対象のため通常不要）

## 注意事項

- `ui/public/docs/` は `.gitignore` 対象。ビルド時に `prebuild` フックで自動コピーされる
- `pnpm exec ng build` を直接叩くと `prebuild` が走らないので `pnpm run build` を使うこと
- 画像は `cp ../docs/*.jpg ../docs/*.png public/docs/docs/` で一括コピーされるため個別追加不要
