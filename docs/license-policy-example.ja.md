---
title: "ライセンスポリシーの例"
---
# ライセンスポリシーの例

`mayu audit --license-policy` で使用するライセンスポリシーファイルの例です。

## 使用方法

```bash
mayu audit --sbom ./sbom.cdx.json --license-policy license-policy.yaml
```

## ポリシーファイルの形式

```yaml
license_policy:
  # 明示的に許可するライセンス（違反として報告されない）
  allow:
    - MIT
    - Apache-2.0
    - BSD-2-Clause
    - BSD-3-Clause
    - ISC
    - Unlicense
    - CC0-1.0
    - 0BSD
    - BlueOak-1.0.0
    - CC-BY-4.0

  # 明示的に拒否するライセンス（終了コード 1）
  deny:
    - GPL-2.0-only
    - GPL-2.0-or-later
    - GPL-3.0-only
    - GPL-3.0-or-later
    - AGPL-3.0-only
    - AGPL-3.0-or-later
    - SSPL-1.0

  # 手動レビューが必要なライセンス（警告として報告）
  review:
    - MPL-2.0
    - LGPL-2.1-only
    - LGPL-2.1-or-later
    - LGPL-3.0-only
    - LGPL-3.0-or-later
    - EPL-2.0
    - CDDL-1.0
```

## 動作

- **allow リストあり**: `allow`、`deny`、`review` のいずれにも含まれないライセンスは暗黙的に拒否されます。
- **allow リストなし**: `deny` または `review` に明示的に含まれるライセンスのみが違反を引き起こします。
- **不明なライセンス**: ライセンス情報が検出されないコンポーネントは、allow リストが存在する場合に拒否として扱われます。

## 終了コード

| コード | 意味 |
|--------|------|
| 0 | ライセンス違反なし（または "review" 違反のみ） |
| 1 | 1 つ以上の "deny" 違反が検出された |
| 2 | エラー（無効なポリシーファイル、無効な SBOM 等） |
