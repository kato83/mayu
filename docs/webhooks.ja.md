---
title: "Webhooks"
---
# Webhooks

Mayuは新しい脆弱性が取り込まれた際に、HTTP POSTリクエストで通知を送信できます。このドキュメントでは、Webhookの設定方法、利用可能なイベント、テンプレート変数について説明します。

## 概要

Webhookは脆弱性データのインジェスト後にトリガーされます。新しい脆弱性が検出されると、Mayuはイベントタイプに一致するすべての登録済みWebhook URLにPOSTリクエストを送信します。

主な機能:
- Go `text/template` 構文による柔軟なペイロード生成
- HMAC-SHA256署名検証（`X-Webhook-Signature` ヘッダー）
- 指数バックオフによる自動リトライ（最大3回: 1秒 → 5秒 → 30秒）
- ワイルドカードイベント購読（`*`）
- デバッグ用の配信ログ

## 設定

Webhookは**YAML設定ファイル**または**CLIコマンド**で設定できます。

### YAML設定

```yaml
webhooks:
  - name: "security-team-slack"
    url: "https://hooks.slack.com/services/T00/B00/xxxx"
    events: ["new_critical", "new_high"]
    content_type: "application/json"
    body_template: |
      {"text": "🚨 {{.ID}} ({{.Severity}}) - {{.Summary}}"}

  - name: "all-vulns"
    url: "https://example.com/api/webhook"
    events: ["*"]
    content_type: "application/json"
    secret: "my-shared-secret"
    body_template: |
      {
        "event": "{{.Event}}",
        "vulnerability": {
          "id": "{{.ID}}",
          "severity": "{{.Severity}}",
          "epss": {{.EPSS}},
          "lev": {{.LEV}},
          "summary": "{{.Summary}}"
        }
      }
```

### CLIコマンド

```bash
# Webhook作成
mayu webhook create \
  --name "slack-alerts" \
  --url "https://hooks.slack.com/services/T00/B00/xxxx" \
  --events "new_critical,new_high" \
  --body-template '{"text": "{{.ID}} ({{.Severity}}) - {{.Summary}}"}' \
  --secret "optional-hmac-secret"

# Webhook一覧表示
mayu webhook list

# Webhookテスト（サンプルペイロードを送信）
mayu webhook test --id 1
```

## イベント一覧

| イベント | 説明 |
|---------|------|
| `new_vulnerability` | 重大度に関わらず、新しく取り込まれたすべての脆弱性で発火。 |
| `new_critical` | CRITICAL（重大度レベル5）の脆弱性が取り込まれた際に発火。 |
| `new_high` | HIGH（重大度レベル4）の脆弱性が取り込まれた際に発火。 |
| `*` | ワイルドカード — すべてのイベントタイプにマッチ。 |

> **注意:** 1つの脆弱性が複数のイベントをトリガーすることがあります。例えば、CRITICALの脆弱性は `new_vulnerability` と `new_critical` の両方をトリガーします。`*` を購読しているWebhookはすべてのイベントを受信します。

### 重大度レベル

| レベル | 名称 | CVSSスコア範囲 |
|--------|------|---------------|
| 5 | CRITICAL | 9.0 – 10.0 |
| 4 | HIGH | 7.0 – 8.9 |
| 3 | MEDIUM | 4.0 – 6.9 |
| 2 | LOW | 0.1 – 3.9 |
| 1 | NONE | 0.0 |

## テンプレート変数

`body_template` フィールドはGoの [`text/template`](https://pkg.go.dev/text/template) 構文を使用します。テンプレートコンテキストで利用可能な変数は以下のとおりです。

| 変数 | 型 | 説明 | 値の例 |
|------|-----|------|--------|
| `{{.Event}}` | string | このWebhookをトリガーしたイベントタイプ。 | `"new_critical"` |
| `{{.ID}}` | string | 脆弱性の識別子。 | `"CVE-2024-1234"` |
| `{{.Severity}}` | string | 人間が読みやすい重大度レベル。 | `"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, `"LOW"`, `"NONE"` |
| `{{.EPSS}}` | float64 | EPSSスコア（0.0〜1.0）。悪用予測スコアリングシステムの確率値。 | `0.94218` |
| `{{.LEV}}` | float64 | LEVスコア（0.0〜1.0）。悪用された可能性の確率値。 | `0.85` |
| `{{.Summary}}` | string | 脆弱性の短い説明文。 | `"Remote code execution in ..."` |

> **注意:** `{{.EPSS}}` と `{{.LEV}}` は数値（float64）です。JSON文字列内で使用する場合、引用符は**不要**です。テキストコンテキストで使用する場合、小数として出力されます（例: `0.94218`）。

### テンプレート例

**Slack Incoming Webhook:**

```
{"text": "🚨 {{.ID}} ({{.Severity}}) - {{.Summary}}"}
```

**Microsoft Teams:**

```json
{
  "@type": "MessageCard",
  "summary": "New Vulnerability: {{.ID}}",
  "sections": [{
    "activityTitle": "{{.ID}} — {{.Severity}}",
    "facts": [
      {"name": "EPSS", "value": "{{.EPSS}}"},
      {"name": "LEV", "value": "{{.LEV}}"}
    ],
    "text": "{{.Summary}}"
  }]
}
```

**汎用JSON:**

```json
{
  "event": "{{.Event}}",
  "id": "{{.ID}}",
  "severity": "{{.Severity}}",
  "epss": {{.EPSS}},
  "lev": {{.LEV}},
  "summary": "{{.Summary}}"
}
```

**プレーンテキスト（メールゲートウェイ等）:**

```
[{{.Severity}}] {{.ID}}: {{.Summary}} (EPSS: {{.EPSS}})
```

### 条件分岐

Goテンプレートは条件分岐をサポートしています。例えば、EPSSが0以外の場合のみ含める:

```
{
  "id": "{{.ID}}",
  "severity": "{{.Severity}}"{{if gt .EPSS 0.0}},
  "epss": {{.EPSS}}{{end}}
}
```

## 署名検証

`secret` が設定されている場合、Mayuは `X-Webhook-Signature` ヘッダーにHMAC-SHA256署名を含めます:

```
X-Webhook-Signature: sha256=<リクエストボディのHMAC-SHA256を16進エンコードした値>
```

### 検証例（Go）

```go
func verifySignature(body []byte, secret, signature string) bool {
    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write(body)
    expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
    return hmac.Equal([]byte(expected), []byte(signature))
}
```

### 検証例（Python）

```python
import hmac
import hashlib

def verify_signature(body: bytes, secret: str, signature: str) -> bool:
    expected = "sha256=" + hmac.new(
        secret.encode(), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)
```

## 配信動作

| 項目 | 詳細 |
|------|------|
| HTTPメソッド | POST |
| Content-Type | 設定可能（デフォルト: `application/json`） |
| タイムアウト | リクエストあたり10秒 |
| 最大リトライ回数 | 合計3回 |
| リトライ間隔 | 1秒 → 5秒 → 30秒（指数バックオフ） |
| リトライ条件 | 5xxレスポンスまたは接続エラー |
| リトライしない | 2xx（成功）または4xx（クライアントエラー） |
| レスポンスボディ上限 | 1 KB（ログ記録用） |
| 配信ログ | Webhookごとに保存（Webhookあたり直近1000件） |

## テスト

`mayu webhook test --id <webhook-id>` でテストペイロードを送信できます。テスト時は以下のサンプル値が使用されます:

| 変数 | テスト値 |
|------|---------|
| `{{.Event}}` | `"test"` |
| `{{.ID}}` | `"CVE-0000-0000"` |
| `{{.Severity}}` | `"MEDIUM"` |
| `{{.EPSS}}` | `0.5` |
| `{{.LEV}}` | `0.3` |
| `{{.Summary}}` | `"Test webhook delivery"` |

## 配信ログ

Webhookの配信試行は記録され、API経由で確認できます:

```bash
curl http://localhost:8080/api/v1/webhooks/1/deliveries
```

各ログエントリには以下が含まれます:
- イベントタイプ
- レンダリング済みペイロード
- レスポンスステータスコード
- レスポンスボディ（先頭1 KB）
- エラーメッセージ（配信失敗時）
- 試行番号
- 所要時間（ミリ秒）
