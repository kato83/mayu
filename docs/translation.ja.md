# 翻訳機能 (LLM ベース)

Mayu は脆弱性のテキストフィールド（概要、詳細、KEV説明、NVD説明）を OpenAI 互換 API を使ってオンデマンド翻訳する機能をサポートしています。

## 概要

翻訳が設定・有効化されている場合：

1. Web UI の脆弱性詳細ページに **「このページを翻訳」** ボタンが表示されます（非英語ロケールビルド時）。
2. ボタンをクリックすると `POST /api/v1/vulnerabilities/{id}/translate` が呼び出され、ソーステキストが LLM に送信されます。
3. 翻訳結果は `*_translation` テーブルに保存され、以降のリクエストで原文と共に返却されます。
4. CLI や外部ツールからも翻訳 API エンドポイントを直接呼び出すことができます。

## 設定

`config.yaml` に `translation` セクションを追加します：

```yaml
translation:
  enabled: true
  provider: openai         # ログ表示用のラベル（動作には影響しない）
  endpoint: https://api.openai.com/v1
  model: gpt-4o-mini
  api_key: sk-...          # ローカルモデルの場合は空
  max_tokens: 4096         # レスポンスの最大トークン数（デフォルト: 4096）
  temperature: 0.3         # 低い値 = より決定論的（デフォルト: 0.3）
  timeout: 120             # HTTPタイムアウト秒数（デフォルト: 120）
  # system_prompt: ""      # オプション: 組み込みの翻訳プロンプトを上書き
```

### プロバイダ設定例

#### OpenAI

```yaml
translation:
  enabled: true
  provider: openai
  endpoint: https://api.openai.com/v1
  model: gpt-4o-mini
  api_key: sk-proj-xxxxx
```

#### Ollama（ローカル LLM）

```yaml
translation:
  enabled: true
  provider: ollama
  endpoint: http://localhost:11434/v1
  model: llama3.1
  # api_key はローカル Ollama では不要
  timeout: 300  # ローカルモデルは処理が遅い場合がある
```

#### Ollama（リモートホスト / GGUF モデル）

Ollama が別のマシン（ホームサーバー等）で動作している場合は、`localhost` の代わりにホストの IP アドレスまたはホスト名を使用します。また、Ollama の `hf.co/` モデル構文で Hugging Face の GGUF モデルを直接指定できます。

```yaml
translation:
  enabled: true
  provider: ollama
  endpoint: http://192.168.1.100:11434/v1    # リモートの Ollama ホスト
  model: "hf.co/LiquidAI/LFM2-350M-ENJP-MT-GGUF:Q4_K_M"
  # api_key は Ollama では不要
  max_tokens: 4096
  temperature: 0.3
  timeout: 120
```

> [!IMPORTANT]
> `endpoint` には **ベース URL のみ** を指定してください（例: `http://host:11434/v1`）。
> `/chat/completions` を含めては**いけません** — mayu が自動的にこのパスを付加します。

> [!TIP]
> Ollama サーバーでリモート接続を受け付けるには `OLLAMA_HOST=0.0.0.0` の設定が必要です。
> デフォルトでは Ollama は `127.0.0.1` のみでリッスンします。

#### AWS Bedrock（LiteLLM プロキシ経由）

```yaml
translation:
  enabled: true
  provider: bedrock
  endpoint: http://localhost:4000/v1   # LiteLLM プロキシ
  model: anthropic.claude-3-haiku-20240307-v1:0
  api_key: sk-litellm-key
```

#### Azure OpenAI

```yaml
translation:
  enabled: true
  provider: azure
  endpoint: https://your-resource.openai.azure.com/openai/deployments/gpt-4o-mini/v1
  model: gpt-4o-mini
  api_key: your-azure-api-key
```

## 設定リファレンス

| フィールド | 型 | デフォルト | 説明 |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | 翻訳機能の有効/無効 |
| `provider` | string | `""` | ログ表示用のプロバイダ名 |
| `endpoint` | string | *必須* | OpenAI 互換 API のベース URL |
| `model` | string | *必須* | モデル識別子 |
| `api_key` | string | `""` | API キー（ローカルモデルでは空） |
| `max_tokens` | int | `4096` | レスポンスの最大トークン数 |
| `temperature` | float | `0.3` | ランダム性の制御（0.0–2.0） |
| `timeout` | int | `120` | HTTP リクエストタイムアウト（秒） |
| `system_prompt` | string | *(組み込み)* | デフォルトの翻訳システムプロンプトを上書き |

## API エンドポイント

### POST /api/v1/vulnerabilities/{id}/translate

脆弱性のテキストフィールドの翻訳をリクエストします。

**リクエストボディ:**

```json
{
  "locale": "ja"
}
```

**レスポンス (200 OK):**

```json
{
  "status": "ok",
  "vulnerability_id": "CVE-2024-1234",
  "locale": "ja",
  "fields_translated": 4
}
```

**エラーレスポンス:**

| ステータス | 条件 |
|--------|-----------|
| 400 | locale 未指定または不正な脆弱性 ID |
| 404 | 脆弱性が見つからない |
| 503 | 翻訳が未設定（`translation.enabled` が false） |
| 500 | LLM API エラーまたは DB エラー |

### CLI での使用

コマンドラインから翻訳エンドポイントを呼び出せます：

```bash
# 特定の脆弱性を日本語に翻訳
curl -X POST http://localhost:8080/api/v1/vulnerabilities/CVE-2024-1234/translate \
  -H "Content-Type: application/json" \
  -d '{"locale": "ja"}'
```

## 翻訳対象フィールド

以下のフィールドが利用可能な場合に翻訳されます：

| ソース | フィールド |
|--------|--------|
| Vulnerability (OSV) | `summary`, `details` |
| NVD | `description` |
| CISA KEV | `vulnerability_name`, `short_description`, `required_action`, `notes` |

## 仕組み

1. 脆弱性のデータベースレコードからソーステキストを取得。
2. 空でない各テキストフィールドを、サイバーセキュリティ専門の翻訳プロンプトと共に LLM に送信。
3. 翻訳結果を `*_translation` テーブルにロケールとタイムスタンプ付きで保存。
4. 以降の API リクエストで `Accept-Language: <locale>` が指定されると、レスポンスに翻訳が含まれる。
5. フロントエンドはデフォルトで翻訳を表示し、トグルで原文に切り替え可能。

## ストレージ

翻訳は別テーブルに保存されます（上流データとは混在しない）：

- `vulnerabilities_translation`
- `kev_entries_translation`
- `nvd_descriptions_translation`
- `mitre_problem_types_translation`
- `mitre_credits_translation`

この設計により、mayu が生成した翻訳と上流が提供する多言語データ（例: NVD の組み込み言語サポート）を明確に区別できます。
