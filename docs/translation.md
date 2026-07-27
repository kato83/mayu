---
title: "Translation (LLM)"
---
# Translation (LLM-based)

Mayu supports on-demand translation of vulnerability text fields (summary, details, KEV descriptions, NVD descriptions) using any OpenAI-compatible API endpoint.

## Overview

When translation is configured and enabled:

1. The web UI shows a **"Translate this page"** button on vulnerability detail pages (for non-English locale builds).
2. Clicking the button calls `POST /api/v1/vulnerabilities/{id}/translate` which sends the source text to an LLM for translation.
3. Translated text is stored in `*_translation` database tables and served alongside the original on subsequent requests.
4. The CLI and external tools can also call the translate API endpoint directly.

## Configuration

Add a `translation` section to your `config.yaml`:

```yaml
translation:
  enabled: true
  provider: openai         # Human-readable label for logs (does not affect behavior)
  endpoint: https://api.openai.com/v1
  model: gpt-4o-mini
  api_key: sk-...          # Leave empty for local models
  max_tokens: 4096         # Max response tokens (default: 4096)
  temperature: 0.3         # Lower = more deterministic (default: 0.3)
  timeout: 120             # HTTP timeout in seconds (default: 120)
  # system_prompt: ""      # Optional: override the built-in translation prompt
```

### Provider Examples

#### OpenAI

```yaml
translation:
  enabled: true
  provider: openai
  endpoint: https://api.openai.com/v1
  model: gpt-4o-mini
  api_key: sk-proj-xxxxx
```

#### Ollama (Local LLM)

```yaml
translation:
  enabled: true
  provider: ollama
  endpoint: http://localhost:11434/v1
  model: llama3.1
  # api_key not needed for local Ollama
  timeout: 300  # Local models may be slower
```

#### Ollama (Remote Host / GGUF Model)

When Ollama is running on a different machine (e.g., a home server), use the host's IP or hostname instead of `localhost`. You can also use Hugging Face GGUF models directly via Ollama's `hf.co/` model syntax.

```yaml
translation:
  enabled: true
  provider: ollama
  endpoint: http://192.168.1.100:11434/v1    # Remote Ollama host
  model: "hf.co/LiquidAI/LFM2-350M-ENJP-MT-GGUF:Q4_K_M"
  # api_key not needed for Ollama
  max_tokens: 4096
  temperature: 0.3
  timeout: 120
```

> [!IMPORTANT]
> The `endpoint` must be the **base URL only** (e.g., `http://host:11434/v1`).
> Do **not** include `/chat/completions` in the endpoint — mayu appends this path automatically.

> [!TIP]
> Ensure `OLLAMA_HOST=0.0.0.0` is set on the Ollama server to accept remote connections.
> By default, Ollama only listens on `127.0.0.1`.

#### AWS Bedrock (via LiteLLM Proxy)

```yaml
translation:
  enabled: true
  provider: bedrock
  endpoint: http://localhost:4000/v1   # LiteLLM proxy
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

## Configuration Reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable/disable translation features |
| `provider` | string | `""` | Provider name for logging (e.g., "openai", "ollama", "bedrock") |
| `endpoint` | string | *required* | Base URL of the OpenAI-compatible API |
| `model` | string | *required* | Model identifier |
| `api_key` | string | `""` | API key/token (leave empty for local models) |
| `max_tokens` | int | `4096` | Maximum response tokens |
| `temperature` | float | `0.3` | Randomness control (0.0–2.0) |
| `timeout` | int | `120` | HTTP request timeout in seconds |
| `system_prompt` | string | *(built-in)* | Override the default translation system prompt |
| `chunking.enabled` | bool | `false` | Enable text chunking for small models |
| `chunking.strategy` | string | `"auto"` | Chunking strategy: `auto`, `sentence`, or `markdown` |
| `chunking.max_chars` | int | `500` | Target maximum characters per chunk |

## Chunking (for Small/Local Models)

Small or local LLMs (e.g., models under 1B parameters) may time out or produce poor translations on long texts. The chunking feature splits input into smaller pieces before sending to the LLM.

### Configuration

```yaml
translation:
  enabled: true
  provider: ollama
  endpoint: http://192.168.1.100:11434/v1
  model: "hf.co/LiquidAI/LFM2-350M-ENJP-MT-GGUF:Q4_K_M"
  timeout: 120
  chunking:
    enabled: true
    strategy: auto     # auto | sentence | markdown
    max_chars: 500     # target max characters per chunk
```

### Strategies

| Strategy | Behavior |
|----------|----------|
| `auto` (default) | Detects if text is markdown (headings, code blocks, lists, etc.) and uses markdown splitting; otherwise falls back to sentence splitting |
| `sentence` | Always splits on sentence boundaries (`. ` followed by uppercase, paragraph breaks) |
| `markdown` | Always parses as markdown — splits on block boundaries (paragraphs, headings, list groups); fenced code blocks are preserved untranslated |

### How It Works

1. Input text is split into chunks based on the chosen strategy
2. Code blocks (` ``` `) are marked as non-translatable and passed through unchanged
3. Each translatable chunk is sent to the LLM individually (shorter input = faster response, less chance of timeout)
4. Translated chunks are reassembled in order, preserving the original document structure

### When to Use

- Your model times out on long vulnerability descriptions (details fields can be 2000+ characters)
- You're using a small model (< 1B parameters) that produces degraded output on long inputs
- You want to reduce per-request latency even at the cost of more API calls

> [!NOTE]
> Chunking increases the total number of LLM API calls (one per chunk instead of one per field).
> For cloud-hosted APIs with per-request pricing, this may increase costs. For local models, it
> trades total throughput for per-chunk reliability.

## API Endpoint

### POST /api/v1/vulnerabilities/{id}/translate

Request translation of a vulnerability's text fields.

**Request Body:**

```json
{
  "locale": "ja"
}
```

**Response (200 OK):**

```json
{
  "status": "ok",
  "vulnerability_id": "CVE-2024-1234",
  "locale": "ja",
  "fields_translated": 4
}
```

**Error Responses:**

| Status | Condition |
|--------|-----------|
| 400 | Missing locale or invalid vulnerability ID |
| 404 | Vulnerability not found |
| 503 | Translation not configured (`translation.enabled` is false) |
| 500 | LLM API error or database error |

### CLI Usage

You can call the translate endpoint from the command line:

```bash
# Translate a specific vulnerability to Japanese
curl -X POST http://localhost:8080/api/v1/vulnerabilities/CVE-2024-1234/translate \
  -H "Content-Type: application/json" \
  -d '{"locale": "ja"}'
```

## Translated Fields

The following fields are translated when available:

| Source | Fields |
|--------|--------|
| Vulnerability (OSV) | `summary`, `details` |
| NVD | `description` |
| CISA KEV | `vulnerability_name`, `short_description`, `required_action`, `notes` |

## How It Works

1. Source texts are extracted from the vulnerability's database records.
2. Each non-empty text field is sent to the configured LLM with a specialized cybersecurity translation prompt.
3. Translated results are stored in `*_translation` tables with the locale and timestamp.
4. Subsequent API requests with `Accept-Language: <locale>` include the translations in the response.
5. The frontend displays translations by default with a toggle to view the original text.

## Storage

Translations are stored in separate tables (not mixed with upstream data):

- `vulnerabilities_translation`
- `kev_entries_translation`
- `nvd_descriptions_translation`
- `osv_entries_translation`
- etc.

This design allows distinguishing mayu-generated translations from upstream-provided multilingual data (e.g., NVD's built-in language support).
