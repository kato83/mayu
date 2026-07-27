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
- `mitre_problem_types_translation`
- `mitre_credits_translation`

This design allows distinguishing mayu-generated translations from upstream-provided multilingual data (e.g., NVD's built-in language support).
