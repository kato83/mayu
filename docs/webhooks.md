---
title: "Webhooks"
---
# Webhooks

Mayu can send HTTP POST notifications when new vulnerabilities are ingested. This document describes how to configure webhooks, available events, and template variables.

## Overview

Webhooks are triggered after vulnerability data is ingested. When new vulnerabilities are found, Mayu dispatches POST requests to all registered webhook URLs that match the event type.

Key features:
- [Mustache](https://mustache.github.io/) template syntax for flexible payload formatting
- HMAC-SHA256 signature verification (`X-Webhook-Signature` header)
- Automatic retry with exponential backoff (3 attempts: 1s → 5s → 30s)
- Wildcard event subscription (`*`)
- Delivery logs for debugging

## Configuration

Webhooks can be configured via **YAML config file** or **CLI commands**.

### YAML Configuration

```yaml
webhooks:
  - name: "security-team-slack"
    url: "https://hooks.slack.com/services/T00/B00/xxxx"
    events: ["new_critical", "new_high"]
    content_type: "application/json"
    body_template: |
      {"text": "🚨 {{ID}} ({{Severity}}) - {{Summary}}"}

  - name: "all-vulns"
    url: "https://example.com/api/webhook"
    events: ["*"]
    content_type: "application/json"
    secret: "my-shared-secret"
    body_template: |
      {
        "event": "{{Event}}",
        "vulnerability": {
          "id": "{{ID}}",
          "severity": "{{Severity}}",
          "epss": {{EPSS}},
          "lev": {{LEV}},
          "summary": "{{Summary}}"
        }
      }
```

### CLI Commands

```bash
# Create a webhook
mayu webhook create \
  --name "slack-alerts" \
  --url "https://hooks.slack.com/services/T00/B00/xxxx" \
  --events "new_critical,new_high" \
  --body-template '{"text": "{{ID}} ({{Severity}}) - {{Summary}}"}' \
  --secret "optional-hmac-secret"

# List all webhooks
mayu webhook list

# Test a webhook (sends a sample payload)
mayu webhook test --id 1
```

## Events

| Event | Description |
|-------|-------------|
| `new_vulnerability` | Fired for every newly ingested vulnerability, regardless of severity. |
| `new_critical` | Fired when a vulnerability with CRITICAL severity (level 5) is ingested. |
| `new_high` | Fired when a vulnerability with HIGH severity (level 4) is ingested. |
| `*` | Wildcard — matches all event types. |

> **Note:** A single vulnerability may trigger multiple events. For example, a CRITICAL vulnerability triggers both `new_vulnerability` and `new_critical`. If a webhook subscribes to `*`, it receives all events.

### Severity Levels

| Level | Name | CVSS Score Range |
|-------|------|-----------------|
| 5 | CRITICAL | 9.0 – 10.0 |
| 4 | HIGH | 7.0 – 8.9 |
| 3 | MEDIUM | 4.0 – 6.9 |
| 2 | LOW | 0.1 – 3.9 |
| 1 | NONE | 0.0 |

## Template Variables

The `body_template` field uses [Mustache](https://mustache.github.io/) template syntax. The following variables are available in the template context:

| Variable | Type | Description | Example Value |
|----------|------|-------------|---------------|
| `{{Event}}` | string | The event type that triggered this webhook. | `"new_critical"` |
| `{{ID}}` | string | The vulnerability identifier. | `"CVE-2024-1234"` |
| `{{Severity}}` | string | Human-readable severity level. | `"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, `"LOW"`, `"NONE"` |
| `{{EPSS}}` | float64 | EPSS score (0.0 to 1.0). Exploit Prediction Scoring System probability. | `0.94218` |
| `{{LEV}}` | float64 | LEV score (0.0 to 1.0). Likely Exploited Vulnerability probability. | `0.85` |
| `{{Summary}}` | string | Short description of the vulnerability. | `"Remote code execution in ..."` |

> **Note:** `{{EPSS}}` and `{{LEV}}` are numeric values (float64). When used inside a JSON string, they do **not** need quotes. When used in a text context, they render as decimal numbers (e.g., `0.94218`).

### Template Examples

**Slack Incoming Webhook:**

```
{"text": "🚨 {{ID}} ({{Severity}}) - {{Summary}}"}
```

**Microsoft Teams:**

```json
{
  "@type": "MessageCard",
  "summary": "New Vulnerability: {{ID}}",
  "sections": [{
    "activityTitle": "{{ID}} — {{Severity}}",
    "facts": [
      {"name": "EPSS", "value": "{{EPSS}}"},
      {"name": "LEV", "value": "{{LEV}}"}
    ],
    "text": "{{Summary}}"
  }]
}
```

**Generic JSON:**

```json
{
  "event": "{{Event}}",
  "id": "{{ID}}",
  "severity": "{{Severity}}",
  "epss": {{EPSS}},
  "lev": {{LEV}},
  "summary": "{{Summary}}"
}
```

**Plain text (for email gateways, etc.):**

```
[{{Severity}}] {{ID}}: {{Summary}} (EPSS: {{EPSS}})
```

### Sections (Conditional Blocks)

Mustache supports sections for conditional rendering. A section begins with `{{#variable}}` and ends with `{{/variable}}`. The block is rendered only when the variable is truthy (non-zero, non-empty):

```
{
  "id": "{{ID}}",
  "severity": "{{Severity}}"{{#EPSS}},
  "epss": {{EPSS}}{{/EPSS}}
}
```

> **Note:** Mustache is a logic-less template engine. Complex conditionals (e.g., numeric comparisons) are not supported. For advanced transformations, use an intermediary service between Mayu and your destination.

## Signature Verification

When a `secret` is configured, Mayu includes an HMAC-SHA256 signature in the `X-Webhook-Signature` header:

```
X-Webhook-Signature: sha256=<hex-encoded HMAC-SHA256 of the request body>
```

### Verification Example (Go)

```go
func verifySignature(body []byte, secret, signature string) bool {
    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write(body)
    expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
    return hmac.Equal([]byte(expected), []byte(signature))
}
```

### Verification Example (Python)

```python
import hmac
import hashlib

def verify_signature(body: bytes, secret: str, signature: str) -> bool:
    expected = "sha256=" + hmac.new(
        secret.encode(), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)
```

## Delivery Behavior

| Aspect | Detail |
|--------|--------|
| HTTP Method | POST |
| Content-Type | Configurable (default: `application/json`) |
| Timeout | 10 seconds per request |
| Max Retries | 3 attempts total |
| Retry Delays | 1s → 5s → 30s (exponential backoff) |
| Retry Condition | 5xx responses or connection errors |
| No Retry | 2xx (success) or 4xx (client error) |
| Response Body Limit | 1 KB (for logging purposes) |
| Delivery Logs | Stored per webhook (last 1000 entries per webhook) |

## Testing

Use `mayu webhook test --id <webhook-id>` to send a test payload. The test uses these sample values:

| Variable | Test Value |
|----------|-----------|
| `{{Event}}` | `"test"` |
| `{{ID}}` | `"CVE-0000-0000"` |
| `{{Severity}}` | `"MEDIUM"` |
| `{{EPSS}}` | `0.5` |
| `{{LEV}}` | `0.3` |
| `{{Summary}}` | `"Test webhook delivery"` |

## Delivery Logs

Webhook delivery attempts are recorded and can be viewed via the API:

```bash
curl http://localhost:8080/api/v1/webhooks/1/deliveries
```

Each log entry contains:
- Event type
- Rendered payload
- Response status code
- Response body (first 1 KB)
- Error message (if delivery failed)
- Attempt number
- Duration (ms)
