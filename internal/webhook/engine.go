package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"text/template"
	"time"

	"github.com/kato83/mayu/internal/model"
)

// WebhookEvent is the template context for rendering webhook body templates.
type WebhookEvent struct {
	// Event is the event type that triggered this webhook (e.g., "new_critical").
	Event string
	// ID is the vulnerability identifier (e.g., "CVE-2024-1234").
	ID string
	// Severity is the human-readable severity level (e.g., "CRITICAL", "HIGH").
	Severity string
	// EPSS is the Exploit Prediction Scoring System score (0.0 to 1.0).
	EPSS float64
	// LEV is the Likelihood of Exploitation in the Vulnerability score.
	LEV float64
	// Summary is a short description of the vulnerability.
	Summary string
}

// EngineOption configures the Engine.
type EngineOption func(*Engine)

// WithHTTPClient sets a custom HTTP client for webhook delivery.
func WithHTTPClient(client *http.Client) EngineOption {
	return func(e *Engine) {
		e.client = client
	}
}

// WithEngineLogger sets a custom logger for the engine.
func WithEngineLogger(logger *log.Logger) EngineOption {
	return func(e *Engine) {
		e.logger = logger
	}
}

// WithMaxRetries sets the maximum number of retry attempts.
func WithMaxRetries(n int) EngineOption {
	return func(e *Engine) {
		if n > 0 {
			e.maxRetries = n
		}
	}
}

// WithRetrySleep sets a custom sleep function for testing retry delays.
func WithRetrySleep(fn func(time.Duration)) EngineOption {
	return func(e *Engine) {
		e.sleepFn = fn
	}
}

// Engine dispatches webhook notifications.
type Engine struct {
	store      WebhookStore
	client     *http.Client
	logger     *log.Logger
	maxRetries int
	sleepFn    func(time.Duration)
}

// NewEngine creates a new webhook dispatch engine.
func NewEngine(store WebhookStore, opts ...EngineOption) *Engine {
	e := &Engine{
		store:      store,
		client:     &http.Client{Timeout: 10 * time.Second},
		logger:     log.Default(),
		maxRetries: 3,
		sleepFn:    time.Sleep,
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// Dispatch sends webhook notifications for the given event and data items.
// It retrieves all enabled webhooks matching the event (including wildcard),
// renders the body template for each data item, and delivers them.
func (e *Engine) Dispatch(ctx context.Context, event string, data []WebhookEvent) {
	if len(data) == 0 {
		return
	}

	webhooks, err := e.store.GetWebhooksByEvent(ctx, event)
	if err != nil {
		e.logger.Printf("webhook: failed to get webhooks for event %q: %v", event, err)
		return
	}

	for _, wh := range webhooks {
		tmpl, err := template.New("body").Parse(wh.BodyTemplate)
		if err != nil {
			e.logger.Printf("webhook: failed to parse template for webhook %q: %v", wh.Name, err)
			continue
		}

		for _, item := range data {
			var body bytes.Buffer
			if err := tmpl.Execute(&body, item); err != nil {
				e.logger.Printf("webhook: failed to render template for webhook %q, item %s: %v", wh.Name, item.ID, err)
				continue
			}

			e.deliver(ctx, wh, event, body.Bytes())
		}
	}
}

// deliver sends a single webhook delivery with retry logic.
func (e *Engine) deliver(ctx context.Context, wh *model.Webhook, event string, payload []byte) {
	retryDelays := getRetryDelays()

	for attempt := 1; attempt <= e.maxRetries; attempt++ {
		start := time.Now()
		status, respBody, err := e.sendRequest(ctx, wh, payload)
		duration := time.Since(start)
		durationMs := int(duration.Milliseconds())

		dl := &model.WebhookDeliveryLog{
			WebhookID:   wh.ID,
			Event:       event,
			Payload:     string(payload),
			Attempt:     attempt,
			DeliveredAt: start,
			DurationMs:  &durationMs,
		}

		if err != nil {
			errMsg := err.Error()
			dl.ErrorMessage = &errMsg
		} else {
			dl.ResponseStatus = &status
			if respBody != "" {
				dl.ResponseBody = &respBody
			}
		}

		if logErr := e.store.CreateDeliveryLog(ctx, dl); logErr != nil {
			e.logger.Printf("webhook: failed to create delivery log: %v", logErr)
		}

		// Determine if delivery succeeded
		if err == nil && status >= 200 && status < 300 {
			return // success
		}

		// Do not retry on 4xx client errors
		if err == nil && status >= 400 && status < 500 {
			e.logger.Printf("webhook: delivery to %q failed with %d (not retrying)", wh.Name, status)
			return
		}

		// Retry on 5xx or connection errors
		if attempt < e.maxRetries {
			delay := retryDelays[attempt-1]
			e.logger.Printf("webhook: delivery to %q failed (attempt %d/%d), retrying in %s", wh.Name, attempt, e.maxRetries, delay)
			e.sleepFn(delay)
		} else {
			e.logger.Printf("webhook: delivery to %q failed after %d attempts", wh.Name, e.maxRetries)
		}
	}
}

// sendRequest performs the actual HTTP POST to the webhook URL.
func (e *Engine) sendRequest(ctx context.Context, wh *model.Webhook, payload []byte) (status int, respBody string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, wh.URL, bytes.NewReader(payload))
	if err != nil {
		return 0, "", fmt.Errorf("create request: %w", err)
	}

	contentType := wh.ContentType
	if contentType == "" {
		contentType = "application/json"
	}
	req.Header.Set("Content-Type", contentType)

	if wh.Secret != "" {
		sig := computeHMACSHA256(payload, []byte(wh.Secret))
		req.Header.Set("X-Webhook-Signature", sig)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Read response body (limited to 1KB to prevent memory issues)
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return resp.StatusCode, string(bodyBytes), nil
}

// computeHMACSHA256 computes the HMAC-SHA256 signature of the data using the given key.
func computeHMACSHA256(data, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// NotifyNewVulnerabilities determines event types based on severity and dispatches webhooks.
// The summaryLookup function returns a map of vulnerability ID to severity level (1-5).
func (e *Engine) NotifyNewVulnerabilities(ctx context.Context, vulnIDs []string, summaryLookup func(ctx context.Context, ids []string) (map[string]int, error)) {
	if len(vulnIDs) == 0 {
		return
	}

	severities, err := summaryLookup(ctx, vulnIDs)
	if err != nil {
		e.logger.Printf("webhook: failed to look up severities: %v", err)
		return
	}

	// Group events by type
	eventData := map[string][]WebhookEvent{
		"new_vulnerability": {},
	}

	for _, id := range vulnIDs {
		sev, ok := severities[id]
		if !ok {
			continue
		}

		sevName := severityName(sev)
		evt := WebhookEvent{
			ID:       id,
			Severity: sevName,
		}

		// All vulnerabilities fire new_vulnerability
		evt.Event = "new_vulnerability"
		eventData["new_vulnerability"] = append(eventData["new_vulnerability"], evt)

		// Severity-specific events
		if sev == 5 {
			critEvt := evt
			critEvt.Event = "new_critical"
			eventData["new_critical"] = append(eventData["new_critical"], critEvt)
		}
		if sev == 4 {
			highEvt := evt
			highEvt.Event = "new_high"
			eventData["new_high"] = append(eventData["new_high"], highEvt)
		}
	}

	// Dispatch each event type
	for event, data := range eventData {
		if len(data) > 0 {
			e.Dispatch(ctx, event, data)
		}
	}

	// Prune old delivery logs (best-effort, keep 1000 per webhook)
	if err := e.store.PruneDeliveryLogs(ctx, 1000); err != nil {
		e.logger.Printf("webhook: failed to prune delivery logs: %v", err)
	}
}

// severityName converts a numeric severity level to a human-readable string.
func severityName(level int) string {
	switch level {
	case 5:
		return "CRITICAL"
	case 4:
		return "HIGH"
	case 3:
		return "MEDIUM"
	case 2:
		return "LOW"
	case 1:
		return "NONE"
	default:
		return "UNKNOWN"
	}
}
