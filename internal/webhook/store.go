// Package webhook provides the webhook notification system for mayu.
// It handles CRUD operations for webhook configurations, dispatches HTTP POST
// notifications with template-based payload rendering, and records delivery logs.
package webhook

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/kato83/mayu/internal/model"
)

// WebhookStore defines the interface for webhook data persistence.
type WebhookStore interface {
	// CreateWebhook inserts a new webhook configuration.
	CreateWebhook(ctx context.Context, w *model.Webhook) (*model.Webhook, error)
	// UpdateWebhook updates an existing webhook configuration.
	UpdateWebhook(ctx context.Context, w *model.Webhook) (*model.Webhook, error)
	// DeleteWebhook removes a webhook by ID.
	DeleteWebhook(ctx context.Context, id int64) error
	// GetWebhook retrieves a single webhook by ID.
	GetWebhook(ctx context.Context, id int64) (*model.Webhook, error)
	// ListWebhooks returns all webhooks ordered by ID.
	ListWebhooks(ctx context.Context) ([]*model.Webhook, error)
	// GetWebhooksByEvent returns all enabled webhooks that match the given event.
	// It includes webhooks registered for the specific event or the wildcard '*'.
	GetWebhooksByEvent(ctx context.Context, event string) ([]*model.Webhook, error)
	// CreateDeliveryLog records a webhook delivery attempt.
	CreateDeliveryLog(ctx context.Context, log *model.WebhookDeliveryLog) error
	// ListDeliveryLogs returns delivery logs for a webhook, ordered by most recent first.
	ListDeliveryLogs(ctx context.Context, webhookID int64, limit int) ([]*model.WebhookDeliveryLog, error)
	// PruneDeliveryLogs removes old delivery logs, keeping only the most recent N per webhook.
	PruneDeliveryLogs(ctx context.Context, keepPerWebhook int) error
}

// PostgresWebhookStore implements WebhookStore using database/sql with the pgx stdlib driver.
type PostgresWebhookStore struct {
	db *sql.DB
}

// NewPostgresWebhookStore creates a new PostgresWebhookStore with the given database connection.
func NewPostgresWebhookStore(db *sql.DB) *PostgresWebhookStore {
	return &PostgresWebhookStore{db: db}
}

// CreateWebhook inserts a new webhook and returns the created record.
func (s *PostgresWebhookStore) CreateWebhook(ctx context.Context, w *model.Webhook) (*model.Webhook, error) {
	var result model.Webhook
	var secret sql.NullString
	if w.Secret != "" {
		secret = sql.NullString{String: w.Secret, Valid: true}
	}

	err := s.db.QueryRowContext(ctx, `
		INSERT INTO webhooks (name, url, events, content_type, body_template, secret, enabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, name, url, events, content_type, body_template, secret, enabled, created_at, updated_at`,
		w.Name, w.URL, pgTextArray(w.Events), w.ContentType, w.BodyTemplate, secret, w.Enabled,
	).Scan(
		&result.ID, &result.Name, &result.URL, &eventScanner{&result.Events},
		&result.ContentType, &result.BodyTemplate, &secret,
		&result.Enabled, &result.CreatedAt, &result.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("insert webhook: %w", err)
	}
	if secret.Valid {
		result.Secret = secret.String
	}
	return &result, nil
}

// UpdateWebhook updates an existing webhook and returns the updated record.
func (s *PostgresWebhookStore) UpdateWebhook(ctx context.Context, w *model.Webhook) (*model.Webhook, error) {
	var result model.Webhook
	var secret sql.NullString
	if w.Secret != "" {
		secret = sql.NullString{String: w.Secret, Valid: true}
	}

	err := s.db.QueryRowContext(ctx, `
		UPDATE webhooks
		SET name = $2, url = $3, events = $4, content_type = $5,
		    body_template = $6, secret = $7, enabled = $8, updated_at = NOW()
		WHERE id = $1
		RETURNING id, name, url, events, content_type, body_template, secret, enabled, created_at, updated_at`,
		w.ID, w.Name, w.URL, pgTextArray(w.Events), w.ContentType, w.BodyTemplate, secret, w.Enabled,
	).Scan(
		&result.ID, &result.Name, &result.URL, &eventScanner{&result.Events},
		&result.ContentType, &result.BodyTemplate, &secret,
		&result.Enabled, &result.CreatedAt, &result.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("webhook not found: id=%d", w.ID)
		}
		return nil, fmt.Errorf("update webhook: %w", err)
	}
	if secret.Valid {
		result.Secret = secret.String
	}
	return &result, nil
}

// DeleteWebhook removes a webhook by ID.
func (s *PostgresWebhookStore) DeleteWebhook(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM webhooks WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete webhook %d: %w", id, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete webhook %d rows affected: %w", id, err)
	}
	if rows == 0 {
		return fmt.Errorf("webhook not found: id=%d", id)
	}
	return nil
}

// GetWebhook retrieves a single webhook by ID.
func (s *PostgresWebhookStore) GetWebhook(ctx context.Context, id int64) (*model.Webhook, error) {
	var w model.Webhook
	var secret sql.NullString

	err := s.db.QueryRowContext(ctx, `
		SELECT id, name, url, events, content_type, body_template, secret, enabled, created_at, updated_at
		FROM webhooks
		WHERE id = $1`, id,
	).Scan(
		&w.ID, &w.Name, &w.URL, &eventScanner{&w.Events},
		&w.ContentType, &w.BodyTemplate, &secret,
		&w.Enabled, &w.CreatedAt, &w.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get webhook %d: %w", id, err)
	}
	if secret.Valid {
		w.Secret = secret.String
	}
	return &w, nil
}

// ListWebhooks returns all webhooks ordered by ID.
func (s *PostgresWebhookStore) ListWebhooks(ctx context.Context) ([]*model.Webhook, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, url, events, content_type, body_template, secret, enabled, created_at, updated_at
		FROM webhooks
		ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list webhooks: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var webhooks []*model.Webhook
	for rows.Next() {
		var w model.Webhook
		var secret sql.NullString
		if err := rows.Scan(
			&w.ID, &w.Name, &w.URL, &eventScanner{&w.Events},
			&w.ContentType, &w.BodyTemplate, &secret,
			&w.Enabled, &w.CreatedAt, &w.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan webhook: %w", err)
		}
		if secret.Valid {
			w.Secret = secret.String
		}
		webhooks = append(webhooks, &w)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate webhooks: %w", err)
	}
	return webhooks, nil
}

// GetWebhooksByEvent returns all enabled webhooks matching the given event or wildcard '*'.
func (s *PostgresWebhookStore) GetWebhooksByEvent(ctx context.Context, event string) ([]*model.Webhook, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, url, events, content_type, body_template, secret, enabled, created_at, updated_at
		FROM webhooks
		WHERE enabled = true AND ($1 = ANY(events) OR '*' = ANY(events))
		ORDER BY id`, event,
	)
	if err != nil {
		return nil, fmt.Errorf("get webhooks by event %q: %w", event, err)
	}
	defer func() { _ = rows.Close() }()

	var webhooks []*model.Webhook
	for rows.Next() {
		var w model.Webhook
		var secret sql.NullString
		if err := rows.Scan(
			&w.ID, &w.Name, &w.URL, &eventScanner{&w.Events},
			&w.ContentType, &w.BodyTemplate, &secret,
			&w.Enabled, &w.CreatedAt, &w.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan webhook: %w", err)
		}
		if secret.Valid {
			w.Secret = secret.String
		}
		webhooks = append(webhooks, &w)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate webhooks by event: %w", err)
	}
	return webhooks, nil
}

// CreateDeliveryLog records a webhook delivery attempt.
func (s *PostgresWebhookStore) CreateDeliveryLog(ctx context.Context, dl *model.WebhookDeliveryLog) error {
	var deliveredAt interface{}
	if !dl.DeliveredAt.IsZero() {
		deliveredAt = dl.DeliveredAt
	} else {
		deliveredAt = time.Now()
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO webhook_delivery_logs (webhook_id, event, payload, response_status, response_body, error_message, attempt, delivered_at, duration_ms)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		dl.WebhookID, dl.Event, nullIfEmpty(dl.Payload),
		dl.ResponseStatus, dl.ResponseBody, dl.ErrorMessage,
		dl.Attempt, deliveredAt, dl.DurationMs,
	)
	if err != nil {
		return fmt.Errorf("insert delivery log: %w", err)
	}
	return nil
}

// ListDeliveryLogs returns delivery logs for a webhook, ordered by most recent first.
func (s *PostgresWebhookStore) ListDeliveryLogs(ctx context.Context, webhookID int64, limit int) ([]*model.WebhookDeliveryLog, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, webhook_id, event, payload, response_status, response_body, error_message, attempt, delivered_at, duration_ms
		FROM webhook_delivery_logs
		WHERE webhook_id = $1
		ORDER BY delivered_at DESC
		LIMIT $2`, webhookID, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list delivery logs for webhook %d: %w", webhookID, err)
	}
	defer func() { _ = rows.Close() }()

	var logs []*model.WebhookDeliveryLog
	for rows.Next() {
		var dl model.WebhookDeliveryLog
		var payload sql.NullString
		if err := rows.Scan(
			&dl.ID, &dl.WebhookID, &dl.Event, &payload,
			&dl.ResponseStatus, &dl.ResponseBody, &dl.ErrorMessage,
			&dl.Attempt, &dl.DeliveredAt, &dl.DurationMs,
		); err != nil {
			return nil, fmt.Errorf("scan delivery log: %w", err)
		}
		if payload.Valid {
			dl.Payload = payload.String
		}
		logs = append(logs, &dl)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate delivery logs: %w", err)
	}
	return logs, nil
}

// pgTextArray converts a Go string slice for use as a PostgreSQL TEXT[] parameter.
// pgx stdlib natively supports []string -> TEXT[] conversion, so we pass it directly.
// Returns nil for empty/nil slices (stored as NULL in PostgreSQL).
func pgTextArray(ss []string) interface{} {
	if len(ss) == 0 {
		return nil
	}
	return ss
}

// nullIfEmpty returns nil for empty strings, otherwise the string value.
func nullIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// eventScanner implements sql.Scanner for PostgreSQL TEXT[] columns.
type eventScanner struct {
	dest *[]string
}

// Scan implements the sql.Scanner interface for TEXT[] arrays.
func (es *eventScanner) Scan(src interface{}) error {
	if src == nil {
		*es.dest = nil
		return nil
	}
	switch v := src.(type) {
	case []byte:
		*es.dest = parseTextArray(string(v))
	case string:
		*es.dest = parseTextArray(v)
	default:
		return fmt.Errorf("eventScanner: unsupported type %T", src)
	}
	return nil
}

// parseTextArray parses a PostgreSQL TEXT[] literal (e.g., "{foo,bar}") into a Go string slice.
func parseTextArray(s string) []string {
	if s == "" || s == "{}" {
		return nil
	}
	// Strip surrounding braces
	s = s[1 : len(s)-1]
	if s == "" {
		return nil
	}

	var result []string
	var current []byte
	inQuote := false
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '"' && !inQuote:
			inQuote = true
		case s[i] == '"' && inQuote:
			inQuote = false
		case s[i] == ',' && !inQuote:
			result = append(result, string(current))
			current = current[:0]
		case s[i] == '\\' && inQuote && i+1 < len(s):
			i++
			current = append(current, s[i])
		default:
			current = append(current, s[i])
		}
	}
	if len(current) > 0 {
		result = append(result, string(current))
	}
	return result
}

// PruneDeliveryLogs removes old delivery logs, keeping only the most recent N per webhook.
func (s *PostgresWebhookStore) PruneDeliveryLogs(ctx context.Context, keepPerWebhook int) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM webhook_delivery_logs
		WHERE id NOT IN (
			SELECT id FROM (
				SELECT id, ROW_NUMBER() OVER (PARTITION BY webhook_id ORDER BY delivered_at DESC) AS rn
				FROM webhook_delivery_logs
			) ranked
			WHERE rn <= $1
		)`, keepPerWebhook)
	if err != nil {
		return fmt.Errorf("prune delivery logs: %w", err)
	}
	return nil
}
