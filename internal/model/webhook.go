package model

import "time"

// Webhook represents a row in the webhooks table.
// It defines an HTTP POST notification endpoint with template-based payload formatting.
type Webhook struct {
	ID           int64
	Name         string
	URL          string
	Events       []string
	ContentType  string
	BodyTemplate string
	Secret       string
	Enabled      bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// WebhookDeliveryLog represents a row in the webhook_delivery_logs table.
// It records the result of a single webhook delivery attempt.
type WebhookDeliveryLog struct {
	ID             int64
	WebhookID      int64
	Event          string
	Payload        string
	ResponseStatus *int
	ResponseBody   *string
	ErrorMessage   *string
	Attempt        int
	DeliveredAt    time.Time
	DurationMs     *int
}
