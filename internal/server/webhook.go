package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/cbroglie/mustache"
	"github.com/go-chi/chi/v5"
	"github.com/kato83/mayu/internal/auth"
	"github.com/kato83/mayu/internal/model"
	"github.com/kato83/mayu/internal/webhook"
)

// webhookRequest is the JSON request body for creating/updating a webhook.
type webhookRequest struct {
	Name         string   `json:"name"`
	URL          string   `json:"url"`
	Events       []string `json:"events"`
	ContentType  string   `json:"content_type"`
	BodyTemplate string   `json:"body_template"`
	Secret       string   `json:"secret"`
	Enabled      *bool    `json:"enabled"`
}

// webhookResponse is the JSON response for a webhook.
type webhookResponse struct {
	ID           int64    `json:"id"`
	Name         string   `json:"name"`
	URL          string   `json:"url"`
	Events       []string `json:"events"`
	ContentType  string   `json:"content_type"`
	BodyTemplate string   `json:"body_template"`
	Secret       string   `json:"secret,omitempty"`
	Enabled      bool     `json:"enabled"`
	CreatedAt    string   `json:"created_at"`
	UpdatedAt    string   `json:"updated_at"`
}

// deliveryLogResponse is the JSON response for a delivery log entry.
type deliveryLogResponse struct {
	ID             int64   `json:"id"`
	WebhookID      int64   `json:"webhook_id"`
	Event          string  `json:"event"`
	Payload        string  `json:"payload,omitempty"`
	ResponseStatus *int    `json:"response_status,omitempty"`
	ResponseBody   *string `json:"response_body,omitempty"`
	ErrorMessage   *string `json:"error_message,omitempty"`
	Attempt        int     `json:"attempt"`
	DeliveredAt    string  `json:"delivered_at"`
	DurationMs     *int    `json:"duration_ms,omitempty"`
}

// testWebhookResponse is the JSON response for a webhook test.
type testWebhookResponse struct {
	Success      bool   `json:"success"`
	StatusCode   int    `json:"status_code,omitempty"`
	ResponseBody string `json:"response_body,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
	DurationMs   int    `json:"duration_ms"`
	RenderedBody string `json:"rendered_body,omitempty"`
}

func toWebhookResponse(w *model.Webhook) webhookResponse {
	return webhookResponse{
		ID:           w.ID,
		Name:         w.Name,
		URL:          w.URL,
		Events:       w.Events,
		ContentType:  w.ContentType,
		BodyTemplate: w.BodyTemplate,
		Enabled:      w.Enabled,
		CreatedAt:    w.CreatedAt.Format(time.RFC3339),
		UpdatedAt:    w.UpdatedAt.Format(time.RFC3339),
	}
}

func toDeliveryLogResponse(dl *model.WebhookDeliveryLog) deliveryLogResponse {
	return deliveryLogResponse{
		ID:             dl.ID,
		WebhookID:      dl.WebhookID,
		Event:          dl.Event,
		Payload:        dl.Payload,
		ResponseStatus: dl.ResponseStatus,
		ResponseBody:   dl.ResponseBody,
		ErrorMessage:   dl.ErrorMessage,
		Attempt:        dl.Attempt,
		DeliveredAt:    dl.DeliveredAt.Format(time.RFC3339),
		DurationMs:     dl.DurationMs,
	}
}

// validateWebhookURL checks that the URL has an http or https scheme.
func validateWebhookURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("url must use http or https scheme")
	}
	if u.Host == "" {
		return fmt.Errorf("url must have a host")
	}
	return nil
}

// handleCreateWebhook handles POST /api/v1/webhooks
func (s *Server) handleCreateWebhook(w http.ResponseWriter, r *http.Request) {
	var req webhookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.URL == "" {
		writeError(w, http.StatusBadRequest, "url is required")
		return
	}
	if err := validateWebhookURL(req.URL); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.Events) == 0 {
		writeError(w, http.StatusBadRequest, "events is required")
		return
	}

	contentType := req.ContentType
	if contentType == "" {
		contentType = "application/json"
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	wh := &model.Webhook{
		Name:         req.Name,
		URL:          req.URL,
		Events:       req.Events,
		ContentType:  contentType,
		BodyTemplate: req.BodyTemplate,
		Secret:       req.Secret,
		Enabled:      enabled,
	}

	// Set user_id from authenticated user
	user := auth.UserFromContext(r.Context())
	if user != nil {
		wh.UserID = &user.ID
	}

	created, err := s.webhookStore.CreateWebhook(r.Context(), wh)
	if err != nil {
		slog.Error("failed to create webhook", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to create webhook")
		return
	}

	writeJSON(w, http.StatusCreated, toWebhookResponse(created))
}

// handleListWebhooks handles GET /api/v1/webhooks
func (s *Server) handleListWebhooks(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())

	var webhooks []*model.Webhook
	var err error

	// Admins see all webhooks; regular users see only their own
	if user != nil && user.Role == auth.RoleAdmin {
		webhooks, err = s.webhookStore.ListWebhooks(r.Context())
	} else if user != nil {
		webhooks, err = s.webhookStore.ListWebhooksByUser(r.Context(), user.ID)
	} else {
		webhooks, err = s.webhookStore.ListWebhooks(r.Context())
	}

	if err != nil {
		slog.Error("failed to list webhooks", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to list webhooks")
		return
	}

	resp := make([]webhookResponse, 0, len(webhooks))
	for _, wh := range webhooks {
		resp = append(resp, toWebhookResponse(wh))
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleGetWebhook handles GET /api/v1/webhooks/{id}
func (s *Server) handleGetWebhook(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid webhook ID")
		return
	}

	wh, err := s.webhookStore.GetWebhook(r.Context(), id)
	if err != nil {
		slog.Error("failed to get webhook", "id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get webhook")
		return
	}
	if wh == nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("webhook %d not found", id))
		return
	}

	// Non-admin users can only access their own webhooks
	user := auth.UserFromContext(r.Context())
	if user != nil && user.Role != auth.RoleAdmin {
		if wh.UserID == nil || *wh.UserID != user.ID {
			writeError(w, http.StatusNotFound, fmt.Sprintf("webhook %d not found", id))
			return
		}
	}

	writeJSON(w, http.StatusOK, toWebhookResponse(wh))
}

// handleUpdateWebhook handles PUT /api/v1/webhooks/{id}
func (s *Server) handleUpdateWebhook(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid webhook ID")
		return
	}

	// Verify ownership for non-admin users
	user := auth.UserFromContext(r.Context())
	if user != nil && user.Role != auth.RoleAdmin {
		existing, err := s.webhookStore.GetWebhook(r.Context(), id)
		if err != nil {
			slog.Error("failed to get webhook for ownership check", "id", id, "error", err)
			writeError(w, http.StatusInternalServerError, "failed to update webhook")
			return
		}
		if existing == nil || existing.UserID == nil || *existing.UserID != user.ID {
			writeError(w, http.StatusNotFound, fmt.Sprintf("webhook %d not found", id))
			return
		}
	}

	var req webhookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.URL == "" {
		writeError(w, http.StatusBadRequest, "url is required")
		return
	}
	if err := validateWebhookURL(req.URL); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.Events) == 0 {
		writeError(w, http.StatusBadRequest, "events is required")
		return
	}

	contentType := req.ContentType
	if contentType == "" {
		contentType = "application/json"
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	wh := &model.Webhook{
		ID:           id,
		Name:         req.Name,
		URL:          req.URL,
		Events:       req.Events,
		ContentType:  contentType,
		BodyTemplate: req.BodyTemplate,
		Secret:       req.Secret,
		Enabled:      enabled,
	}

	// Preserve user_id ownership
	if user != nil && user.Role != auth.RoleAdmin {
		wh.UserID = &user.ID
	}

	updated, err := s.webhookStore.UpdateWebhook(r.Context(), wh)
	if err != nil {
		slog.Error("failed to update webhook", "id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "failed to update webhook")
		return
	}

	writeJSON(w, http.StatusOK, toWebhookResponse(updated))
}

// handleDeleteWebhook handles DELETE /api/v1/webhooks/{id}
func (s *Server) handleDeleteWebhook(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid webhook ID")
		return
	}

	// Verify ownership for non-admin users
	user := auth.UserFromContext(r.Context())
	if user != nil && user.Role != auth.RoleAdmin {
		existing, err := s.webhookStore.GetWebhook(r.Context(), id)
		if err != nil {
			slog.Error("failed to get webhook for ownership check", "id", id, "error", err)
			writeError(w, http.StatusInternalServerError, "failed to delete webhook")
			return
		}
		if existing == nil || existing.UserID == nil || *existing.UserID != user.ID {
			writeError(w, http.StatusNotFound, fmt.Sprintf("webhook %d not found", id))
			return
		}
	}

	if err := s.webhookStore.DeleteWebhook(r.Context(), id); err != nil {
		slog.Error("failed to delete webhook", "id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "failed to delete webhook")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "webhook deleted"})
}

// handleListWebhookDeliveries handles GET /api/v1/webhooks/{id}/deliveries
func (s *Server) handleListWebhookDeliveries(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid webhook ID")
		return
	}

	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		parsed, err := strconv.Atoi(l)
		if err != nil || parsed < 1 {
			writeError(w, http.StatusBadRequest, "invalid limit parameter")
			return
		}
		if parsed > 1000 {
			parsed = 1000
		}
		limit = parsed
	}

	logs, err := s.webhookStore.ListDeliveryLogs(r.Context(), id, limit)
	if err != nil {
		slog.Error("failed to list delivery logs", "webhook_id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "failed to list delivery logs")
		return
	}

	resp := make([]deliveryLogResponse, 0, len(logs))
	for _, dl := range logs {
		resp = append(resp, toDeliveryLogResponse(dl))
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleTestWebhook handles POST /api/v1/webhooks/{id}/test
func (s *Server) handleTestWebhook(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid webhook ID")
		return
	}

	wh, err := s.webhookStore.GetWebhook(r.Context(), id)
	if err != nil {
		slog.Error("failed to get webhook for test", "id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get webhook")
		return
	}
	if wh == nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("webhook %d not found", id))
		return
	}

	// Render the body template with sample data
	sampleEvent := webhook.WebhookEvent{
		Event:    "test",
		ID:       "CVE-0000-0000",
		Severity: "MEDIUM",
		EPSS:     0.5,
		LEV:      0.3,
		Summary:  "Test webhook delivery",
	}

	rendered, err := mustache.Render(wh.BodyTemplate, sampleEvent)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid body template: %v", err))
		return
	}

	renderedBody := rendered

	// Send the actual HTTP POST
	start := time.Now()
	req2, err := http.NewRequestWithContext(r.Context(), http.MethodPost, wh.URL, bytes.NewReader([]byte(rendered)))
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("failed to create request: %v", err))
		return
	}

	contentType := wh.ContentType
	if contentType == "" {
		contentType = "application/json"
	}
	req2.Header.Set("Content-Type", contentType)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req2)
	duration := time.Since(start)
	durationMs := int(duration.Milliseconds())

	if err != nil {
		writeJSON(w, http.StatusOK, testWebhookResponse{
			Success:      false,
			ErrorMessage: err.Error(),
			DurationMs:   durationMs,
			RenderedBody: renderedBody,
		})
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// Read limited response body
	var respBody bytes.Buffer
	_, _ = respBody.ReadFrom(http.MaxBytesReader(nil, resp.Body, 1024))

	success := resp.StatusCode >= 200 && resp.StatusCode < 300
	writeJSON(w, http.StatusOK, testWebhookResponse{
		Success:      success,
		StatusCode:   resp.StatusCode,
		ResponseBody: respBody.String(),
		DurationMs:   durationMs,
		RenderedBody: renderedBody,
	})
}
