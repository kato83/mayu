package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kato83/mayu/internal/auth"
	"github.com/kato83/mayu/internal/model"
	"github.com/kato83/mayu/internal/webhook"
)

// mockWebhookStore implements webhook.WebhookStore for testing.
type mockWebhookStore struct {
	webhooks     []*model.Webhook
	deliveryLogs []*model.WebhookDeliveryLog
	nextID       int64
	createErr    error
	updateErr    error
	deleteErr    error
	getErr       error
	listErr      error
}

func newMockWebhookStore() *mockWebhookStore {
	return &mockWebhookStore{
		webhooks:     make([]*model.Webhook, 0),
		deliveryLogs: make([]*model.WebhookDeliveryLog, 0),
		nextID:       1,
	}
}

func (m *mockWebhookStore) CreateWebhook(_ context.Context, w *model.Webhook) (*model.Webhook, error) {
	if m.createErr != nil {
		return nil, m.createErr
	}
	created := &model.Webhook{
		ID:           m.nextID,
		Name:         w.Name,
		URL:          w.URL,
		Events:       w.Events,
		ContentType:  w.ContentType,
		BodyTemplate: w.BodyTemplate,
		Secret:       w.Secret,
		Enabled:      w.Enabled,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	m.nextID++
	m.webhooks = append(m.webhooks, created)
	return created, nil
}

func (m *mockWebhookStore) UpdateWebhook(_ context.Context, w *model.Webhook) (*model.Webhook, error) {
	if m.updateErr != nil {
		return nil, m.updateErr
	}
	for i, wh := range m.webhooks {
		if wh.ID == w.ID {
			m.webhooks[i] = &model.Webhook{
				ID:           w.ID,
				Name:         w.Name,
				URL:          w.URL,
				Events:       w.Events,
				ContentType:  w.ContentType,
				BodyTemplate: w.BodyTemplate,
				Secret:       w.Secret,
				Enabled:      w.Enabled,
				CreatedAt:    wh.CreatedAt,
				UpdatedAt:    time.Now(),
			}
			return m.webhooks[i], nil
		}
	}
	return nil, fmt.Errorf("webhook not found: id=%d", w.ID)
}

func (m *mockWebhookStore) DeleteWebhook(_ context.Context, id int64) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	for i, wh := range m.webhooks {
		if wh.ID == id {
			m.webhooks = append(m.webhooks[:i], m.webhooks[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("webhook not found: id=%d", id)
}

func (m *mockWebhookStore) GetWebhook(_ context.Context, id int64) (*model.Webhook, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	for _, wh := range m.webhooks {
		if wh.ID == id {
			return wh, nil
		}
	}
	return nil, nil
}

func (m *mockWebhookStore) ListWebhooks(_ context.Context) ([]*model.Webhook, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.webhooks, nil
}

func (m *mockWebhookStore) GetWebhooksByEvent(_ context.Context, event string) ([]*model.Webhook, error) {
	var result []*model.Webhook
	for _, wh := range m.webhooks {
		if !wh.Enabled {
			continue
		}
		for _, e := range wh.Events {
			if e == event || e == "*" {
				result = append(result, wh)
				break
			}
		}
	}
	return result, nil
}

func (m *mockWebhookStore) CreateDeliveryLog(_ context.Context, dl *model.WebhookDeliveryLog) error {
	dl.ID = m.nextID
	m.nextID++
	m.deliveryLogs = append(m.deliveryLogs, dl)
	return nil
}

func (m *mockWebhookStore) ListDeliveryLogs(_ context.Context, webhookID int64, limit int) ([]*model.WebhookDeliveryLog, error) {
	var result []*model.WebhookDeliveryLog
	for _, dl := range m.deliveryLogs {
		if dl.WebhookID == webhookID {
			result = append(result, dl)
		}
	}
	if len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

func (m *mockWebhookStore) PruneDeliveryLogs(_ context.Context, keepPerWebhook int) error {
	return nil
}

// newTestServerWithWebhook creates a Server with a mock webhook store for testing.
func newTestServerWithWebhook(ws webhook.WebhookStore) *Server {
	return New(Config{
		Addr:         ":0",
		Store:        &mockStore{},
		Version:      "test-v1.0.0",
		AuthProvider: auth.NewNoAuthProvider(),
		WebhookStore: ws,
	})
}

func TestCreateWebhook(t *testing.T) {
	ws := newMockWebhookStore()
	srv := newTestServerWithWebhook(ws)

	body := `{"name":"test-webhook","url":"https://example.com/hook","events":["new_critical","new_high"],"content_type":"application/json","body_template":"{\"text\":\"{{.ID}}\"}","enabled":true}`

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp webhookResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.ID != 1 {
		t.Errorf("expected ID 1, got %d", resp.ID)
	}
	if resp.Name != "test-webhook" {
		t.Errorf("expected name 'test-webhook', got %q", resp.Name)
	}
	if resp.URL != "https://example.com/hook" {
		t.Errorf("expected URL 'https://example.com/hook', got %q", resp.URL)
	}
	if len(resp.Events) != 2 {
		t.Errorf("expected 2 events, got %d", len(resp.Events))
	}
	if !resp.Enabled {
		t.Error("expected enabled to be true")
	}
}

func TestCreateWebhook_MissingName(t *testing.T) {
	ws := newMockWebhookStore()
	srv := newTestServerWithWebhook(ws)

	body := `{"url":"https://example.com/hook","events":["*"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestCreateWebhook_MissingURL(t *testing.T) {
	ws := newMockWebhookStore()
	srv := newTestServerWithWebhook(ws)

	body := `{"name":"test","events":["*"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestCreateWebhook_MissingEvents(t *testing.T) {
	ws := newMockWebhookStore()
	srv := newTestServerWithWebhook(ws)

	body := `{"name":"test","url":"https://example.com/hook"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestListWebhooks(t *testing.T) {
	ws := newMockWebhookStore()
	srv := newTestServerWithWebhook(ws)

	// Create two webhooks
	ws.webhooks = []*model.Webhook{
		{ID: 1, Name: "hook1", URL: "https://example.com/1", Events: []string{"*"}, Enabled: true, CreatedAt: time.Now(), UpdatedAt: time.Now()},
		{ID: 2, Name: "hook2", URL: "https://example.com/2", Events: []string{"new_critical"}, Enabled: false, CreatedAt: time.Now(), UpdatedAt: time.Now()},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/webhooks", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp []webhookResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(resp) != 2 {
		t.Fatalf("expected 2 webhooks, got %d", len(resp))
	}
	if resp[0].Name != "hook1" {
		t.Errorf("expected first webhook name 'hook1', got %q", resp[0].Name)
	}
	if resp[1].Enabled {
		t.Error("expected second webhook to be disabled")
	}
}

func TestGetWebhook(t *testing.T) {
	ws := newMockWebhookStore()
	srv := newTestServerWithWebhook(ws)

	ws.webhooks = []*model.Webhook{
		{ID: 1, Name: "hook1", URL: "https://example.com/1", Events: []string{"*"}, ContentType: "application/json", Enabled: true, CreatedAt: time.Now(), UpdatedAt: time.Now()},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/webhooks/1", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp webhookResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.ID != 1 {
		t.Errorf("expected ID 1, got %d", resp.ID)
	}
	if resp.Name != "hook1" {
		t.Errorf("expected name 'hook1', got %q", resp.Name)
	}
}

func TestGetWebhook_NotFound(t *testing.T) {
	ws := newMockWebhookStore()
	srv := newTestServerWithWebhook(ws)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/webhooks/999", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetWebhook_InvalidID(t *testing.T) {
	ws := newMockWebhookStore()
	srv := newTestServerWithWebhook(ws)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/webhooks/abc", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUpdateWebhook(t *testing.T) {
	ws := newMockWebhookStore()
	srv := newTestServerWithWebhook(ws)

	ws.webhooks = []*model.Webhook{
		{ID: 1, Name: "hook1", URL: "https://example.com/1", Events: []string{"*"}, ContentType: "application/json", Enabled: true, CreatedAt: time.Now(), UpdatedAt: time.Now()},
	}

	body := `{"name":"updated-hook","url":"https://example.com/updated","events":["new_critical"],"content_type":"application/json","enabled":false}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/webhooks/1", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp webhookResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Name != "updated-hook" {
		t.Errorf("expected name 'updated-hook', got %q", resp.Name)
	}
	if resp.URL != "https://example.com/updated" {
		t.Errorf("expected URL 'https://example.com/updated', got %q", resp.URL)
	}
	if resp.Enabled {
		t.Error("expected enabled to be false")
	}
}

func TestDeleteWebhook(t *testing.T) {
	ws := newMockWebhookStore()
	srv := newTestServerWithWebhook(ws)

	ws.webhooks = []*model.Webhook{
		{ID: 1, Name: "hook1", URL: "https://example.com/1", Events: []string{"*"}, Enabled: true, CreatedAt: time.Now(), UpdatedAt: time.Now()},
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/webhooks/1", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify it was removed
	if len(ws.webhooks) != 0 {
		t.Errorf("expected 0 webhooks after delete, got %d", len(ws.webhooks))
	}
}

func TestDeleteWebhook_NotFound(t *testing.T) {
	ws := newMockWebhookStore()
	srv := newTestServerWithWebhook(ws)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/webhooks/999", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d: %s", w.Code, w.Body.String())
	}
}

func TestListWebhookDeliveries(t *testing.T) {
	ws := newMockWebhookStore()
	srv := newTestServerWithWebhook(ws)

	status := 200
	durationMs := 42
	ws.deliveryLogs = []*model.WebhookDeliveryLog{
		{ID: 1, WebhookID: 1, Event: "new_critical", Payload: `{"text":"test"}`, ResponseStatus: &status, Attempt: 1, DeliveredAt: time.Now(), DurationMs: &durationMs},
		{ID: 2, WebhookID: 1, Event: "new_high", Payload: `{"text":"test2"}`, ResponseStatus: &status, Attempt: 1, DeliveredAt: time.Now(), DurationMs: &durationMs},
		{ID: 3, WebhookID: 2, Event: "test", Payload: `{}`, ResponseStatus: &status, Attempt: 1, DeliveredAt: time.Now(), DurationMs: &durationMs},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/webhooks/1/deliveries", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp []deliveryLogResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(resp) != 2 {
		t.Fatalf("expected 2 delivery logs for webhook 1, got %d", len(resp))
	}
}

func TestListWebhookDeliveries_WithLimit(t *testing.T) {
	ws := newMockWebhookStore()
	srv := newTestServerWithWebhook(ws)

	status := 200
	durationMs := 10
	ws.deliveryLogs = []*model.WebhookDeliveryLog{
		{ID: 1, WebhookID: 1, Event: "a", Attempt: 1, ResponseStatus: &status, DeliveredAt: time.Now(), DurationMs: &durationMs},
		{ID: 2, WebhookID: 1, Event: "b", Attempt: 1, ResponseStatus: &status, DeliveredAt: time.Now(), DurationMs: &durationMs},
		{ID: 3, WebhookID: 1, Event: "c", Attempt: 1, ResponseStatus: &status, DeliveredAt: time.Now(), DurationMs: &durationMs},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/webhooks/1/deliveries?limit=2", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp []deliveryLogResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(resp) != 2 {
		t.Fatalf("expected 2 delivery logs with limit=2, got %d", len(resp))
	}
}

func TestTestWebhook(t *testing.T) {
	// Create a test HTTP server that the webhook will post to
	var receivedBody string
	var receivedContentType string
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 1024)
		n, _ := r.Body.Read(buf)
		receivedBody = string(buf[:n])
		receivedContentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer testServer.Close()

	ws := newMockWebhookStore()
	srv := newTestServerWithWebhook(ws)

	ws.webhooks = []*model.Webhook{
		{
			ID:           1,
			Name:         "test-hook",
			URL:          testServer.URL,
			Events:       []string{"*"},
			ContentType:  "application/json",
			BodyTemplate: `{"event":"{{.Event}}","id":"{{.ID}}","severity":"{{.Severity}}"}`,
			Enabled:      true,
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/1/test", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp testWebhookResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !resp.Success {
		t.Errorf("expected success=true, got false (error: %s)", resp.ErrorMessage)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status code 200, got %d", resp.StatusCode)
	}
	if resp.DurationMs < 0 {
		t.Errorf("expected non-negative duration, got %d", resp.DurationMs)
	}

	// Verify the payload was rendered correctly
	expectedBody := `{"event":"test","id":"CVE-0000-0000","severity":"MEDIUM"}`
	if receivedBody != expectedBody {
		t.Errorf("expected received body %q, got %q", expectedBody, receivedBody)
	}
	if receivedContentType != "application/json" {
		t.Errorf("expected content-type 'application/json', got %q", receivedContentType)
	}
}

func TestTestWebhook_NotFound(t *testing.T) {
	ws := newMockWebhookStore()
	srv := newTestServerWithWebhook(ws)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/999/test", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestWebhookEndpoints_RequireAuth(t *testing.T) {
	provider := &localAuthProvider{
		validSession: "good-session",
		validAPIKey:  "good-api-key",
		user: &auth.User{
			ID:    1,
			Email: "test@example.com",
			Name:  "Test",
			Role:  "admin",
		},
	}

	ws := newMockWebhookStore()
	srv := New(Config{
		Addr:         ":0",
		Store:        &mockStore{},
		Version:      "test-v1.0.0",
		AuthProvider: provider,
		WebhookStore: ws,
	})

	// All webhook endpoints should return 401 without auth
	endpoints := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/webhooks"},
		{http.MethodPost, "/api/v1/webhooks"},
		{http.MethodGet, "/api/v1/webhooks/1"},
		{http.MethodPut, "/api/v1/webhooks/1"},
		{http.MethodDelete, "/api/v1/webhooks/1"},
		{http.MethodGet, "/api/v1/webhooks/1/deliveries"},
		{http.MethodPost, "/api/v1/webhooks/1/test"},
	}

	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path+" unauthenticated", func(t *testing.T) {
			req := httptest.NewRequest(ep.method, ep.path, nil)
			w := httptest.NewRecorder()
			srv.httpServer.Handler.ServeHTTP(w, req)

			if w.Code != http.StatusUnauthorized {
				t.Fatalf("expected 401, got %d", w.Code)
			}
		})
	}

	// With valid session, should be allowed
	t.Run("GET /api/v1/webhooks with auth", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/webhooks", nil)
		req.AddCookie(&http.Cookie{Name: "mayu_session", Value: "good-session"})
		w := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(w, req)

		if w.Code == http.StatusUnauthorized {
			t.Fatal("expected authenticated request to succeed, got 401")
		}
	})
}

func TestCreateWebhook_DefaultContentType(t *testing.T) {
	ws := newMockWebhookStore()
	srv := newTestServerWithWebhook(ws)

	// Create without specifying content_type - should default to application/json
	body := `{"name":"test","url":"https://example.com/hook","events":["*"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp webhookResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.ContentType != "application/json" {
		t.Errorf("expected default content_type 'application/json', got %q", resp.ContentType)
	}
}

func TestCreateWebhook_DefaultEnabled(t *testing.T) {
	ws := newMockWebhookStore()
	srv := newTestServerWithWebhook(ws)

	// Create without specifying enabled - should default to true
	body := `{"name":"test","url":"https://example.com/hook","events":["*"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp webhookResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !resp.Enabled {
		t.Error("expected default enabled to be true")
	}
}

func TestWebhookRoutes_NotRegisteredWithoutStore(t *testing.T) {
	// When WebhookStore is nil, routes should not be registered
	srv := New(Config{
		Addr:         ":0",
		Store:        &mockStore{},
		Version:      "test-v1.0.0",
		AuthProvider: auth.NewNoAuthProvider(),
		WebhookStore: nil,
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/webhooks", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	// Should get 404 or 405 since routes are not registered
	if w.Code == http.StatusOK {
		t.Fatal("expected webhook routes to not be registered when store is nil")
	}
}
