package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kato83/mayu/internal/model"
)

// mockWebhookStore implements WebhookStore for testing.
type mockWebhookStore struct {
	mu       sync.Mutex
	webhooks []*model.Webhook
	logs     []*model.WebhookDeliveryLog
}

func newMockStore() *mockWebhookStore {
	return &mockWebhookStore{}
}

func (m *mockWebhookStore) CreateWebhook(_ context.Context, w *model.Webhook) (*model.Webhook, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	w.ID = int64(len(m.webhooks) + 1)
	w.CreatedAt = time.Now()
	w.UpdatedAt = time.Now()
	m.webhooks = append(m.webhooks, w)
	return w, nil
}

func (m *mockWebhookStore) UpdateWebhook(_ context.Context, w *model.Webhook) (*model.Webhook, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, existing := range m.webhooks {
		if existing.ID == w.ID {
			w.UpdatedAt = time.Now()
			m.webhooks[i] = w
			return w, nil
		}
	}
	return nil, nil
}

func (m *mockWebhookStore) DeleteWebhook(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, w := range m.webhooks {
		if w.ID == id {
			m.webhooks = append(m.webhooks[:i], m.webhooks[i+1:]...)
			return nil
		}
	}
	return nil
}

func (m *mockWebhookStore) GetWebhook(_ context.Context, id int64) (*model.Webhook, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, w := range m.webhooks {
		if w.ID == id {
			return w, nil
		}
	}
	return nil, nil
}

func (m *mockWebhookStore) ListWebhooks(_ context.Context) ([]*model.Webhook, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]*model.Webhook, len(m.webhooks))
	copy(result, m.webhooks)
	return result, nil
}

func (m *mockWebhookStore) GetWebhooksByEvent(_ context.Context, event string) ([]*model.Webhook, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []*model.Webhook
	for _, w := range m.webhooks {
		if !w.Enabled {
			continue
		}
		for _, e := range w.Events {
			if e == event || e == "*" {
				result = append(result, w)
				break
			}
		}
	}
	return result, nil
}

func (m *mockWebhookStore) CreateDeliveryLog(_ context.Context, dl *model.WebhookDeliveryLog) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	dl.ID = int64(len(m.logs) + 1)
	m.logs = append(m.logs, dl)
	return nil
}

func (m *mockWebhookStore) ListDeliveryLogs(_ context.Context, webhookID int64, limit int) ([]*model.WebhookDeliveryLog, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []*model.WebhookDeliveryLog
	for i := len(m.logs) - 1; i >= 0 && len(result) < limit; i-- {
		if m.logs[i].WebhookID == webhookID {
			result = append(result, m.logs[i])
		}
	}
	return result, nil
}

func (m *mockWebhookStore) PruneDeliveryLogs(_ context.Context, keepPerWebhook int) error {
	return nil
}

func (m *mockWebhookStore) ListWebhooksByUser(_ context.Context, userID int64) ([]*model.Webhook, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []*model.Webhook
	for _, w := range m.webhooks {
		if w.UserID != nil && *w.UserID == userID {
			result = append(result, w)
		}
	}
	return result, nil
}

func (m *mockWebhookStore) getLogs() []*model.WebhookDeliveryLog {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]*model.WebhookDeliveryLog, len(m.logs))
	copy(result, m.logs)
	return result
}

func TestDispatch_SuccessfulDelivery(t *testing.T) {
	var received atomic.Int32
	var receivedBody string
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		receivedBody = string(body)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	store := newMockStore()
	store.webhooks = append(store.webhooks, &model.Webhook{
		ID:           1,
		Name:         "test-hook",
		URL:          server.URL,
		Events:       []string{"new_critical"},
		ContentType:  "application/json",
		BodyTemplate: `{"id": "{{ID}}"}`,
		Enabled:      true,
	})

	engine := NewEngine(store,
		WithHTTPClient(server.Client()),
		WithRetrySleep(func(d time.Duration) {}),
	)

	engine.Dispatch(context.Background(), "new_critical", []WebhookEvent{
		{Event: "new_critical", ID: "CVE-2024-0001", Severity: "CRITICAL"},
	})

	if received.Load() != 1 {
		t.Fatalf("expected 1 request, got %d", received.Load())
	}

	mu.Lock()
	defer mu.Unlock()
	if receivedBody != `{"id": "CVE-2024-0001"}` {
		t.Errorf("unexpected body: %s", receivedBody)
	}

	logs := store.getLogs()
	if len(logs) != 1 {
		t.Fatalf("expected 1 delivery log, got %d", len(logs))
	}
	if logs[0].Attempt != 1 {
		t.Errorf("expected attempt 1, got %d", logs[0].Attempt)
	}
	if logs[0].ResponseStatus == nil || *logs[0].ResponseStatus != 200 {
		t.Errorf("expected response status 200")
	}
}

func TestDispatch_TemplateRendering(t *testing.T) {
	var receivedBody string
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		receivedBody = string(body)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	store := newMockStore()
	store.webhooks = append(store.webhooks, &model.Webhook{
		ID:           1,
		Name:         "template-test",
		URL:          server.URL,
		Events:       []string{"new_vulnerability"},
		ContentType:  "application/json",
		BodyTemplate: `{"event":"{{Event}}","id":"{{ID}}","severity":"{{Severity}}","epss":{{EPSS}},"lev":{{LEV}},"summary":"{{Summary}}"}`,
		Enabled:      true,
	})

	engine := NewEngine(store,
		WithHTTPClient(server.Client()),
		WithRetrySleep(func(d time.Duration) {}),
	)

	engine.Dispatch(context.Background(), "new_vulnerability", []WebhookEvent{
		{
			Event:    "new_vulnerability",
			ID:       "CVE-2024-9999",
			Severity: "HIGH",
			EPSS:     0.75,
			LEV:      0.9,
			Summary:  "Test vulnerability",
		},
	})

	mu.Lock()
	defer mu.Unlock()
	expected := `{"event":"new_vulnerability","id":"CVE-2024-9999","severity":"HIGH","epss":0.75,"lev":0.9,"summary":"Test vulnerability"}`
	if receivedBody != expected {
		t.Errorf("template rendering mismatch:\ngot:  %s\nwant: %s", receivedBody, expected)
	}
}

func TestDispatch_RetryOn500(t *testing.T) {
	var requestCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := requestCount.Add(1)
		if count < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("server error"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	store := newMockStore()
	store.webhooks = append(store.webhooks, &model.Webhook{
		ID:           1,
		Name:         "retry-test",
		URL:          server.URL,
		Events:       []string{"new_high"},
		ContentType:  "application/json",
		BodyTemplate: `{"id": "{{ID}}"}`,
		Enabled:      true,
	})

	engine := NewEngine(store,
		WithHTTPClient(server.Client()),
		WithRetrySleep(func(d time.Duration) {}), // skip real delays in tests
	)

	engine.Dispatch(context.Background(), "new_high", []WebhookEvent{
		{Event: "new_high", ID: "CVE-2024-0002", Severity: "HIGH"},
	})

	if requestCount.Load() != 3 {
		t.Fatalf("expected 3 requests (2 retries + 1 success), got %d", requestCount.Load())
	}

	logs := store.getLogs()
	if len(logs) != 3 {
		t.Fatalf("expected 3 delivery logs, got %d", len(logs))
	}

	// First two should be failures
	for i := 0; i < 2; i++ {
		if logs[i].ResponseStatus == nil || *logs[i].ResponseStatus != 500 {
			t.Errorf("log[%d]: expected status 500", i)
		}
		if logs[i].Attempt != i+1 {
			t.Errorf("log[%d]: expected attempt %d, got %d", i, i+1, logs[i].Attempt)
		}
	}

	// Third should be success
	if logs[2].ResponseStatus == nil || *logs[2].ResponseStatus != 200 {
		t.Errorf("log[2]: expected status 200")
	}
	if logs[2].Attempt != 3 {
		t.Errorf("log[2]: expected attempt 3, got %d", logs[2].Attempt)
	}
}

func TestDispatch_NoRetryOn4xx(t *testing.T) {
	var requestCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad request"))
	}))
	defer server.Close()

	store := newMockStore()
	store.webhooks = append(store.webhooks, &model.Webhook{
		ID:           1,
		Name:         "no-retry-test",
		URL:          server.URL,
		Events:       []string{"new_critical"},
		ContentType:  "application/json",
		BodyTemplate: `{"id": "{{ID}}"}`,
		Enabled:      true,
	})

	engine := NewEngine(store,
		WithHTTPClient(server.Client()),
		WithRetrySleep(func(d time.Duration) {}),
	)

	engine.Dispatch(context.Background(), "new_critical", []WebhookEvent{
		{Event: "new_critical", ID: "CVE-2024-0003", Severity: "CRITICAL"},
	})

	if requestCount.Load() != 1 {
		t.Fatalf("expected 1 request (no retry on 4xx), got %d", requestCount.Load())
	}

	logs := store.getLogs()
	if len(logs) != 1 {
		t.Fatalf("expected 1 delivery log, got %d", len(logs))
	}
}

func TestDispatch_WildcardEventMatching(t *testing.T) {
	var received atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	store := newMockStore()
	// Webhook with wildcard event
	store.webhooks = append(store.webhooks, &model.Webhook{
		ID:           1,
		Name:         "wildcard-hook",
		URL:          server.URL,
		Events:       []string{"*"},
		ContentType:  "application/json",
		BodyTemplate: `{"id": "{{ID}}"}`,
		Enabled:      true,
	})

	engine := NewEngine(store,
		WithHTTPClient(server.Client()),
		WithRetrySleep(func(d time.Duration) {}),
	)

	// Should match any event
	engine.Dispatch(context.Background(), "new_critical", []WebhookEvent{
		{Event: "new_critical", ID: "CVE-2024-0004", Severity: "CRITICAL"},
	})
	engine.Dispatch(context.Background(), "new_high", []WebhookEvent{
		{Event: "new_high", ID: "CVE-2024-0005", Severity: "HIGH"},
	})
	engine.Dispatch(context.Background(), "new_vulnerability", []WebhookEvent{
		{Event: "new_vulnerability", ID: "CVE-2024-0006", Severity: "MEDIUM"},
	})

	if received.Load() != 3 {
		t.Fatalf("expected 3 requests (wildcard matches all), got %d", received.Load())
	}
}

func TestDispatch_DisabledWebhookSkipped(t *testing.T) {
	var received atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	store := newMockStore()
	// Disabled webhook
	store.webhooks = append(store.webhooks, &model.Webhook{
		ID:           1,
		Name:         "disabled-hook",
		URL:          server.URL,
		Events:       []string{"new_critical"},
		ContentType:  "application/json",
		BodyTemplate: `{"id": "{{ID}}"}`,
		Enabled:      false,
	})
	// Enabled webhook
	store.webhooks = append(store.webhooks, &model.Webhook{
		ID:           2,
		Name:         "enabled-hook",
		URL:          server.URL,
		Events:       []string{"new_critical"},
		ContentType:  "application/json",
		BodyTemplate: `{"id": "{{ID}}"}`,
		Enabled:      true,
	})

	engine := NewEngine(store,
		WithHTTPClient(server.Client()),
		WithRetrySleep(func(d time.Duration) {}),
	)

	engine.Dispatch(context.Background(), "new_critical", []WebhookEvent{
		{Event: "new_critical", ID: "CVE-2024-0007", Severity: "CRITICAL"},
	})

	if received.Load() != 1 {
		t.Fatalf("expected 1 request (disabled webhook skipped), got %d", received.Load())
	}
}

func TestDispatch_HMACSignature(t *testing.T) {
	secret := "my-webhook-secret"
	var receivedSig string
	var receivedBody []byte
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedSig = r.Header.Get("X-Webhook-Signature")
		receivedBody, _ = io.ReadAll(r.Body)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	store := newMockStore()
	store.webhooks = append(store.webhooks, &model.Webhook{
		ID:           1,
		Name:         "hmac-hook",
		URL:          server.URL,
		Events:       []string{"new_critical"},
		ContentType:  "application/json",
		BodyTemplate: `{"id": "{{ID}}"}`,
		Secret:       secret,
		Enabled:      true,
	})

	engine := NewEngine(store,
		WithHTTPClient(server.Client()),
		WithRetrySleep(func(d time.Duration) {}),
	)

	engine.Dispatch(context.Background(), "new_critical", []WebhookEvent{
		{Event: "new_critical", ID: "CVE-2024-0008", Severity: "CRITICAL"},
	})

	mu.Lock()
	defer mu.Unlock()

	if receivedSig == "" {
		t.Fatal("expected X-Webhook-Signature header to be set")
	}

	if !strings.HasPrefix(receivedSig, "sha256=") {
		t.Fatalf("expected signature to start with 'sha256=', got: %s", receivedSig)
	}

	// Verify the HMAC
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(receivedBody)
	expectedSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	if receivedSig != expectedSig {
		t.Errorf("HMAC mismatch:\ngot:  %s\nwant: %s", receivedSig, expectedSig)
	}
}

func TestDispatch_MaxRetriesExhausted(t *testing.T) {
	var requestCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("error"))
	}))
	defer server.Close()

	store := newMockStore()
	store.webhooks = append(store.webhooks, &model.Webhook{
		ID:           1,
		Name:         "exhaust-retries",
		URL:          server.URL,
		Events:       []string{"new_critical"},
		ContentType:  "application/json",
		BodyTemplate: `{"id": "{{ID}}"}`,
		Enabled:      true,
	})

	engine := NewEngine(store,
		WithHTTPClient(server.Client()),
		WithRetrySleep(func(d time.Duration) {}),
	)

	engine.Dispatch(context.Background(), "new_critical", []WebhookEvent{
		{Event: "new_critical", ID: "CVE-2024-0009", Severity: "CRITICAL"},
	})

	if requestCount.Load() != 3 {
		t.Fatalf("expected 3 requests (max retries), got %d", requestCount.Load())
	}

	logs := store.getLogs()
	if len(logs) != 3 {
		t.Fatalf("expected 3 delivery logs, got %d", len(logs))
	}

	// All should be failures
	for i, dl := range logs {
		if dl.ResponseStatus == nil || *dl.ResponseStatus != 500 {
			t.Errorf("log[%d]: expected status 500", i)
		}
	}
}

func TestNotifyNewVulnerabilities(t *testing.T) {
	var requestCount atomic.Int32
	var receivedBodies []string
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		receivedBodies = append(receivedBodies, string(body))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	store := newMockStore()
	store.webhooks = append(store.webhooks, &model.Webhook{
		ID:           1,
		Name:         "critical-hook",
		URL:          server.URL,
		Events:       []string{"new_critical"},
		ContentType:  "application/json",
		BodyTemplate: `{"id":"{{ID}}","sev":"{{Severity}}"}`,
		Enabled:      true,
	})
	store.webhooks = append(store.webhooks, &model.Webhook{
		ID:           2,
		Name:         "all-hook",
		URL:          server.URL,
		Events:       []string{"new_vulnerability"},
		ContentType:  "application/json",
		BodyTemplate: `{"id":"{{ID}}","event":"{{Event}}"}`,
		Enabled:      true,
	})

	engine := NewEngine(store,
		WithHTTPClient(server.Client()),
		WithRetrySleep(func(d time.Duration) {}),
	)

	lookupFn := func(_ context.Context, ids []string) (map[string]int, error) {
		result := map[string]int{
			"CVE-2024-1000": 5, // critical
			"CVE-2024-2000": 4, // high
			"CVE-2024-3000": 3, // medium
		}
		return result, nil
	}

	engine.NotifyNewVulnerabilities(context.Background(), []string{"CVE-2024-1000", "CVE-2024-2000", "CVE-2024-3000"}, lookupFn)

	// Expected: 1 new_critical dispatch (CVE-2024-1000) + 3 new_vulnerability dispatches
	// = 4 total HTTP requests
	if requestCount.Load() != 4 {
		t.Fatalf("expected 4 requests, got %d", requestCount.Load())
	}
}
