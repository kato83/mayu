package webhook

import (
	"context"
	"testing"
	"time"

	"github.com/kato83/mayu/internal/model"
)

func TestMockStore_CreateWebhook(t *testing.T) {
	store := newMockStore()
	ctx := context.Background()

	w := &model.Webhook{
		Name:         "test-hook",
		URL:          "https://example.com/webhook",
		Events:       []string{"new_critical", "new_high"},
		ContentType:  "application/json",
		BodyTemplate: `{"id": "{{.ID}}"}`,
		Secret:       "secret123",
		Enabled:      true,
	}

	created, err := store.CreateWebhook(ctx, w)
	if err != nil {
		t.Fatalf("CreateWebhook failed: %v", err)
	}

	if created.ID == 0 {
		t.Error("expected non-zero ID")
	}
	if created.Name != "test-hook" {
		t.Errorf("expected name 'test-hook', got %q", created.Name)
	}
	if created.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be set")
	}
}

func TestMockStore_GetWebhook(t *testing.T) {
	store := newMockStore()
	ctx := context.Background()

	w := &model.Webhook{
		Name:         "find-me",
		URL:          "https://example.com/hook",
		Events:       []string{"*"},
		ContentType:  "application/json",
		BodyTemplate: `{}`,
		Enabled:      true,
	}

	created, err := store.CreateWebhook(ctx, w)
	if err != nil {
		t.Fatalf("CreateWebhook failed: %v", err)
	}

	found, err := store.GetWebhook(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetWebhook failed: %v", err)
	}
	if found == nil {
		t.Fatal("expected webhook to be found")
	}
	if found.Name != "find-me" {
		t.Errorf("expected name 'find-me', got %q", found.Name)
	}

	// Not found
	notFound, err := store.GetWebhook(ctx, 9999)
	if err != nil {
		t.Fatalf("GetWebhook for missing ID failed: %v", err)
	}
	if notFound != nil {
		t.Error("expected nil for non-existent webhook")
	}
}

func TestMockStore_ListWebhooks(t *testing.T) {
	store := newMockStore()
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		_, err := store.CreateWebhook(ctx, &model.Webhook{
			Name:         "hook",
			URL:          "https://example.com",
			Events:       []string{"new_vulnerability"},
			ContentType:  "application/json",
			BodyTemplate: `{}`,
			Enabled:      true,
		})
		if err != nil {
			t.Fatalf("CreateWebhook failed: %v", err)
		}
	}

	all, err := store.ListWebhooks(ctx)
	if err != nil {
		t.Fatalf("ListWebhooks failed: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("expected 3 webhooks, got %d", len(all))
	}
}

func TestMockStore_UpdateWebhook(t *testing.T) {
	store := newMockStore()
	ctx := context.Background()

	w := &model.Webhook{
		Name:         "original",
		URL:          "https://example.com/v1",
		Events:       []string{"new_critical"},
		ContentType:  "application/json",
		BodyTemplate: `{}`,
		Enabled:      true,
	}

	created, err := store.CreateWebhook(ctx, w)
	if err != nil {
		t.Fatalf("CreateWebhook failed: %v", err)
	}

	created.Name = "updated"
	created.URL = "https://example.com/v2"
	updated, err := store.UpdateWebhook(ctx, created)
	if err != nil {
		t.Fatalf("UpdateWebhook failed: %v", err)
	}
	if updated == nil {
		t.Fatal("expected non-nil updated webhook")
	}
	if updated.Name != "updated" {
		t.Errorf("expected name 'updated', got %q", updated.Name)
	}
	if updated.URL != "https://example.com/v2" {
		t.Errorf("expected URL 'https://example.com/v2', got %q", updated.URL)
	}
}

func TestMockStore_DeleteWebhook(t *testing.T) {
	store := newMockStore()
	ctx := context.Background()

	w := &model.Webhook{
		Name:         "delete-me",
		URL:          "https://example.com",
		Events:       []string{"*"},
		ContentType:  "application/json",
		BodyTemplate: `{}`,
		Enabled:      true,
	}

	created, err := store.CreateWebhook(ctx, w)
	if err != nil {
		t.Fatalf("CreateWebhook failed: %v", err)
	}

	err = store.DeleteWebhook(ctx, created.ID)
	if err != nil {
		t.Fatalf("DeleteWebhook failed: %v", err)
	}

	found, err := store.GetWebhook(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetWebhook after delete failed: %v", err)
	}
	if found != nil {
		t.Error("expected nil after deletion")
	}
}

func TestMockStore_GetWebhooksByEvent(t *testing.T) {
	store := newMockStore()
	ctx := context.Background()

	tests := []struct {
		name    string
		webhook *model.Webhook
	}{
		{
			name: "critical-only",
			webhook: &model.Webhook{
				Name:         "critical-hook",
				URL:          "https://example.com/critical",
				Events:       []string{"new_critical"},
				ContentType:  "application/json",
				BodyTemplate: `{}`,
				Enabled:      true,
			},
		},
		{
			name: "wildcard",
			webhook: &model.Webhook{
				Name:         "wildcard-hook",
				URL:          "https://example.com/all",
				Events:       []string{"*"},
				ContentType:  "application/json",
				BodyTemplate: `{}`,
				Enabled:      true,
			},
		},
		{
			name: "disabled",
			webhook: &model.Webhook{
				Name:         "disabled-hook",
				URL:          "https://example.com/disabled",
				Events:       []string{"new_critical"},
				ContentType:  "application/json",
				BodyTemplate: `{}`,
				Enabled:      false,
			},
		},
		{
			name: "high-only",
			webhook: &model.Webhook{
				Name:         "high-hook",
				URL:          "https://example.com/high",
				Events:       []string{"new_high"},
				ContentType:  "application/json",
				BodyTemplate: `{}`,
				Enabled:      true,
			},
		},
	}

	for _, tt := range tests {
		if _, err := store.CreateWebhook(ctx, tt.webhook); err != nil {
			t.Fatalf("CreateWebhook(%s) failed: %v", tt.name, err)
		}
	}

	// Query for new_critical: should return critical-hook and wildcard-hook (not disabled)
	criticals, err := store.GetWebhooksByEvent(ctx, "new_critical")
	if err != nil {
		t.Fatalf("GetWebhooksByEvent(new_critical) failed: %v", err)
	}
	if len(criticals) != 2 {
		t.Errorf("expected 2 webhooks for new_critical, got %d", len(criticals))
	}

	// Query for new_high: should return wildcard-hook and high-hook
	highs, err := store.GetWebhooksByEvent(ctx, "new_high")
	if err != nil {
		t.Fatalf("GetWebhooksByEvent(new_high) failed: %v", err)
	}
	if len(highs) != 2 {
		t.Errorf("expected 2 webhooks for new_high, got %d", len(highs))
	}

	// Query for custom_event: should return only wildcard-hook
	customs, err := store.GetWebhooksByEvent(ctx, "custom_event")
	if err != nil {
		t.Fatalf("GetWebhooksByEvent(custom_event) failed: %v", err)
	}
	if len(customs) != 1 {
		t.Errorf("expected 1 webhook for custom_event, got %d", len(customs))
	}
	if customs[0].Name != "wildcard-hook" {
		t.Errorf("expected wildcard-hook, got %q", customs[0].Name)
	}
}

func TestMockStore_CreateDeliveryLog(t *testing.T) {
	store := newMockStore()
	ctx := context.Background()

	status := 200
	durationMs := 42
	dl := &model.WebhookDeliveryLog{
		WebhookID:      1,
		Event:          "new_critical",
		Payload:        `{"id": "CVE-2024-0001"}`,
		ResponseStatus: &status,
		Attempt:        1,
		DeliveredAt:    time.Now(),
		DurationMs:     &durationMs,
	}

	err := store.CreateDeliveryLog(ctx, dl)
	if err != nil {
		t.Fatalf("CreateDeliveryLog failed: %v", err)
	}

	if dl.ID == 0 {
		t.Error("expected non-zero ID after creation")
	}
}

func TestMockStore_ListDeliveryLogs(t *testing.T) {
	store := newMockStore()
	ctx := context.Background()

	// Create multiple logs
	for i := 1; i <= 5; i++ {
		status := 200
		durationMs := i * 10
		_ = store.CreateDeliveryLog(ctx, &model.WebhookDeliveryLog{
			WebhookID:      1,
			Event:          "new_critical",
			Payload:        `{}`,
			ResponseStatus: &status,
			Attempt:        1,
			DeliveredAt:    time.Now().Add(time.Duration(i) * time.Second),
			DurationMs:     &durationMs,
		})
	}

	// Also add log for different webhook
	status := 200
	durationMs := 5
	_ = store.CreateDeliveryLog(ctx, &model.WebhookDeliveryLog{
		WebhookID:      2,
		Event:          "new_high",
		Payload:        `{}`,
		ResponseStatus: &status,
		Attempt:        1,
		DeliveredAt:    time.Now(),
		DurationMs:     &durationMs,
	})

	// List logs for webhook 1, limit 3
	logs, err := store.ListDeliveryLogs(ctx, 1, 3)
	if err != nil {
		t.Fatalf("ListDeliveryLogs failed: %v", err)
	}
	if len(logs) != 3 {
		t.Errorf("expected 3 logs, got %d", len(logs))
	}

	// List all logs for webhook 1
	allLogs, err := store.ListDeliveryLogs(ctx, 1, 100)
	if err != nil {
		t.Fatalf("ListDeliveryLogs failed: %v", err)
	}
	if len(allLogs) != 5 {
		t.Errorf("expected 5 logs, got %d", len(allLogs))
	}

	// List logs for webhook 2
	wh2Logs, err := store.ListDeliveryLogs(ctx, 2, 100)
	if err != nil {
		t.Fatalf("ListDeliveryLogs failed: %v", err)
	}
	if len(wh2Logs) != 1 {
		t.Errorf("expected 1 log for webhook 2, got %d", len(wh2Logs))
	}
}

func TestParseTextArray(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{"empty string", "", nil},
		{"empty array", "{}", nil},
		{"single element", "{foo}", []string{"foo"}},
		{"multiple elements", "{foo,bar,baz}", []string{"foo", "bar", "baz"}},
		{"quoted elements", `{"foo bar","baz"}`, []string{"foo bar", "baz"}},
		{"wildcard", "{*}", []string{"*"}},
		{"mixed", `{new_critical,"*",new_high}`, []string{"new_critical", "*", "new_high"}},
		{"escaped quote", `{"say \"hello\"",world}`, []string{`say "hello"`, "world"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseTextArray(tt.input)
			if len(got) != len(tt.want) {
				t.Fatalf("len mismatch: got %d, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("element[%d]: got %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestEventScanner(t *testing.T) {
	tests := []struct {
		name  string
		input interface{}
		want  []string
	}{
		{"nil", nil, nil},
		{"byte slice", []byte("{foo,bar}"), []string{"foo", "bar"}},
		{"string", "{new_critical,*}", []string{"new_critical", "*"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var dest []string
			scanner := &eventScanner{&dest}
			err := scanner.Scan(tt.input)
			if err != nil {
				t.Fatalf("Scan failed: %v", err)
			}
			if len(dest) != len(tt.want) {
				t.Fatalf("len mismatch: got %d, want %d", len(dest), len(tt.want))
			}
			for i := range dest {
				if dest[i] != tt.want[i] {
					t.Errorf("element[%d]: got %q, want %q", i, dest[i], tt.want[i])
				}
			}
		})
	}
}

func TestShouldRetry(t *testing.T) {
	tests := []struct {
		name   string
		status int
		err    error
		want   bool
	}{
		{"success 200", 200, nil, false},
		{"client error 400", 400, nil, false},
		{"client error 404", 404, nil, false},
		{"server error 500", 500, nil, true},
		{"server error 503", 503, nil, true},
		{"connection error", 0, context.DeadlineExceeded, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldRetry(tt.status, tt.err)
			if got != tt.want {
				t.Errorf("shouldRetry(%d, %v) = %v, want %v", tt.status, tt.err, got, tt.want)
			}
		})
	}
}

func TestSeverityName(t *testing.T) {
	tests := []struct {
		level int
		want  string
	}{
		{5, "CRITICAL"},
		{4, "HIGH"},
		{3, "MEDIUM"},
		{2, "LOW"},
		{1, "NONE"},
		{0, "UNKNOWN"},
		{99, "UNKNOWN"},
	}

	for _, tt := range tests {
		got := severityName(tt.level)
		if got != tt.want {
			t.Errorf("severityName(%d) = %q, want %q", tt.level, got, tt.want)
		}
	}
}
