package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kato83/mayu/internal/store"
)

// --- EPSS History with period filter tests ---

func TestGetEPSSHistory_DefaultPeriod(t *testing.T) {
	ms := &mockStore{
		getEPSSHistoryFunc: func(ctx context.Context, vulnID string, since *time.Time) ([]store.EPSSHistoryEntry, error) {
			if vulnID != "CVE-2024-1234" {
				t.Errorf("expected vulnID CVE-2024-1234, got %q", vulnID)
			}
			if since != nil {
				t.Errorf("expected since to be nil for default period, got %v", since)
			}
			return []store.EPSSHistoryEntry{
				{Date: "2024-01-01", EPSS: 0.5, Percentile: 0.9},
				{Date: "2024-01-02", EPSS: 0.6, Percentile: 0.92},
			}, nil
		},
	}
	srv := newTestServer(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities/CVE-2024-1234/epss-history", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["vulnerability_id"] != "CVE-2024-1234" {
		t.Errorf("expected vulnerability_id CVE-2024-1234, got %v", resp["vulnerability_id"])
	}
	if resp["period"] != "all" {
		t.Errorf("expected period 'all', got %v", resp["period"])
	}
	history := resp["history"].([]interface{})
	if len(history) != 2 {
		t.Errorf("expected 2 history entries, got %d", len(history))
	}
}

func TestGetEPSSHistory_With30dPeriod(t *testing.T) {
	ms := &mockStore{
		getEPSSHistoryFunc: func(ctx context.Context, vulnID string, since *time.Time) ([]store.EPSSHistoryEntry, error) {
			if since == nil {
				t.Error("expected since to be non-nil for 30d period")
			}
			return []store.EPSSHistoryEntry{
				{Date: "2024-06-01", EPSS: 0.3, Percentile: 0.8},
			}, nil
		},
	}
	srv := newTestServer(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities/CVE-2024-1234/epss-history?period=30d", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["period"] != "30d" {
		t.Errorf("expected period '30d', got %v", resp["period"])
	}
}

func TestGetEPSSHistory_InvalidPeriod(t *testing.T) {
	srv := newTestServer(&mockStore{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities/CVE-2024-1234/epss-history?period=7d", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["error"] == "" {
		t.Error("expected non-empty error message")
	}
}

func TestGetEPSSHistory_StoreError(t *testing.T) {
	ms := &mockStore{
		getEPSSHistoryFunc: func(ctx context.Context, vulnID string, since *time.Time) ([]store.EPSSHistoryEntry, error) {
			return nil, errors.New("db error")
		},
	}
	srv := newTestServer(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities/CVE-2024-1234/epss-history", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestGetEPSSHistory_EmptyResult(t *testing.T) {
	ms := &mockStore{
		getEPSSHistoryFunc: func(ctx context.Context, vulnID string, since *time.Time) ([]store.EPSSHistoryEntry, error) {
			return nil, nil
		},
	}
	srv := newTestServer(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities/CVE-2024-1234/epss-history", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	history := resp["history"].([]interface{})
	if len(history) != 0 {
		t.Errorf("expected empty history array, got %d entries", len(history))
	}
}

func TestGetEPSSHistory_ValidPeriods(t *testing.T) {
	periods := []string{"30d", "90d", "365d", "all"}
	for _, period := range periods {
		t.Run(period, func(t *testing.T) {
			ms := &mockStore{
				getEPSSHistoryFunc: func(ctx context.Context, vulnID string, since *time.Time) ([]store.EPSSHistoryEntry, error) {
					return nil, nil
				},
			}
			srv := newTestServer(ms)

			req := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities/CVE-2024-1234/epss-history?period="+period, nil)
			w := httptest.NewRecorder()
			srv.httpServer.Handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("expected status 200 for period %q, got %d", period, w.Code)
			}
		})
	}
}

// --- LEV History endpoint tests ---

func TestGetLEVHistory_Success(t *testing.T) {
	ms := &mockStore{
		getLEVHistoryFunc: func(ctx context.Context, vulnID string, since *time.Time) ([]store.LEVHistoryEntry, error) {
			if vulnID != "CVE-2024-1234" {
				t.Errorf("expected vulnID CVE-2024-1234, got %q", vulnID)
			}
			return []store.LEVHistoryEntry{
				{Date: "2024-01-01", LEVScore: 0.01, EPSSScore: 0.5, IsKEV: false},
				{Date: "2024-01-02", LEVScore: 0.02, EPSSScore: 0.6, IsKEV: false},
			}, nil
		},
	}
	srv := newTestServer(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities/CVE-2024-1234/lev-history", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["vulnerability_id"] != "CVE-2024-1234" {
		t.Errorf("expected vulnerability_id CVE-2024-1234, got %v", resp["vulnerability_id"])
	}
	if resp["period"] != "all" {
		t.Errorf("expected period 'all', got %v", resp["period"])
	}
	history := resp["history"].([]interface{})
	if len(history) != 2 {
		t.Errorf("expected 2 history entries, got %d", len(history))
	}
	// Verify first entry structure
	entry := history[0].(map[string]interface{})
	if entry["date"] != "2024-01-01" {
		t.Errorf("expected date 2024-01-01, got %v", entry["date"])
	}
	if entry["lev_score"].(float64) != 0.01 {
		t.Errorf("expected lev_score 0.01, got %v", entry["lev_score"])
	}
	if entry["epss_score"].(float64) != 0.5 {
		t.Errorf("expected epss_score 0.5, got %v", entry["epss_score"])
	}
	if entry["is_kev"].(bool) != false {
		t.Errorf("expected is_kev false, got %v", entry["is_kev"])
	}
}

func TestGetLEVHistory_WithPeriod(t *testing.T) {
	ms := &mockStore{
		getLEVHistoryFunc: func(ctx context.Context, vulnID string, since *time.Time) ([]store.LEVHistoryEntry, error) {
			if since == nil {
				t.Error("expected since to be non-nil for 90d period")
			}
			return []store.LEVHistoryEntry{}, nil
		},
	}
	srv := newTestServer(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities/CVE-2024-1234/lev-history?period=90d", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetLEVHistory_InvalidPeriod(t *testing.T) {
	srv := newTestServer(&mockStore{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities/CVE-2024-1234/lev-history?period=60d", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestGetLEVHistory_StoreError(t *testing.T) {
	ms := &mockStore{
		getLEVHistoryFunc: func(ctx context.Context, vulnID string, since *time.Time) ([]store.LEVHistoryEntry, error) {
			return nil, errors.New("db error")
		},
	}
	srv := newTestServer(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities/CVE-2024-1234/lev-history", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestGetLEVHistory_EmptyResult(t *testing.T) {
	ms := &mockStore{
		getLEVHistoryFunc: func(ctx context.Context, vulnID string, since *time.Time) ([]store.LEVHistoryEntry, error) {
			return nil, nil
		},
	}
	srv := newTestServer(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities/CVE-2024-1234/lev-history", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	history := resp["history"].([]interface{})
	if len(history) != 0 {
		t.Errorf("expected empty history array, got %d entries", len(history))
	}
}

// --- EPSS Trending endpoint tests ---

func TestGetEPSSTrending_Defaults(t *testing.T) {
	ms := &mockStore{
		getEPSSTrendingFunc: func(ctx context.Context, params store.EPSSTrendingQuery) (*store.EPSSTrendingResult, error) {
			if params.Days != 7 {
				t.Errorf("expected default days 7, got %d", params.Days)
			}
			if params.Threshold != 0.1 {
				t.Errorf("expected default threshold 0.1, got %f", params.Threshold)
			}
			if params.Limit != 20 {
				t.Errorf("expected default limit 20, got %d", params.Limit)
			}
			return &store.EPSSTrendingResult{
				Entries: []store.EPSSTrendingEntry{
					{
						VulnerabilityID:   "CVE-2024-5678",
						CVEID:             "CVE-2024-5678",
						CurrentEPSS:       0.85,
						PreviousEPSS:      0.2,
						Delta:             0.65,
						CurrentPercentile: 0.99,
						Severity:          "CRITICAL",
						Summary:           "Critical vuln",
					},
				},
				LatestDate:           "2025-12-31",
				PreviousDate:         "2025-12-24",
				ExpectedPreviousDate: "2025-12-24",
			}, nil
		},
	}
	srv := newTestServer(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/epss/trending", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	query := resp["query"].(map[string]interface{})
	if query["days"].(float64) != 7 {
		t.Errorf("expected query.days 7, got %v", query["days"])
	}
	if query["threshold"].(float64) != 0.1 {
		t.Errorf("expected query.threshold 0.1, got %v", query["threshold"])
	}
	if query["limit"].(float64) != 20 {
		t.Errorf("expected query.limit 20, got %v", query["limit"])
	}
	entries := resp["entries"].([]interface{})
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	entry := entries[0].(map[string]interface{})
	if entry["vulnerability_id"] != "CVE-2024-5678" {
		t.Errorf("expected vulnerability_id CVE-2024-5678, got %v", entry["vulnerability_id"])
	}
	if entry["delta"].(float64) != 0.65 {
		t.Errorf("expected delta 0.65, got %v", entry["delta"])
	}
	if entry["severity"] != "CRITICAL" {
		t.Errorf("expected severity CRITICAL, got %v", entry["severity"])
	}
	// Verify new date fields
	if resp["latest_date"] != "2025-12-31" {
		t.Errorf("expected latest_date 2025-12-31, got %v", resp["latest_date"])
	}
	if resp["previous_date"] != "2025-12-24" {
		t.Errorf("expected previous_date 2025-12-24, got %v", resp["previous_date"])
	}
	// stale should be true since 2025-12-31 is far in the past relative to now (2026-08-02)
	if resp["stale"] != true {
		t.Errorf("expected stale true, got %v", resp["stale"])
	}
	// previous_date_missing should be false when previous_date is set
	if resp["previous_date_missing"] != false {
		t.Errorf("expected previous_date_missing false, got %v", resp["previous_date_missing"])
	}
	// expected_previous_date should match the computed date (latest_date - 7 days)
	if resp["expected_previous_date"] != "2025-12-24" {
		t.Errorf("expected expected_previous_date 2025-12-24, got %v", resp["expected_previous_date"])
	}
	// previous_date_approximate should be false when previous_date == expected_previous_date
	if resp["previous_date_approximate"] != false {
		t.Errorf("expected previous_date_approximate false, got %v", resp["previous_date_approximate"])
	}
}

func TestGetEPSSTrending_CustomParams(t *testing.T) {
	ms := &mockStore{
		getEPSSTrendingFunc: func(ctx context.Context, params store.EPSSTrendingQuery) (*store.EPSSTrendingResult, error) {
			if params.Days != 14 {
				t.Errorf("expected days 14, got %d", params.Days)
			}
			if params.Threshold != 0.05 {
				t.Errorf("expected threshold 0.05, got %f", params.Threshold)
			}
			if params.Limit != 10 {
				t.Errorf("expected limit 10, got %d", params.Limit)
			}
			return &store.EPSSTrendingResult{}, nil
		},
	}
	srv := newTestServer(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/epss/trending?days=14&threshold=0.05&limit=10", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetEPSSTrending_InvalidDays(t *testing.T) {
	tests := []struct {
		name  string
		query string
	}{
		{"non-numeric", "/api/v1/epss/trending?days=abc"},
		{"zero", "/api/v1/epss/trending?days=0"},
		{"negative", "/api/v1/epss/trending?days=-1"},
		{"too large", "/api/v1/epss/trending?days=400"},
	}

	srv := newTestServer(&mockStore{})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.query, nil)
			w := httptest.NewRecorder()
			srv.httpServer.Handler.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected status 400, got %d", w.Code)
			}
		})
	}
}

func TestGetEPSSTrending_InvalidThreshold(t *testing.T) {
	tests := []struct {
		name  string
		query string
	}{
		{"non-numeric", "/api/v1/epss/trending?threshold=abc"},
		{"negative", "/api/v1/epss/trending?threshold=-0.1"},
		{"too large", "/api/v1/epss/trending?threshold=1.5"},
	}

	srv := newTestServer(&mockStore{})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.query, nil)
			w := httptest.NewRecorder()
			srv.httpServer.Handler.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected status 400, got %d", w.Code)
			}
		})
	}
}

func TestGetEPSSTrending_InvalidLimit(t *testing.T) {
	tests := []struct {
		name  string
		query string
	}{
		{"non-numeric", "/api/v1/epss/trending?limit=abc"},
		{"zero", "/api/v1/epss/trending?limit=0"},
		{"negative", "/api/v1/epss/trending?limit=-1"},
		{"too large", "/api/v1/epss/trending?limit=200"},
	}

	srv := newTestServer(&mockStore{})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.query, nil)
			w := httptest.NewRecorder()
			srv.httpServer.Handler.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected status 400, got %d", w.Code)
			}
		})
	}
}

func TestGetEPSSTrending_StoreError(t *testing.T) {
	ms := &mockStore{
		getEPSSTrendingFunc: func(ctx context.Context, params store.EPSSTrendingQuery) (*store.EPSSTrendingResult, error) {
			return nil, errors.New("db error")
		},
	}
	srv := newTestServer(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/epss/trending", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestGetEPSSTrending_EmptyResult(t *testing.T) {
	ms := &mockStore{
		getEPSSTrendingFunc: func(ctx context.Context, params store.EPSSTrendingQuery) (*store.EPSSTrendingResult, error) {
			return &store.EPSSTrendingResult{
				LatestDate:           "2026-08-01",
				PreviousDate:         "2026-07-25",
				ExpectedPreviousDate: "2026-07-25",
			}, nil
		},
	}
	srv := newTestServer(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/epss/trending", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	entries := resp["entries"].([]interface{})
	if len(entries) != 0 {
		t.Errorf("expected empty entries array, got %d entries", len(entries))
	}
	// Verify dates are still returned even when entries is empty
	if resp["latest_date"] != "2026-08-01" {
		t.Errorf("expected latest_date 2026-08-01, got %v", resp["latest_date"])
	}
	if resp["previous_date"] != "2026-07-25" {
		t.Errorf("expected previous_date 2026-07-25, got %v", resp["previous_date"])
	}
}

func TestGetEPSSTrending_StaleFlag(t *testing.T) {
	today := time.Now().UTC().Format("2006-01-02")
	yesterday := time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02")
	weekAgo := time.Now().UTC().AddDate(0, 0, -8).Format("2006-01-02")
	threeDaysAgo := time.Now().UTC().AddDate(0, 0, -3).Format("2006-01-02")

	tests := []struct {
		name         string
		latestDate   string
		previousDate string
		wantStale    bool
	}{
		{"today - not stale", today, weekAgo, false},
		{"yesterday - not stale", yesterday, weekAgo, false},
		{"3 days ago - stale", threeDaysAgo, weekAgo, true},
		{"empty date - not stale", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ms := &mockStore{
				getEPSSTrendingFunc: func(ctx context.Context, params store.EPSSTrendingQuery) (*store.EPSSTrendingResult, error) {
					return &store.EPSSTrendingResult{
						LatestDate:   tt.latestDate,
						PreviousDate: tt.previousDate,
					}, nil
				},
			}
			srv := newTestServer(ms)

			req := httptest.NewRequest(http.MethodGet, "/api/v1/epss/trending", nil)
			w := httptest.NewRecorder()
			srv.httpServer.Handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
			}

			var resp map[string]interface{}
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}
			if got := resp["stale"].(bool); got != tt.wantStale {
				t.Errorf("expected stale=%v, got %v (latest_date=%s)", tt.wantStale, got, tt.latestDate)
			}
		})
	}
}

func TestGetEPSSTrending_PreviousDateMissing(t *testing.T) {
	today := time.Now().UTC().Format("2006-01-02")

	tests := []struct {
		name         string
		latestDate   string
		previousDate string
		wantMissing  bool
	}{
		{"previous_date present", today, "2026-07-25", false},
		{"previous_date empty", today, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ms := &mockStore{
				getEPSSTrendingFunc: func(ctx context.Context, params store.EPSSTrendingQuery) (*store.EPSSTrendingResult, error) {
					return &store.EPSSTrendingResult{
						LatestDate:   tt.latestDate,
						PreviousDate: tt.previousDate,
					}, nil
				},
			}
			srv := newTestServer(ms)

			req := httptest.NewRequest(http.MethodGet, "/api/v1/epss/trending", nil)
			w := httptest.NewRecorder()
			srv.httpServer.Handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
			}

			var resp map[string]interface{}
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}
			if got := resp["previous_date_missing"].(bool); got != tt.wantMissing {
				t.Errorf("expected previous_date_missing=%v, got %v", tt.wantMissing, got)
			}
		})
	}
}

func TestGetEPSSTrending_PreviousDateApproximate(t *testing.T) {
	tests := []struct {
		name                 string
		latestDate           string
		previousDate         string
		expectedPreviousDate string
		wantApproximate      bool
	}{
		{
			name:                 "exact match - not approximate",
			latestDate:           "2026-08-01",
			previousDate:         "2026-07-25",
			expectedPreviousDate: "2026-07-25",
			wantApproximate:      false,
		},
		{
			name:                 "data gap - approximate",
			latestDate:           "2026-08-01",
			previousDate:         "2026-07-24",
			expectedPreviousDate: "2026-07-25",
			wantApproximate:      true,
		},
		{
			name:                 "empty previous_date - not approximate",
			latestDate:           "2026-08-01",
			previousDate:         "",
			expectedPreviousDate: "2026-07-25",
			wantApproximate:      false,
		},
		{
			name:                 "empty expected - not approximate",
			latestDate:           "",
			previousDate:         "",
			expectedPreviousDate: "",
			wantApproximate:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ms := &mockStore{
				getEPSSTrendingFunc: func(ctx context.Context, params store.EPSSTrendingQuery) (*store.EPSSTrendingResult, error) {
					return &store.EPSSTrendingResult{
						LatestDate:           tt.latestDate,
						PreviousDate:         tt.previousDate,
						ExpectedPreviousDate: tt.expectedPreviousDate,
					}, nil
				},
			}
			srv := newTestServer(ms)

			req := httptest.NewRequest(http.MethodGet, "/api/v1/epss/trending", nil)
			w := httptest.NewRecorder()
			srv.httpServer.Handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
			}

			var resp map[string]interface{}
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}

			gotApprox := resp["previous_date_approximate"].(bool)
			if gotApprox != tt.wantApproximate {
				t.Errorf("expected previous_date_approximate=%v, got %v", tt.wantApproximate, gotApprox)
			}

			gotExpected := resp["expected_previous_date"]
			if gotExpected != tt.expectedPreviousDate {
				t.Errorf("expected expected_previous_date=%q, got %v", tt.expectedPreviousDate, gotExpected)
			}
		})
	}
}
