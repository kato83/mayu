package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kato83/mayu/internal/model"
	"github.com/kato83/mayu/internal/store"
)

// mockStore implements store.Store for testing.
type mockStore struct {
	getByIDFunc                func(ctx context.Context, id string) (*model.Vulnerability, error)
	getVulnerabilityDetailFunc func(ctx context.Context, id string) (*model.VulnerabilityDetail, error)
	searchFunc                 func(ctx context.Context, query store.SearchQuery) ([]*model.Vulnerability, error)
	countFunc                  func(ctx context.Context, query store.SearchQuery) (int64, error)
	listIngestJobsFunc         func(ctx context.Context, limit int) ([]store.IngestJob, error)
	getIngestJobFunc           func(ctx context.Context, id int64) (*store.IngestJob, error)
	listSyncStatesFunc         func(ctx context.Context) ([]store.SyncState, error)
	getEPSSCoverageFunc        func(ctx context.Context) (*store.EPSSCoverage, error)
}

func (m *mockStore) Insert(ctx context.Context, vuln *model.Vulnerability) error { return nil }
func (m *mockStore) UpsertBatch(ctx context.Context, vulns []*model.Vulnerability) error {
	return nil
}
func (m *mockStore) GetByID(ctx context.Context, id string) (*model.Vulnerability, error) {
	if m.getByIDFunc != nil {
		return m.getByIDFunc(ctx, id)
	}
	return nil, nil
}
func (m *mockStore) GetVulnerabilityDetail(ctx context.Context, id string) (*model.VulnerabilityDetail, error) {
	if m.getVulnerabilityDetailFunc != nil {
		return m.getVulnerabilityDetailFunc(ctx, id)
	}
	return nil, nil
}
func (m *mockStore) Search(ctx context.Context, query store.SearchQuery) ([]*model.Vulnerability, error) {
	if m.searchFunc != nil {
		return m.searchFunc(ctx, query)
	}
	return nil, nil
}
func (m *mockStore) Count(ctx context.Context, query store.SearchQuery) (int64, error) {
	if m.countFunc != nil {
		return m.countFunc(ctx, query)
	}
	return 0, nil
}
func (m *mockStore) GetSyncState(ctx context.Context, source string) (*store.SyncState, error) {
	return nil, nil
}
func (m *mockStore) UpdateSyncState(ctx context.Context, state *store.SyncState) error { return nil }
func (m *mockStore) RefreshSummary(ctx context.Context, vulnIDs []string) error        { return nil }
func (m *mockStore) RefreshEPSSSummary(ctx context.Context, vulnIDs []string) error    { return nil }
func (m *mockStore) UpsertProductIdentifiers(ctx context.Context, identifiers []*model.ProductIdentifier) error {
	return nil
}
func (m *mockStore) Close() error { return nil }
func (m *mockStore) ListOSVEcosystems(ctx context.Context) ([]string, error) {
	return []string{"Go", "npm", "PyPI"}, nil
}
func (m *mockStore) UpsertOSVEcosystems(ctx context.Context, names []string) error { return nil }
func (m *mockStore) SearchByPackages(ctx context.Context, packages []store.PackageQuery) (map[string][]*model.Vulnerability, error) {
	return nil, nil
}
func (m *mockStore) CreateIngestJob(ctx context.Context, job *store.IngestJob) (int64, error) {
	return 0, nil
}
func (m *mockStore) UpdateIngestJob(ctx context.Context, job *store.IngestJob) error { return nil }
func (m *mockStore) RecordIngestFailure(ctx context.Context, failure *store.IngestFailure) error {
	return nil
}
func (m *mockStore) RecordIngestFailures(ctx context.Context, failures []store.IngestFailure) error {
	return nil
}
func (m *mockStore) ListIngestJobs(ctx context.Context, limit int) ([]store.IngestJob, error) {
	if m.listIngestJobsFunc != nil {
		return m.listIngestJobsFunc(ctx, limit)
	}
	return nil, nil
}
func (m *mockStore) GetIngestJob(ctx context.Context, id int64) (*store.IngestJob, error) {
	if m.getIngestJobFunc != nil {
		return m.getIngestJobFunc(ctx, id)
	}
	return nil, nil
}
func (m *mockStore) ListSyncStates(ctx context.Context) ([]store.SyncState, error) {
	if m.listSyncStatesFunc != nil {
		return m.listSyncStatesFunc(ctx)
	}
	return nil, nil
}
func (m *mockStore) GetEPSSCoverage(ctx context.Context) (*store.EPSSCoverage, error) {
	if m.getEPSSCoverageFunc != nil {
		return m.getEPSSCoverageFunc(ctx)
	}
	return &store.EPSSCoverage{}, nil
}

// newTestServer creates a Server with the given mock store for testing.
func newTestServer(ms *mockStore) *Server {
	return New(Config{
		Addr:    ":0",
		Store:   ms,
		Version: "test-v1.0.0",
	})
}

func TestHealthCheck(t *testing.T) {
	srv := newTestServer(&mockStore{})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("expected status ok, got %q", body["status"])
	}
	if body["version"] != "test-v1.0.0" {
		t.Errorf("expected version test-v1.0.0, got %q", body["version"])
	}
}

func TestOpenAPISpec(t *testing.T) {
	srv := newTestServer(&mockStore{})

	req := httptest.NewRequest(http.MethodGet, "/openapi.yaml", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/yaml; charset=utf-8" {
		t.Errorf("expected Content-Type application/yaml; charset=utf-8, got %q", ct)
	}
	// Should not have a duplicate Access-Control-Allow-Origin set by the handler
	// (CORS middleware handles this globally)
	body := w.Body.String()
	if len(body) == 0 {
		t.Error("expected non-empty OpenAPI spec body")
	}
	if body[:7] != "openapi" {
		t.Errorf("expected body to start with 'openapi', got %q", body[:20])
	}
}

func TestSearchVulnerabilities_Success(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	rawJSON := json.RawMessage(`{"id":"GO-2024-2687","modified":"2024-06-01T00:00:00Z","summary":"test vuln"}`)

	ms := &mockStore{
		countFunc: func(ctx context.Context, query store.SearchQuery) (int64, error) {
			if query.Ecosystem != "Go" {
				t.Errorf("expected ecosystem Go, got %q", query.Ecosystem)
			}
			return 1, nil
		},
		searchFunc: func(ctx context.Context, query store.SearchQuery) ([]*model.Vulnerability, error) {
			if query.Limit != 5 {
				t.Errorf("expected limit 5, got %d", query.Limit)
			}
			return []*model.Vulnerability{
				{
					ID:       "GO-2024-2687",
					Modified: now,
					Summary:  "test vuln",
					RawJSON:  rawJSON,
				},
			}, nil
		},
	}
	srv := newTestServer(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities?ecosystem=Go&limit=5", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	// Check X-Total-Count header
	if tc := w.Header().Get("X-Total-Count"); tc != "1" {
		t.Errorf("expected X-Total-Count 1, got %q", tc)
	}

	var resp SearchResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Total != 1 {
		t.Errorf("expected total 1, got %d", resp.Total)
	}
	if resp.Limit != 5 {
		t.Errorf("expected limit 5, got %d", resp.Limit)
	}
	if len(resp.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(resp.Vulnerabilities))
	}
	// Verify raw JSON is passed through
	var vuln map[string]interface{}
	if err := json.Unmarshal(resp.Vulnerabilities[0], &vuln); err != nil {
		t.Fatalf("failed to unmarshal vulnerability: %v", err)
	}
	if vuln["id"] != "GO-2024-2687" {
		t.Errorf("expected id GO-2024-2687, got %v", vuln["id"])
	}
}

func TestSearchVulnerabilities_NoParams(t *testing.T) {
	srv := newTestServer(&mockStore{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if _, ok := body["vulnerabilities"]; !ok {
		t.Error("response should contain 'vulnerabilities' key")
	}
}

func TestSearchVulnerabilities_InvalidLimit(t *testing.T) {
	srv := newTestServer(&mockStore{})

	tests := []struct {
		name  string
		query string
	}{
		{"non-numeric", "/api/v1/vulnerabilities?ecosystem=Go&limit=abc"},
		{"zero", "/api/v1/vulnerabilities?ecosystem=Go&limit=0"},
		{"negative", "/api/v1/vulnerabilities?ecosystem=Go&limit=-1"},
	}

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

func TestSearchVulnerabilities_InvalidOffset(t *testing.T) {
	srv := newTestServer(&mockStore{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities?ecosystem=Go&offset=-1", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestSearchVulnerabilities_InvalidSeverity(t *testing.T) {
	srv := newTestServer(&mockStore{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities?severity=extreme", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}

	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if body["error"] == "" {
		t.Error("expected non-empty error message")
	}
}

func TestSearchVulnerabilities_InvalidSince(t *testing.T) {
	srv := newTestServer(&mockStore{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities?since=not-a-date", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestSearchVulnerabilities_LimitCap(t *testing.T) {
	ms := &mockStore{
		countFunc: func(ctx context.Context, query store.SearchQuery) (int64, error) {
			return 0, nil
		},
		searchFunc: func(ctx context.Context, query store.SearchQuery) ([]*model.Vulnerability, error) {
			if query.Limit != 1000 {
				t.Errorf("expected limit capped at 1000, got %d", query.Limit)
			}
			return nil, nil
		},
	}
	srv := newTestServer(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities?ecosystem=Go&limit=9999", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
}

func TestSearchVulnerabilities_StoreError(t *testing.T) {
	ms := &mockStore{
		countFunc: func(ctx context.Context, query store.SearchQuery) (int64, error) {
			return 0, errors.New("db connection failed")
		},
	}
	srv := newTestServer(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities?ecosystem=Go", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}

	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if body["error"] != "internal server error" {
		t.Errorf("expected generic error message, got %q", body["error"])
	}
}

func TestGetVulnerability_Success(t *testing.T) {
	rawJSON := json.RawMessage(`{"id":"GO-2024-2687","modified":"2024-06-01T00:00:00Z","summary":"test"}`)

	ms := &mockStore{
		getByIDFunc: func(ctx context.Context, id string) (*model.Vulnerability, error) {
			if id != "GO-2024-2687" {
				t.Errorf("expected id GO-2024-2687, got %q", id)
			}
			return &model.Vulnerability{
				ID:      "GO-2024-2687",
				RawJSON: rawJSON,
			}, nil
		},
	}
	srv := newTestServer(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities/GO-2024-2687", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}

	// Should return raw JSON directly
	var vuln map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&vuln); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if vuln["id"] != "GO-2024-2687" {
		t.Errorf("expected id GO-2024-2687, got %v", vuln["id"])
	}
}

func TestGetVulnerability_NotFound(t *testing.T) {
	ms := &mockStore{
		getByIDFunc: func(ctx context.Context, id string) (*model.Vulnerability, error) {
			return nil, nil
		},
	}
	srv := newTestServer(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities/NONEXISTENT", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", w.Code)
	}

	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if body["error"] == "" {
		t.Error("expected non-empty error message")
	}
}

func TestGetVulnerability_StoreError(t *testing.T) {
	ms := &mockStore{
		getByIDFunc: func(ctx context.Context, id string) (*model.Vulnerability, error) {
			return nil, errors.New("db timeout")
		},
	}
	srv := newTestServer(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities/GO-2024-2687", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestGetVulnerability_FallbackMarshal(t *testing.T) {
	// When RawJSON is nil, the handler should marshal the struct
	now := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	ms := &mockStore{
		getByIDFunc: func(ctx context.Context, id string) (*model.Vulnerability, error) {
			return &model.Vulnerability{
				ID:       "GO-2024-2687",
				Modified: now,
				Summary:  "fallback test",
			}, nil
		},
	}
	srv := newTestServer(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities/GO-2024-2687", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var vuln map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&vuln); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if vuln["id"] != "GO-2024-2687" {
		t.Errorf("expected id GO-2024-2687, got %v", vuln["id"])
	}
	if vuln["summary"] != "fallback test" {
		t.Errorf("expected summary 'fallback test', got %v", vuln["summary"])
	}
}

func TestSearchVulnerabilities_ValidSeverities(t *testing.T) {
	validSeverities := []string{"critical", "high", "medium", "low", "none", "unknown"}

	for _, sev := range validSeverities {
		t.Run(sev, func(t *testing.T) {
			ms := &mockStore{
				countFunc: func(ctx context.Context, query store.SearchQuery) (int64, error) {
					if query.Severity != sev {
						t.Errorf("expected severity %q, got %q", sev, query.Severity)
					}
					return 0, nil
				},
				searchFunc: func(ctx context.Context, query store.SearchQuery) ([]*model.Vulnerability, error) {
					return nil, nil
				},
			}
			srv := newTestServer(ms)

			req := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities?severity="+sev, nil)
			w := httptest.NewRecorder()
			srv.httpServer.Handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("expected status 200 for severity %q, got %d", sev, w.Code)
			}
		})
	}
}

func TestSearchVulnerabilities_ValidSince(t *testing.T) {
	tests := []struct {
		name  string
		since string
	}{
		{"date", "2024-01-15"},
		{"rfc3339", "2024-01-15T00:00:00Z"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ms := &mockStore{
				countFunc: func(ctx context.Context, query store.SearchQuery) (int64, error) {
					return 0, nil
				},
				searchFunc: func(ctx context.Context, query store.SearchQuery) ([]*model.Vulnerability, error) {
					return nil, nil
				},
			}
			srv := newTestServer(ms)

			req := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities?since="+tt.since, nil)
			w := httptest.NewRecorder()
			srv.httpServer.Handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("expected status 200 for since %q, got %d", tt.since, w.Code)
			}
		})
	}
}

func TestSearchVulnerabilities_DefaultLimitAndOffset(t *testing.T) {
	ms := &mockStore{
		countFunc: func(ctx context.Context, query store.SearchQuery) (int64, error) {
			return 0, nil
		},
		searchFunc: func(ctx context.Context, query store.SearchQuery) ([]*model.Vulnerability, error) {
			if query.Limit != 20 {
				t.Errorf("expected default limit 20, got %d", query.Limit)
			}
			if query.Offset != 0 {
				t.Errorf("expected default offset 0, got %d", query.Offset)
			}
			return nil, nil
		},
	}
	srv := newTestServer(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities?ecosystem=Go", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
}

func TestSearchVulnerabilities_CursorParam(t *testing.T) {
	now := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	validCursor := store.EncodeCursor(&now, "GO-2024-2687")

	ms := &mockStore{
		countFunc: func(ctx context.Context, query store.SearchQuery) (int64, error) {
			return 10, nil
		},
		searchFunc: func(ctx context.Context, query store.SearchQuery) ([]*model.Vulnerability, error) {
			if query.Cursor != validCursor {
				t.Errorf("expected cursor %q, got %q", validCursor, query.Cursor)
			}
			return nil, nil
		},
	}
	srv := newTestServer(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities?cursor="+validCursor, nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
}

func TestSearchVulnerabilities_InvalidCursor(t *testing.T) {
	srv := newTestServer(&mockStore{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities?cursor=invalid!!!", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}

	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if body["error"] == "" {
		t.Error("expected non-empty error message")
	}
}

func TestSearchVulnerabilities_NextCursorInResponse(t *testing.T) {
	pub := time.Date(2024, 6, 2, 0, 0, 0, 0, time.UTC)
	rawJSON := json.RawMessage(`{"id":"GO-2024-2688","modified":"2024-06-02T00:00:00Z"}`)

	ms := &mockStore{
		countFunc: func(ctx context.Context, query store.SearchQuery) (int64, error) {
			return 50, nil
		},
		searchFunc: func(ctx context.Context, query store.SearchQuery) ([]*model.Vulnerability, error) {
			// Return exactly limit items to trigger next_cursor generation
			results := make([]*model.Vulnerability, query.Limit)
			for i := range results {
				results[i] = &model.Vulnerability{
					ID:        "GO-2024-2688",
					Modified:  pub,
					Published: &pub,
					RawJSON:   rawJSON,
				}
			}
			return results, nil
		},
	}
	srv := newTestServer(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities?ecosystem=Go&limit=5", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var resp SearchResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.NextCursor == "" {
		t.Error("expected non-empty next_cursor when results == limit")
	}

	// Verify the cursor can be decoded
	cursor, err := store.DecodeCursor(resp.NextCursor)
	if err != nil {
		t.Fatalf("failed to decode next_cursor: %v", err)
	}
	if cursor.ID != "GO-2024-2688" {
		t.Errorf("expected cursor ID GO-2024-2688, got %q", cursor.ID)
	}
}

func TestSearchVulnerabilities_NoNextCursorWhenFewerResults(t *testing.T) {
	pub := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	rawJSON := json.RawMessage(`{"id":"GO-2024-2687","modified":"2024-06-01T00:00:00Z"}`)

	ms := &mockStore{
		countFunc: func(ctx context.Context, query store.SearchQuery) (int64, error) {
			return 1, nil
		},
		searchFunc: func(ctx context.Context, query store.SearchQuery) ([]*model.Vulnerability, error) {
			return []*model.Vulnerability{
				{ID: "GO-2024-2687", Modified: pub, Published: &pub, RawJSON: rawJSON},
			}, nil
		},
	}
	srv := newTestServer(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities?limit=20", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var resp SearchResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.NextCursor != "" {
		t.Errorf("expected empty next_cursor when results < limit, got %q", resp.NextCursor)
	}
}
