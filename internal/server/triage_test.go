package server

import (
	"context"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kato83/mayu/internal/auth"
	"github.com/kato83/mayu/internal/triage"
)

// TestHandleTriageBatch_Success tests POST /api/v1/triage with vulnerability IDs.
// Validates: Requirements 7.1, 7.3
func TestHandleTriageBatch_Success(t *testing.T) {
	srv := newTestServer(&mockStore{})

	body := map[string]interface{}{
		"vulnerability_ids": []string{"CVE-2024-1234", "CVE-2024-5678"},
		"profile":           "default",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/triage", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d, body: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Summary     map[string]int        `json:"summary"`
		Results     []triage.TriageResult `json:"results"`
		ProfileUsed string                `json:"profile_used"`
		ComputedAt  string                `json:"computed_at"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.ProfileUsed != "default" {
		t.Errorf("expected profile_used 'default', got %q", resp.ProfileUsed)
	}
	if resp.Summary["total"] != 2 {
		t.Errorf("expected summary.total=2, got %d", resp.Summary["total"])
	}
	if len(resp.Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(resp.Results))
	}
	if resp.ComputedAt == "" {
		t.Error("expected non-empty computed_at")
	}

	// Verify each result has required fields
	for _, r := range resp.Results {
		if r.VulnerabilityID == "" {
			t.Error("expected non-empty vulnerability_id")
		}
		if r.PriorityLevel == "" {
			t.Error("expected non-empty priority_level")
		}
		if r.ProfileUsed == "" {
			t.Error("expected non-empty profile_used in result")
		}
	}
}

// TestHandleTriageBatch_InvalidBody tests POST /api/v1/triage with invalid request.
// Validates: Requirements 7.1
func TestHandleTriageBatch_InvalidBody(t *testing.T) {
	srv := newTestServer(&mockStore{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/triage", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

// TestHandleTriageBatch_MissingIDs tests POST /api/v1/triage with no vulnerability_ids or project_id.
// Validates: Requirements 7.1
func TestHandleTriageBatch_MissingIDs(t *testing.T) {
	srv := newTestServer(&mockStore{})

	body := map[string]interface{}{
		"vulnerability_ids": []string{},
		"project_id":        "",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/triage", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

// TestHandleTriageBatch_WithProfile tests POST /api/v1/triage with profile selection.
// Validates: Requirements 7.4
func TestHandleTriageBatch_WithProfile(t *testing.T) {
	srv := newTestServer(&mockStore{})

	body := map[string]interface{}{
		"vulnerability_ids": []string{"CVE-2024-0001"},
		"profile":           "internet-facing",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/triage", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		ProfileUsed string `json:"profile_used"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.ProfileUsed != "internet-facing" {
		t.Errorf("expected profile_used 'internet-facing', got %q", resp.ProfileUsed)
	}
}

// TestHandleGetVulnerabilityTriage_Success tests GET /api/v1/vulnerabilities/{id}/triage.
// Validates: Requirements 7.2, 7.3
func TestHandleGetVulnerabilityTriage_Success(t *testing.T) {
	srv := newTestServer(&mockStore{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities/CVE-2024-1234/triage", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d, body: %s", w.Code, w.Body.String())
	}

	var result triage.TriageResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if result.VulnerabilityID != "CVE-2024-1234" {
		t.Errorf("expected vulnerability_id 'CVE-2024-1234', got %q", result.VulnerabilityID)
	}
	if result.PriorityLevel == "" {
		t.Error("expected non-empty priority_level")
	}
	if result.CompositeScore < 0 || result.CompositeScore > 1 {
		t.Errorf("expected composite_score in [0,1], got %f", result.CompositeScore)
	}
	if result.ProfileUsed == "" {
		t.Error("expected non-empty profile_used")
	}
	if result.Rationale == nil {
		t.Error("expected non-nil rationale")
	}
}

// TestHandleGetVulnerabilityTriage_WithProfile tests GET /api/v1/vulnerabilities/{id}/triage?profile=internet-facing.
// Validates: Requirements 7.4
func TestHandleGetVulnerabilityTriage_WithProfile(t *testing.T) {
	srv := newTestServer(&mockStore{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities/CVE-2024-9999/triage?profile=internet-facing", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var result triage.TriageResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.ProfileUsed != "internet-facing" {
		t.Errorf("expected profile_used 'internet-facing', got %q", result.ProfileUsed)
	}
}

// TestHandleTriageOverviewVulnerabilities tests GET /api/v1/triage/overview/vulnerabilities.
// Validates: Requirements 9.1
func TestHandleTriageOverviewVulnerabilities(t *testing.T) {
	srv := newTestServer(&mockStore{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/triage/overview/vulnerabilities", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d, body: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Vulnerabilities []interface{}       `json:"vulnerabilities"`
		Summary         triage.OverviewSummary `json:"summary"`
		ComputedAt      string              `json:"computed_at"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.ComputedAt == "" {
		t.Error("expected non-empty computed_at")
	}
}

// TestHandleTriageOverviewVulnerabilities_WithFilter tests query parameter filtering.
// Validates: Requirements 9.1
func TestHandleTriageOverviewVulnerabilities_WithFilter(t *testing.T) {
	srv := newTestServer(&mockStore{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/triage/overview/vulnerabilities?priority=critical&limit=10&sort=score", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
}

// TestHandleListTriagePaths tests GET /api/v1/triage/paths.
// Validates: Requirements 9.1
func TestHandleListTriagePaths(t *testing.T) {
	srv := newTestServer(&mockStore{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/triage/paths", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d, body: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Paths      []interface{} `json:"paths"`
		Total      int           `json:"total"`
		ComputedAt string        `json:"computed_at"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.ComputedAt == "" {
		t.Error("expected non-empty computed_at")
	}
}

// TestHandleListTriagePaths_WithFilters tests query parameters on GET /api/v1/triage/paths.
// Validates: Requirements 9.1
func TestHandleListTriagePaths_WithFilters(t *testing.T) {
	srv := newTestServer(&mockStore{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/triage/paths?limit=5&priority=critical&ecosystem=npm", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
}

// TestHandleSetServerProfile tests PUT /api/v1/sbom/projects/{id}/servers/{label}/profile roundtrip.
// Validates: Requirements 7.4 (binding API)
func TestHandleSetServerProfile(t *testing.T) {
	ms := &mockStore{}
	srv := New(Config{
		Addr:         ":0",
		Store:        ms,
		Version:      "test",
		AuthProvider: auth.NewNoAuthProvider(),
		SBOMStore:    &mockSBOMStoreForPortfolio{},
	})

	t.Run("set profile binding", func(t *testing.T) {
		body := map[string]string{
			"profile_name": "internet-facing",
			"description":  "API production server",
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/sbom/projects/proj-1/servers/api-prod/profile", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d, body: %s", w.Code, w.Body.String())
		}

		var resp map[string]interface{}
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if resp["profile_name"] != "internet-facing" {
			t.Errorf("expected profile_name 'internet-facing', got %v", resp["profile_name"])
		}
		if resp["server_label"] != "api-prod" {
			t.Errorf("expected server_label 'api-prod', got %v", resp["server_label"])
		}
	})

	t.Run("get bindings after set", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/sbom/projects/proj-1/servers", nil)
		w := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("set profile with missing profile_name", func(t *testing.T) {
		body := map[string]string{
			"description": "Missing profile name",
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/sbom/projects/proj-1/servers/web-prod/profile", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", w.Code)
		}
	})
}

// TestHandleTriageOverview_MaxPriority tests that cross-project aggregation uses max priority.
// Validates: Requirements 9.1
func TestHandleTriageOverview_MaxPriority(t *testing.T) {
	// Test the aggregation logic directly
	entries := []triage.ServerTriageEntry{
		{
			ProjectID:   1,
			ProjectName: "service-a",
			ServerLabel: "api-prod",
			ProfileUsed: "internet-facing",
			TriageResult: &triage.TriageResult{
				VulnerabilityID: "CVE-2024-1234",
				PriorityLevel:   triage.PriorityCritical,
				CompositeScore:  0.92,
			},
		},
		{
			ProjectID:   2,
			ProjectName: "service-b",
			ServerLabel: "admin-internal",
			ProfileUsed: "internal-only",
			TriageResult: &triage.TriageResult{
				VulnerabilityID: "CVE-2024-1234",
				PriorityLevel:   triage.PriorityMedium,
				CompositeScore:  0.55,
			},
		},
	}

	result := triage.AggregateCrossProject("CVE-2024-1234", entries)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.OrgPriorityLevel != triage.PriorityCritical {
		t.Errorf("expected org_priority_level Critical, got %s", result.OrgPriorityLevel)
	}
	if result.MaxCompositeScore != 0.92 {
		t.Errorf("expected max_composite_score 0.92, got %f", result.MaxCompositeScore)
	}
	if result.AffectedServers != 2 {
		t.Errorf("expected affected_servers 2, got %d", result.AffectedServers)
	}
	if result.AffectedProjects != 2 {
		t.Errorf("expected affected_projects 2, got %d", result.AffectedProjects)
	}
}

// TestHandleDashboardTriage tests GET /api/v1/dashboard/triage.
// Validates: Requirements 11.1
func TestHandleDashboardTriage(t *testing.T) {
	srv := newTestServer(&mockStore{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/triage", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var resp struct {
		ByPriority   map[string]int `json:"by_priority"`
		TotalTriaged int            `json:"total_triaged"`
		ProfileUsed  string         `json:"profile_used"`
		LastComputed string         `json:"last_computed"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.ByPriority == nil {
		t.Error("expected non-nil by_priority")
	}
	if resp.ProfileUsed == "" {
		t.Error("expected non-empty profile_used")
	}
}

// TestHandleListTriageProfiles tests GET /api/v1/triage/profiles.
func TestHandleListTriageProfiles(t *testing.T) {
	srv := newTestServer(&mockStore{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/triage/profiles", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		Profiles []triage.Profile `json:"profiles"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Profiles) < 4 {
		t.Errorf("expected at least 4 profiles (default, internet-facing, internal-only, air-gapped), got %d", len(resp.Profiles))
	}
}

// TestHandleValidateTriageProfile_Valid tests POST /api/v1/triage/profiles/validate with valid profile.
func TestHandleValidateTriageProfile_Valid(t *testing.T) {
	srv := newTestServer(&mockStore{})

	profile := triage.Profile{
		Name:        "test",
		Description: "Test profile",
		Weights: &triage.ExtendedWeights{
			CVSS: 0.20, EPSS: 0.20, LEV: 0.15, KEV: 0.15,
			Patch: 0.08, Age: 0.05, ExploitDB: 0.10, Reachability: 0.07,
		},
		Thresholds: &triage.Thresholds{Critical: 0.85, High: 0.65, Medium: 0.40},
	}
	bodyBytes, _ := json.Marshal(profile)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/triage/profiles/validate", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d, body: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Valid bool `json:"valid"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Valid {
		t.Error("expected valid=true")
	}
}

// TestHandleValidateTriageProfile_Invalid tests POST /api/v1/triage/profiles/validate with invalid profile.
func TestHandleValidateTriageProfile_Invalid(t *testing.T) {
	srv := newTestServer(&mockStore{})

	profile := triage.Profile{
		Name:        "bad",
		Description: "Invalid profile",
		Weights: &triage.ExtendedWeights{
			CVSS: 0.50, EPSS: 0.50, LEV: 0.50, KEV: 0.00,
			Patch: 0.00, Age: 0.00, ExploitDB: 0.00, Reachability: 0.00,
		},
		Thresholds: &triage.Thresholds{Critical: 0.85, High: 0.65, Medium: 0.40},
	}
	bodyBytes, _ := json.Marshal(profile)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/triage/profiles/validate", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", w.Code)
	}

	var resp struct {
		Valid  bool     `json:"valid"`
		Errors []string `json:"errors"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Valid {
		t.Error("expected valid=false")
	}
	if len(resp.Errors) == 0 {
		t.Error("expected at least one error")
	}
}

// TestWatchlistNotificationPayload tests that Critical triage results include triage info in notification payload.
// Validates: Requirements 11.1
func TestWatchlistNotificationPayload(t *testing.T) {
	// Test the triage engine produces data that can be used in notification payload
	engine := triage.NewEngine(triage.DefaultProfile())

	cvss := 9.8
	epss := 0.97
	input := &triage.TriageInput{
		VulnerabilityID: "CVE-2024-CRIT",
		CVSSScore:       &cvss,
		EPSSScore:       &epss,
		InKEV:           true,
		HasExploit:      true,
	}

	result, err := engine.Triage(context.TODO(), input)
	if err != nil {
		t.Fatalf("triage failed: %v", err)
	}

	// Verify the result has the fields needed for notification payload
	if result.PriorityLevel != triage.PriorityCritical {
		t.Errorf("expected Critical priority for high-risk vuln, got %s", result.PriorityLevel)
	}
	if result.CompositeScore <= 0 {
		t.Error("expected positive composite_score")
	}
	if result.SSVCDecision == "" {
		t.Error("expected non-empty ssvc_decision")
	}

	// Verify JSON serialization includes all notification payload fields
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}

	requiredFields := []string{"priority_level", "composite_score", "ssvc_decision"}
	for _, field := range requiredFields {
		if _, ok := payload[field]; !ok {
			t.Errorf("notification payload missing required field: %s", field)
		}
	}
}


