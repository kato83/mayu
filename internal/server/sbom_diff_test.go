package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kato83/mayu/internal/auth"
	"github.com/kato83/mayu/internal/sbommon"
)

func TestHandleSBOMVersionDiff_Success(t *testing.T) {
	ms := &mockStore{}
	sbomStore := &mockSBOMStoreForPortfolio{
		projects: []*sbommon.SBOMProject{
			{ID: 1, UserID: 1, Name: "my-app"},
		},
		versions: map[int64]*sbommon.SBOMVersion{
			10: {
				ID:        10,
				ProjectID: 1,
				Version:   "2.0.0",
				RawSBOM:   []byte(`{"components":[{"purl":"pkg:npm/foo@2.0.0"},{"purl":"pkg:npm/new-pkg@1.0.0"},{"purl":"pkg:npm/baz@1.0.0"}]}`),
			},
			20: {
				ID:        20,
				ProjectID: 1,
				Version:   "1.0.0",
				RawSBOM:   []byte(`{"components":[{"purl":"pkg:npm/foo@1.0.0"},{"purl":"pkg:npm/old-pkg@0.9.0"},{"purl":"pkg:npm/baz@1.0.0"}]}`),
			},
		},
		scanResults: map[int64]*sbommon.SBOMScanResult{
			10: {
				ID:            1,
				VersionID:     10,
				ScannedAt:     time.Now(),
				TotalFindings: 2,
				Findings: []sbommon.ScanFinding{
					{VulnID: "CVE-2024-001", Severity: "HIGH", Purl: "pkg:npm/new-pkg@1.0.0"},
					{VulnID: "CVE-2024-002", Severity: "MEDIUM", Purl: "pkg:npm/baz@1.0.0"},
				},
			},
			20: {
				ID:            2,
				VersionID:     20,
				ScannedAt:     time.Now(),
				TotalFindings: 2,
				Findings: []sbommon.ScanFinding{
					{VulnID: "CVE-2024-003", Severity: "CRITICAL", Purl: "pkg:npm/old-pkg@0.9.0"},
					{VulnID: "CVE-2024-002", Severity: "MEDIUM", Purl: "pkg:npm/baz@1.0.0"},
				},
			},
		},
	}

	srv := New(Config{
		Addr:         ":0",
		Store:        ms,
		Version:      "test",
		AuthProvider: auth.NewNoAuthProvider(),
		SBOMStore:    sbomStore,
	})

	req := httptest.NewRequest("GET", "/api/v1/sbom/projects/1/versions/10/diff?compare_to=20", nil)
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp SBOMDiffResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	// new-pkg was added
	if len(resp.AddedComponents) != 1 {
		t.Errorf("added_components count = %d, want 1", len(resp.AddedComponents))
	} else if resp.AddedComponents[0].Purl != "pkg:npm/new-pkg@1.0.0" {
		t.Errorf("added_components[0].purl = %q, want pkg:npm/new-pkg@1.0.0", resp.AddedComponents[0].Purl)
	}

	// old-pkg was removed
	if len(resp.RemovedComponents) != 1 {
		t.Errorf("removed_components count = %d, want 1", len(resp.RemovedComponents))
	} else if resp.RemovedComponents[0].Purl != "pkg:npm/old-pkg@0.9.0" {
		t.Errorf("removed_components[0].purl = %q, want pkg:npm/old-pkg@0.9.0", resp.RemovedComponents[0].Purl)
	}

	// foo was updated from 1.0.0 to 2.0.0
	if len(resp.UpdatedComponents) != 1 {
		t.Errorf("updated_components count = %d, want 1", len(resp.UpdatedComponents))
	} else {
		if resp.UpdatedComponents[0].Purl != "pkg:npm/foo@2.0.0" {
			t.Errorf("updated_components[0].purl = %q, want pkg:npm/foo@2.0.0", resp.UpdatedComponents[0].Purl)
		}
		if resp.UpdatedComponents[0].PreviousVersion != "1.0.0" {
			t.Errorf("updated_components[0].previous_version = %q, want 1.0.0", resp.UpdatedComponents[0].PreviousVersion)
		}
	}

	// CVE-2024-001 is new (in current, not in compare)
	if len(resp.NewVulnerabilities) != 1 {
		t.Errorf("new_vulnerabilities count = %d, want 1", len(resp.NewVulnerabilities))
	} else if resp.NewVulnerabilities[0].VulnID != "CVE-2024-001" {
		t.Errorf("new_vulnerabilities[0].vuln_id = %q, want CVE-2024-001", resp.NewVulnerabilities[0].VulnID)
	}

	// CVE-2024-003 is resolved (in compare, not in current)
	if len(resp.ResolvedVulnerabilities) != 1 {
		t.Errorf("resolved_vulnerabilities count = %d, want 1", len(resp.ResolvedVulnerabilities))
	} else if resp.ResolvedVulnerabilities[0].VulnID != "CVE-2024-003" {
		t.Errorf("resolved_vulnerabilities[0].vuln_id = %q, want CVE-2024-003", resp.ResolvedVulnerabilities[0].VulnID)
	}
}

func TestHandleSBOMVersionDiff_MissingCompareTo(t *testing.T) {
	ms := &mockStore{}
	sbomStore := &mockSBOMStoreForPortfolio{
		projects: []*sbommon.SBOMProject{
			{ID: 1, UserID: 1, Name: "my-app"},
		},
	}

	srv := New(Config{
		Addr:         ":0",
		Store:        ms,
		Version:      "test",
		AuthProvider: auth.NewNoAuthProvider(),
		SBOMStore:    sbomStore,
	})

	req := httptest.NewRequest("GET", "/api/v1/sbom/projects/1/versions/10/diff", nil)
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleSBOMVersionDiff_ProjectNotFound(t *testing.T) {
	ms := &mockStore{}
	sbomStore := &mockSBOMStoreForPortfolio{
		projects: []*sbommon.SBOMProject{},
	}

	srv := New(Config{
		Addr:         ":0",
		Store:        ms,
		Version:      "test",
		AuthProvider: auth.NewNoAuthProvider(),
		SBOMStore:    sbomStore,
	})

	req := httptest.NewRequest("GET", "/api/v1/sbom/projects/999/versions/10/diff?compare_to=20", nil)
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleSBOMVersionDiff_NoSBOMStore(t *testing.T) {
	ms := &mockStore{}
	srv := New(Config{
		Addr:         ":0",
		Store:        ms,
		Version:      "test",
		AuthProvider: auth.NewNoAuthProvider(),
	})

	req := httptest.NewRequest("GET", "/api/v1/sbom/projects/1/versions/10/diff?compare_to=20", nil)
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)

	// Without sbomStore, the route is not registered but the diff handler still exists
	// It should return 503 if hit directly
	if rr.Code != http.StatusNotFound && rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 404 or 503, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestStripVersionFromPurl(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"pkg:npm/foo@1.0.0", "pkg:npm/foo"},
		{"pkg:npm/%40angular/core@15.0.0", "pkg:npm/%40angular/core"},
		{"pkg:maven/org.apache/commons@1.2", "pkg:maven/org.apache/commons"},
		{"pkg:npm/no-version", "pkg:npm/no-version"},
		{"pkg:npm/foo@1.0.0?repository_url=https://example.com", "pkg:npm/foo"},
	}

	for _, tt := range tests {
		got := stripVersionFromPurl(tt.input)
		if got != tt.want {
			t.Errorf("stripVersionFromPurl(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestExtractVersionFromPurl(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"pkg:npm/foo@1.0.0", "1.0.0"},
		{"pkg:npm/%40angular/core@15.0.0", "15.0.0"},
		{"pkg:npm/no-version", ""},
		{"pkg:npm/foo@1.0.0?qualifiers=yes", "1.0.0"},
	}

	for _, tt := range tests {
		got := extractVersionFromPurl(tt.input)
		if got != tt.want {
			t.Errorf("extractVersionFromPurl(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
