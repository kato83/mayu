package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kato83/mayu/internal/auth"
	"github.com/kato83/mayu/internal/sbommon"
	"github.com/kato83/mayu/internal/store"
)

// mockSBOMStoreForPortfolio implements sbommon.SBOMStore for portfolio tests.
type mockSBOMStoreForPortfolio struct {
	projects    []*sbommon.SBOMProject
	versions    map[int64]*sbommon.SBOMVersion
	scanResults map[int64]*sbommon.SBOMScanResult
	statuses    map[int64][]*sbommon.FindingStatus
}

func (m *mockSBOMStoreForPortfolio) CreateProject(_ context.Context, _ *sbommon.SBOMProject) (int64, error) {
	return 0, nil
}
func (m *mockSBOMStoreForPortfolio) GetProject(_ context.Context, id int64, _ int64) (*sbommon.SBOMProject, error) {
	for _, p := range m.projects {
		if p.ID == id {
			return p, nil
		}
	}
	return nil, nil
}
func (m *mockSBOMStoreForPortfolio) GetProjectByName(_ context.Context, _ string, _ int64) (*sbommon.SBOMProject, error) {
	return nil, nil
}
func (m *mockSBOMStoreForPortfolio) ListProjects(_ context.Context, _ int64) ([]*sbommon.SBOMProject, error) {
	return m.projects, nil
}
func (m *mockSBOMStoreForPortfolio) ListProjectsByTeam(_ context.Context, _ int64) ([]*sbommon.SBOMProject, error) {
	return nil, nil
}
func (m *mockSBOMStoreForPortfolio) UpdateProject(_ context.Context, _ *sbommon.SBOMProject) error {
	return nil
}
func (m *mockSBOMStoreForPortfolio) DeleteProject(_ context.Context, _ int64, _ int64) error {
	return nil
}
func (m *mockSBOMStoreForPortfolio) CreateVersion(_ context.Context, _ *sbommon.SBOMVersion) (int64, error) {
	return 0, nil
}
func (m *mockSBOMStoreForPortfolio) GetVersion(_ context.Context, id int64) (*sbommon.SBOMVersion, error) {
	if v, ok := m.versions[id]; ok {
		return v, nil
	}
	return nil, nil
}
func (m *mockSBOMStoreForPortfolio) ListVersions(_ context.Context, _ int64) ([]*sbommon.SBOMVersion, error) {
	return nil, nil
}
func (m *mockSBOMStoreForPortfolio) GetLatestVersion(_ context.Context, projectID int64) (*sbommon.SBOMVersion, error) {
	for _, v := range m.versions {
		if v.ProjectID == projectID {
			return v, nil
		}
	}
	return nil, nil
}
func (m *mockSBOMStoreForPortfolio) CreateScanResult(_ context.Context, _ *sbommon.SBOMScanResult) (int64, error) {
	return 0, nil
}
func (m *mockSBOMStoreForPortfolio) GetScanResult(_ context.Context, _ int64) (*sbommon.SBOMScanResult, error) {
	return nil, nil
}
func (m *mockSBOMStoreForPortfolio) ListScanResults(_ context.Context, _ int64) ([]*sbommon.SBOMScanResult, error) {
	return nil, nil
}
func (m *mockSBOMStoreForPortfolio) GetLatestScanResult(_ context.Context, versionID int64) (*sbommon.SBOMScanResult, error) {
	if sr, ok := m.scanResults[versionID]; ok {
		return sr, nil
	}
	return nil, nil
}
func (m *mockSBOMStoreForPortfolio) GetPreviousVersionScanResult(_ context.Context, _ int64, _ int64) (*sbommon.SBOMScanResult, error) {
	return nil, nil
}
func (m *mockSBOMStoreForPortfolio) GetPreviousScanResult(_ context.Context, _ int64, _ int64) (*sbommon.SBOMScanResult, error) {
	return nil, nil
}
func (m *mockSBOMStoreForPortfolio) ListAllVersions(_ context.Context) ([]*sbommon.SBOMVersion, error) {
	return nil, nil
}
func (m *mockSBOMStoreForPortfolio) ListAllVersionIDs(_ context.Context) ([]int64, error) {
	return nil, nil
}
func (m *mockSBOMStoreForPortfolio) UpsertFindingStatus(_ context.Context, _ *sbommon.FindingStatus) (*sbommon.FindingStatus, error) {
	return nil, nil
}
func (m *mockSBOMStoreForPortfolio) GetFindingStatus(_ context.Context, _ int64, _ string, _ string) (*sbommon.FindingStatus, error) {
	return nil, nil
}
func (m *mockSBOMStoreForPortfolio) ListFindingStatuses(_ context.Context, versionID int64, _ []string) ([]*sbommon.FindingStatus, error) {
	if statuses, ok := m.statuses[versionID]; ok {
		return statuses, nil
	}
	return nil, nil
}
func (m *mockSBOMStoreForPortfolio) ListFindingStatusLog(_ context.Context, _ int64) ([]*sbommon.FindingStatusLog, error) {
	return nil, nil
}
func (m *mockSBOMStoreForPortfolio) DeleteFindingStatus(_ context.Context, _ int64, _ string, _ string) error {
	return nil
}

func TestHandleDashboardPortfolio_Success(t *testing.T) {
	ms := &mockStore{}
	sbomStore := &mockSBOMStoreForPortfolio{
		projects: []*sbommon.SBOMProject{
			{ID: 1, UserID: 1, Name: "my-app"},
			{ID: 2, UserID: 1, Name: "other-app"},
		},
		versions: map[int64]*sbommon.SBOMVersion{
			10: {ID: 10, ProjectID: 1, Version: "1.2.0", ComponentCount: 100},
			20: {ID: 20, ProjectID: 2, Version: "2.0.0", ComponentCount: 50},
		},
		scanResults: map[int64]*sbommon.SBOMScanResult{
			10: {
				ID:            1,
				VersionID:     10,
				ScannedAt:     time.Now(),
				TotalFindings: 3,
				Findings: []sbommon.ScanFinding{
					{VulnID: "CVE-2024-001", Severity: "CRITICAL", Purl: "pkg:npm/foo@1.0.0"},
					{VulnID: "CVE-2024-002", Severity: "HIGH", Purl: "pkg:npm/bar@2.0.0"},
					{VulnID: "CVE-2024-003", Severity: "MEDIUM", Purl: "pkg:npm/baz@3.0.0"},
				},
			},
			20: {
				ID:            2,
				VersionID:     20,
				ScannedAt:     time.Now(),
				TotalFindings: 1,
				Findings: []sbommon.ScanFinding{
					{VulnID: "CVE-2024-004", Severity: "LOW", Purl: "pkg:npm/qux@1.0.0"},
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

	req := httptest.NewRequest("GET", "/api/v1/dashboard/portfolio", nil)
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp PortfolioResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	if resp.TotalProjects != 2 {
		t.Errorf("total_projects = %d, want 2", resp.TotalProjects)
	}
	if resp.TotalComponents != 150 {
		t.Errorf("total_components = %d, want 150", resp.TotalComponents)
	}
	if resp.TotalFindings != 4 {
		t.Errorf("total_findings = %d, want 4", resp.TotalFindings)
	}
	if resp.FindingsBySeverity["critical"] != 1 {
		t.Errorf("critical = %d, want 1", resp.FindingsBySeverity["critical"])
	}
	if resp.FindingsBySeverity["high"] != 1 {
		t.Errorf("high = %d, want 1", resp.FindingsBySeverity["high"])
	}
	if len(resp.Projects) != 2 {
		t.Errorf("projects count = %d, want 2", len(resp.Projects))
	}
}

func TestHandleDashboardPortfolio_NoSBOMStore(t *testing.T) {
	ms := &mockStore{}
	srv := New(Config{
		Addr:         ":0",
		Store:        ms,
		Version:      "test",
		AuthProvider: auth.NewNoAuthProvider(),
	})

	req := httptest.NewRequest("GET", "/api/v1/dashboard/portfolio", nil)
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

func TestHandleDashboardEOLReport_Success(t *testing.T) {
	ms := &mockStore{}
	// Override GetEOLReport to return test data
	ms2 := &mockStoreWithEOLReport{
		mockStore: ms,
		eolProducts: []store.EOLReportProduct{
			{Name: "nodejs", Label: "Node.js", Release: "18", EOLDate: "2025-04-30"},
		},
		upcoming: []store.EOLUpcomingProduct{
			{Name: "python", Label: "Python", Release: "3.9", EOLDate: "2026-10-01", DaysUntilEOL: 120},
		},
	}

	srv := New(Config{
		Addr:         ":0",
		Store:        ms2,
		Version:      "test",
		AuthProvider: auth.NewNoAuthProvider(),
	})

	req := httptest.NewRequest("GET", "/api/v1/dashboard/eol-report", nil)
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp EOLReportResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	if len(resp.EOLProducts) != 1 {
		t.Fatalf("eol_products count = %d, want 1", len(resp.EOLProducts))
	}
	if resp.EOLProducts[0].Name != "nodejs" {
		t.Errorf("eol_products[0].name = %q, want nodejs", resp.EOLProducts[0].Name)
	}
	if len(resp.UpcomingEOL) != 1 {
		t.Fatalf("upcoming_eol count = %d, want 1", len(resp.UpcomingEOL))
	}
	if resp.UpcomingEOL[0].DaysUntilEOL != 120 {
		t.Errorf("upcoming_eol[0].days_until_eol = %d, want 120", resp.UpcomingEOL[0].DaysUntilEOL)
	}
}

func TestHandleDashboardEOLReport_InvalidDays(t *testing.T) {
	ms := &mockStoreWithEOLReport{mockStore: &mockStore{}}
	srv := New(Config{
		Addr:         ":0",
		Store:        ms,
		Version:      "test",
		AuthProvider: auth.NewNoAuthProvider(),
	})

	req := httptest.NewRequest("GET", "/api/v1/dashboard/eol-report?days=abc", nil)
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// mockStoreWithEOLReport wraps mockStore and overrides GetEOLReport.
type mockStoreWithEOLReport struct {
	*mockStore
	eolProducts []store.EOLReportProduct
	upcoming    []store.EOLUpcomingProduct
}

func (m *mockStoreWithEOLReport) GetEOLReport(_ context.Context, _ int) ([]store.EOLReportProduct, []store.EOLUpcomingProduct, error) {
	return m.eolProducts, m.upcoming, nil
}
