package sbommon

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/kato83/mayu/internal/auth"
)

// mockSBOMStore implements SBOMStore for handler tests.
type mockSBOMStore struct {
	projects    map[int64]*SBOMProject
	versions    map[int64]*SBOMVersion
	scanResults map[int64]*SBOMScanResult
	nextID      int64
}

func newMockSBOMStore() *mockSBOMStore {
	return &mockSBOMStore{
		projects:    make(map[int64]*SBOMProject),
		versions:    make(map[int64]*SBOMVersion),
		scanResults: make(map[int64]*SBOMScanResult),
		nextID:      1,
	}
}

func (m *mockSBOMStore) CreateProject(_ context.Context, p *SBOMProject) (int64, error) {
	id := m.nextID
	m.nextID++
	p.ID = id
	p.CreatedAt = time.Now()
	p.UpdatedAt = time.Now()
	m.projects[id] = p
	return id, nil
}

func (m *mockSBOMStore) GetProject(_ context.Context, id int64, userID int64) (*SBOMProject, error) {
	p, ok := m.projects[id]
	if !ok || p.UserID != userID {
		return nil, nil
	}
	return p, nil
}

func (m *mockSBOMStore) GetProjectByName(_ context.Context, name string, userID int64) (*SBOMProject, error) {
	for _, p := range m.projects {
		if p.Name == name && p.UserID == userID {
			return p, nil
		}
	}
	return nil, nil
}

func (m *mockSBOMStore) ListProjects(_ context.Context, userID int64) ([]*SBOMProject, error) {
	var result []*SBOMProject
	for _, p := range m.projects {
		if p.UserID == userID {
			result = append(result, p)
		}
	}
	return result, nil
}

func (m *mockSBOMStore) UpdateProject(_ context.Context, p *SBOMProject) error {
	m.projects[p.ID] = p
	return nil
}

func (m *mockSBOMStore) DeleteProject(_ context.Context, id int64, _ int64) error {
	delete(m.projects, id)
	return nil
}

func (m *mockSBOMStore) CreateVersion(_ context.Context, v *SBOMVersion) (int64, error) {
	id := m.nextID
	m.nextID++
	v.ID = id
	v.CreatedAt = time.Now()
	m.versions[id] = v
	return id, nil
}

func (m *mockSBOMStore) GetVersion(_ context.Context, id int64) (*SBOMVersion, error) {
	v, ok := m.versions[id]
	if !ok {
		return nil, nil
	}
	return v, nil
}

func (m *mockSBOMStore) ListVersions(_ context.Context, projectID int64) ([]*SBOMVersion, error) {
	var result []*SBOMVersion
	for _, v := range m.versions {
		if v.ProjectID == projectID {
			result = append(result, v)
		}
	}
	return result, nil
}

func (m *mockSBOMStore) GetLatestVersion(_ context.Context, projectID int64) (*SBOMVersion, error) {
	var latest *SBOMVersion
	for _, v := range m.versions {
		if v.ProjectID == projectID {
			if latest == nil || v.CreatedAt.After(latest.CreatedAt) {
				latest = v
			}
		}
	}
	return latest, nil
}

func (m *mockSBOMStore) CreateScanResult(_ context.Context, sr *SBOMScanResult) (int64, error) {
	id := m.nextID
	m.nextID++
	sr.ID = id
	m.scanResults[id] = sr
	return id, nil
}

func (m *mockSBOMStore) GetScanResult(_ context.Context, id int64) (*SBOMScanResult, error) {
	sr, ok := m.scanResults[id]
	if !ok {
		return nil, nil
	}
	return sr, nil
}

func (m *mockSBOMStore) ListScanResults(_ context.Context, versionID int64) ([]*SBOMScanResult, error) {
	var result []*SBOMScanResult
	for _, sr := range m.scanResults {
		if sr.VersionID == versionID {
			result = append(result, sr)
		}
	}
	return result, nil
}

func (m *mockSBOMStore) GetLatestScanResult(_ context.Context, versionID int64) (*SBOMScanResult, error) {
	var latest *SBOMScanResult
	for _, sr := range m.scanResults {
		if sr.VersionID == versionID {
			if latest == nil || sr.ScannedAt.After(latest.ScannedAt) {
				latest = sr
			}
		}
	}
	return latest, nil
}

func (m *mockSBOMStore) GetPreviousScanResult(_ context.Context, versionID int64, beforeScanID int64) (*SBOMScanResult, error) {
	var prev *SBOMScanResult
	for _, sr := range m.scanResults {
		if sr.VersionID == versionID && sr.ID < beforeScanID {
			if prev == nil || sr.ID > prev.ID {
				prev = sr
			}
		}
	}
	return prev, nil
}

func (m *mockSBOMStore) ListAllVersions(_ context.Context) ([]*SBOMVersion, error) {
	var result []*SBOMVersion
	for _, v := range m.versions {
		result = append(result, v)
	}
	return result, nil
}

func (m *mockSBOMStore) ListAllVersionIDs(_ context.Context) ([]int64, error) {
	var ids []int64
	for id := range m.versions {
		ids = append(ids, id)
	}
	return ids, nil
}

// helper to create a request with auth context
func reqWithUser(method, path string, body []byte) *http.Request {
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, path, bytes.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r.Header.Set("Content-Type", "application/json")
	user := &auth.User{ID: 1, Email: "test@example.com", Name: "Test", Role: "admin"}
	ctx := auth.ContextWithUser(r.Context(), user)
	return r.WithContext(ctx)
}

func TestHandleCreateProject(t *testing.T) {
	store := newMockSBOMStore()
	handler := HandleCreateProject(store)

	body, _ := json.Marshal(createProjectRequest{Name: "my-project"})
	req := reqWithUser("POST", "/api/v1/sbom/projects", body)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusCreated, w.Body.String())
	}

	var resp projectResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Name != "my-project" {
		t.Errorf("Name = %q, want %q", resp.Name, "my-project")
	}
	if resp.ID == 0 {
		t.Error("ID should be non-zero")
	}
}

func TestHandleCreateProject_NoName(t *testing.T) {
	store := newMockSBOMStore()
	handler := HandleCreateProject(store)

	body, _ := json.Marshal(createProjectRequest{Name: ""})
	req := reqWithUser("POST", "/api/v1/sbom/projects", body)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleListProjects(t *testing.T) {
	store := newMockSBOMStore()
	store.projects[1] = &SBOMProject{ID: 1, UserID: 1, Name: "proj-1", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	store.projects[2] = &SBOMProject{ID: 2, UserID: 1, Name: "proj-2", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	store.projects[3] = &SBOMProject{ID: 3, UserID: 2, Name: "other-user", CreatedAt: time.Now(), UpdatedAt: time.Now()}

	handler := HandleListProjects(store)
	req := reqWithUser("GET", "/api/v1/sbom/projects", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp []projectResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp) != 2 {
		t.Errorf("len(resp) = %d, want 2", len(resp))
	}
}

func TestHandleGetProject_NotFound(t *testing.T) {
	store := newMockSBOMStore()
	handler := HandleGetProject(store)

	req := reqWithUser("GET", "/api/v1/sbom/projects/999", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "999")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestHandleDeleteProject(t *testing.T) {
	store := newMockSBOMStore()
	store.projects[1] = &SBOMProject{ID: 1, UserID: 1, Name: "to-delete", CreatedAt: time.Now(), UpdatedAt: time.Now()}

	handler := HandleDeleteProject(store)

	req := reqWithUser("DELETE", "/api/v1/sbom/projects/1", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusNoContent, w.Body.String())
	}

	if _, exists := store.projects[1]; exists {
		t.Error("project should have been deleted")
	}
}

func TestHandleGetScanDiff(t *testing.T) {
	store := newMockSBOMStore()
	// Set up project and version ownership for user 1
	store.projects[100] = &SBOMProject{ID: 100, UserID: 1, Name: "proj", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	store.versions[10] = &SBOMVersion{ID: 10, ProjectID: 100, Version: "1.0", CreatedAt: time.Now()}

	store.scanResults[1] = &SBOMScanResult{
		ID:        1,
		VersionID: 10,
		ScannedAt: time.Now().Add(-time.Hour),
		Findings: []ScanFinding{
			{VulnID: "CVE-1", Name: "pkg-a", Version: "1.0", Ecosystem: "npm"},
			{VulnID: "CVE-2", Name: "pkg-b", Version: "2.0", Ecosystem: "npm"},
		},
		Status:  "completed",
		Trigger: "api",
	}
	store.scanResults[2] = &SBOMScanResult{
		ID:        2,
		VersionID: 10,
		ScannedAt: time.Now(),
		Findings: []ScanFinding{
			{VulnID: "CVE-1", Name: "pkg-a", Version: "1.0", Ecosystem: "npm"},
			{VulnID: "CVE-3", Name: "pkg-c", Version: "3.0", Ecosystem: "npm"},
		},
		Status:  "completed",
		Trigger: "api",
	}

	handler := HandleGetScanDiff(store)

	req := reqWithUser("GET", "/api/v1/sbom/scans/2/diff", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("scanID", "2")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp scanDiffResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.NewFindings) != 1 {
		t.Errorf("NewFindings = %d, want 1", len(resp.NewFindings))
	}
	if len(resp.ResolvedFindings) != 1 {
		t.Errorf("ResolvedFindings = %d, want 1", len(resp.ResolvedFindings))
	}
}

func TestHandleCreateProject_Unauthorized(t *testing.T) {
	store := newMockSBOMStore()
	handler := HandleCreateProject(store)

	body, _ := json.Marshal(createProjectRequest{Name: "test"})
	// Create request without auth context
	req := httptest.NewRequest("POST", "/api/v1/sbom/projects", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

// reqWithUserID creates a request with auth context for a specific user ID.
func reqWithUserID(method, path string, body []byte, userID int64) *http.Request {
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, path, bytes.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r.Header.Set("Content-Type", "application/json")
	user := &auth.User{ID: userID, Email: "user@example.com", Name: "User", Role: "viewer"}
	ctx := auth.ContextWithUser(r.Context(), user)
	return r.WithContext(ctx)
}

func TestHandleListScanResults_IDORProtection(t *testing.T) {
	store := newMockSBOMStore()
	// User 1 owns project 100, which contains version 10
	store.projects[100] = &SBOMProject{ID: 100, UserID: 1, Name: "user1-proj", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	store.versions[10] = &SBOMVersion{ID: 10, ProjectID: 100, Version: "1.0", CreatedAt: time.Now()}
	store.scanResults[1] = &SBOMScanResult{
		ID: 1, VersionID: 10, ScannedAt: time.Now(),
		Findings: []ScanFinding{{VulnID: "CVE-1", Name: "pkg-a", Version: "1.0", Ecosystem: "npm"}},
		Status:   "completed", Trigger: "api",
	}

	handler := HandleListScanResults(store)

	// User 2 tries to access user 1's scan results via version ID
	req := reqWithUserID("GET", "/api/v1/sbom/versions/10/scans", nil, 2)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("versionID", "10")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d (IDOR protection); body: %s", w.Code, http.StatusNotFound, w.Body.String())
	}
}

func TestHandleGetScanResult_IDORProtection(t *testing.T) {
	store := newMockSBOMStore()
	// User 1 owns project 100, which contains version 10
	store.projects[100] = &SBOMProject{ID: 100, UserID: 1, Name: "user1-proj", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	store.versions[10] = &SBOMVersion{ID: 10, ProjectID: 100, Version: "1.0", CreatedAt: time.Now()}
	store.scanResults[1] = &SBOMScanResult{
		ID: 1, VersionID: 10, ScannedAt: time.Now(),
		Findings: []ScanFinding{{VulnID: "CVE-1", Name: "pkg-a", Version: "1.0", Ecosystem: "npm"}},
		Status:   "completed", Trigger: "api",
	}

	handler := HandleGetScanResult(store)

	// User 2 tries to access user 1's scan result by ID
	req := reqWithUserID("GET", "/api/v1/sbom/scans/1", nil, 2)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("scanID", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d (IDOR protection); body: %s", w.Code, http.StatusNotFound, w.Body.String())
	}
}

func TestHandleGetScanDiff_IDORProtection(t *testing.T) {
	store := newMockSBOMStore()
	// User 1 owns project 100, which contains version 10
	store.projects[100] = &SBOMProject{ID: 100, UserID: 1, Name: "user1-proj", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	store.versions[10] = &SBOMVersion{ID: 10, ProjectID: 100, Version: "1.0", CreatedAt: time.Now()}
	store.scanResults[1] = &SBOMScanResult{
		ID: 1, VersionID: 10, ScannedAt: time.Now().Add(-time.Hour),
		Findings: []ScanFinding{{VulnID: "CVE-1", Name: "pkg-a", Version: "1.0", Ecosystem: "npm"}},
		Status:   "completed", Trigger: "api",
	}
	store.scanResults[2] = &SBOMScanResult{
		ID: 2, VersionID: 10, ScannedAt: time.Now(),
		Findings: []ScanFinding{{VulnID: "CVE-2", Name: "pkg-b", Version: "2.0", Ecosystem: "npm"}},
		Status:   "completed", Trigger: "api",
	}

	handler := HandleGetScanDiff(store)

	// User 2 tries to access user 1's scan diff
	req := reqWithUserID("GET", "/api/v1/sbom/scans/2/diff", nil, 2)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("scanID", "2")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d (IDOR protection); body: %s", w.Code, http.StatusNotFound, w.Body.String())
	}
}

func TestHandleListScanResults_OwnerCanAccess(t *testing.T) {
	store := newMockSBOMStore()
	// User 1 owns project 100, which contains version 10
	store.projects[100] = &SBOMProject{ID: 100, UserID: 1, Name: "user1-proj", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	store.versions[10] = &SBOMVersion{ID: 10, ProjectID: 100, Version: "1.0", CreatedAt: time.Now()}
	store.scanResults[1] = &SBOMScanResult{
		ID: 1, VersionID: 10, ScannedAt: time.Now(),
		Findings: []ScanFinding{{VulnID: "CVE-1", Name: "pkg-a", Version: "1.0", Ecosystem: "npm"}},
		Status:   "completed", Trigger: "api",
	}

	handler := HandleListScanResults(store)

	// User 1 (owner) should be able to access their own scan results
	req := reqWithUser("GET", "/api/v1/sbom/versions/10/scans", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("versionID", "10")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp []scanResultResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp) != 1 {
		t.Errorf("len(resp) = %d, want 1", len(resp))
	}
}
