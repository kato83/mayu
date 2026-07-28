package sbommon

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// TestMockSBOMStore_CRUD exercises the mock store to verify
// interface coverage and basic CRUD logic patterns.
func TestMockSBOMStore_CRUD(t *testing.T) {
	store := newMockSBOMStore()
	ctx := context.Background()

	// CreateProject
	p := &SBOMProject{UserID: 1, Name: "test-project"}
	id, err := store.CreateProject(ctx, p)
	if err != nil {
		t.Fatalf("CreateProject() error = %v", err)
	}
	if id == 0 {
		t.Fatal("CreateProject() returned id 0")
	}

	// GetProject
	got, err := store.GetProject(ctx, id, 1)
	if err != nil {
		t.Fatalf("GetProject() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetProject() returned nil")
	}
	if got.Name != "test-project" {
		t.Errorf("Name = %q, want %q", got.Name, "test-project")
	}

	// GetProject wrong user
	got, err = store.GetProject(ctx, id, 999)
	if err != nil {
		t.Fatalf("GetProject(wrong user) error = %v", err)
	}
	if got != nil {
		t.Error("GetProject(wrong user) should return nil")
	}

	// GetProjectByName
	got, err = store.GetProjectByName(ctx, "test-project", 1)
	if err != nil {
		t.Fatalf("GetProjectByName() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetProjectByName() returned nil")
	}

	// ListProjects
	projects, err := store.ListProjects(ctx, 1)
	if err != nil {
		t.Fatalf("ListProjects() error = %v", err)
	}
	if len(projects) != 1 {
		t.Errorf("ListProjects() len = %d, want 1", len(projects))
	}

	// UpdateProject
	got.Name = "updated-name"
	err = store.UpdateProject(ctx, got)
	if err != nil {
		t.Fatalf("UpdateProject() error = %v", err)
	}

	// DeleteProject
	err = store.DeleteProject(ctx, id, 1)
	if err != nil {
		t.Fatalf("DeleteProject() error = %v", err)
	}
	got, _ = store.GetProject(ctx, id, 1)
	if got != nil {
		t.Error("project should be deleted")
	}
}

func TestMockSBOMStore_Versions(t *testing.T) {
	store := newMockSBOMStore()
	ctx := context.Background()

	// Setup project
	pID, _ := store.CreateProject(ctx, &SBOMProject{UserID: 1, Name: "proj"})

	// CreateVersion
	v := &SBOMVersion{
		ProjectID:      pID,
		Version:        "1.0.0",
		Environment:    "production",
		SBOMFormat:     "CycloneDX",
		RawSBOM:        json.RawMessage(`{}`),
		ComponentCount: 5,
	}
	vID, err := store.CreateVersion(ctx, v)
	if err != nil {
		t.Fatalf("CreateVersion() error = %v", err)
	}
	if vID == 0 {
		t.Fatal("CreateVersion() returned id 0")
	}

	// GetVersion
	got, err := store.GetVersion(ctx, vID)
	if err != nil {
		t.Fatalf("GetVersion() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetVersion() returned nil")
	}
	if got.Version != "1.0.0" {
		t.Errorf("Version = %q, want %q", got.Version, "1.0.0")
	}

	// ListVersions
	versions, err := store.ListVersions(ctx, pID)
	if err != nil {
		t.Fatalf("ListVersions() error = %v", err)
	}
	if len(versions) != 1 {
		t.Errorf("ListVersions() len = %d, want 1", len(versions))
	}

	// GetLatestVersion
	latest, err := store.GetLatestVersion(ctx, pID)
	if err != nil {
		t.Fatalf("GetLatestVersion() error = %v", err)
	}
	if latest == nil {
		t.Fatal("GetLatestVersion() returned nil")
	}
}

func TestMockSBOMStore_ScanResults(t *testing.T) {
	store := newMockSBOMStore()
	ctx := context.Background()

	// Create scan result
	sr := &SBOMScanResult{
		VersionID:          1,
		ScannedAt:          time.Now(),
		TotalPackages:      10,
		VulnerablePackages: 2,
		TotalFindings:      3,
		Findings: []ScanFinding{
			{VulnID: "CVE-1", Name: "pkg", Version: "1.0", Ecosystem: "npm"},
		},
		Status:  "completed",
		Trigger: "api",
	}
	srID, err := store.CreateScanResult(ctx, sr)
	if err != nil {
		t.Fatalf("CreateScanResult() error = %v", err)
	}

	// GetScanResult
	got, err := store.GetScanResult(ctx, srID)
	if err != nil {
		t.Fatalf("GetScanResult() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetScanResult() returned nil")
	}
	if got.TotalPackages != 10 {
		t.Errorf("TotalPackages = %d, want 10", got.TotalPackages)
	}

	// ListScanResults
	results, err := store.ListScanResults(ctx, 1)
	if err != nil {
		t.Fatalf("ListScanResults() error = %v", err)
	}
	if len(results) != 1 {
		t.Errorf("ListScanResults() len = %d, want 1", len(results))
	}

	// GetLatestScanResult
	latest, err := store.GetLatestScanResult(ctx, 1)
	if err != nil {
		t.Fatalf("GetLatestScanResult() error = %v", err)
	}
	if latest == nil {
		t.Fatal("GetLatestScanResult() returned nil")
	}

	// Create another scan result for GetPreviousScanResult test
	sr2 := &SBOMScanResult{
		VersionID: 1,
		ScannedAt: time.Now().Add(time.Hour),
		Findings:  []ScanFinding{},
		Status:    "completed",
		Trigger:   "ingest",
	}
	sr2ID, _ := store.CreateScanResult(ctx, sr2)

	prev, err := store.GetPreviousScanResult(ctx, 1, sr2ID)
	if err != nil {
		t.Fatalf("GetPreviousScanResult() error = %v", err)
	}
	if prev == nil {
		t.Fatal("GetPreviousScanResult() returned nil")
	}
	if prev.ID != srID {
		t.Errorf("GetPreviousScanResult() ID = %d, want %d", prev.ID, srID)
	}
}

func TestMockSBOMStore_ListAllVersions(t *testing.T) {
	store := newMockSBOMStore()
	ctx := context.Background()

	store.CreateVersion(ctx, &SBOMVersion{ProjectID: 1, Version: "1.0"})
	store.CreateVersion(ctx, &SBOMVersion{ProjectID: 2, Version: "2.0"})

	all, err := store.ListAllVersions(ctx)
	if err != nil {
		t.Fatalf("ListAllVersions() error = %v", err)
	}
	if len(all) != 2 {
		t.Errorf("ListAllVersions() len = %d, want 2", len(all))
	}
}
