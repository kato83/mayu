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

	if _, err := store.CreateVersion(ctx, &SBOMVersion{ProjectID: 1, Version: "1.0"}); err != nil {
		t.Fatalf("CreateVersion() error = %v", err)
	}
	if _, err := store.CreateVersion(ctx, &SBOMVersion{ProjectID: 2, Version: "2.0"}); err != nil {
		t.Fatalf("CreateVersion() error = %v", err)
	}

	all, err := store.ListAllVersions(ctx)
	if err != nil {
		t.Fatalf("ListAllVersions() error = %v", err)
	}
	if len(all) != 2 {
		t.Errorf("ListAllVersions() len = %d, want 2", len(all))
	}
}

func TestMockSBOMStore_ListAllVersionIDs(t *testing.T) {
	store := newMockSBOMStore()
	ctx := context.Background()

	if _, err := store.CreateVersion(ctx, &SBOMVersion{ProjectID: 1, Version: "1.0"}); err != nil {
		t.Fatalf("CreateVersion() error = %v", err)
	}
	if _, err := store.CreateVersion(ctx, &SBOMVersion{ProjectID: 2, Version: "2.0"}); err != nil {
		t.Fatalf("CreateVersion() error = %v", err)
	}

	ids, err := store.ListAllVersionIDs(ctx)
	if err != nil {
		t.Fatalf("ListAllVersionIDs() error = %v", err)
	}
	if len(ids) != 2 {
		t.Errorf("ListAllVersionIDs() len = %d, want 2", len(ids))
	}
}

func TestMockSBOMStore_UpsertFindingStatus(t *testing.T) {
	store := newMockSBOMStore()
	ctx := context.Background()

	// Insert a new finding status.
	fs := &FindingStatus{
		VersionID:     10,
		VulnID:        "CVE-2024-1234",
		Purl:          "pkg:npm/lodash@4.17.20",
		Status:        FindingStatusOpen,
		Justification: "initial triage",
		UpdatedBy:     1,
	}
	result, err := store.UpsertFindingStatus(ctx, fs)
	if err != nil {
		t.Fatalf("UpsertFindingStatus() error = %v", err)
	}
	if result.ID == 0 {
		t.Fatal("UpsertFindingStatus() returned ID 0")
	}
	if result.Status != FindingStatusOpen {
		t.Errorf("Status = %q, want %q", result.Status, FindingStatusOpen)
	}
	if result.VulnID != "CVE-2024-1234" {
		t.Errorf("VulnID = %q, want %q", result.VulnID, "CVE-2024-1234")
	}

	// Update the same finding status (status change should create a log entry).
	fs2 := &FindingStatus{
		VersionID:     10,
		VulnID:        "CVE-2024-1234",
		Purl:          "pkg:npm/lodash@4.17.20",
		Status:        FindingStatusSuppressed,
		Justification: "not applicable to our use case",
		UpdatedBy:     2,
	}
	result2, err := store.UpsertFindingStatus(ctx, fs2)
	if err != nil {
		t.Fatalf("UpsertFindingStatus() update error = %v", err)
	}
	if result2.ID != result.ID {
		t.Errorf("ID = %d, want %d (same record)", result2.ID, result.ID)
	}
	if result2.Status != FindingStatusSuppressed {
		t.Errorf("Status = %q, want %q", result2.Status, FindingStatusSuppressed)
	}

	// Verify audit log was created.
	logs, err := store.ListFindingStatusLog(ctx, result.ID)
	if err != nil {
		t.Fatalf("ListFindingStatusLog() error = %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("ListFindingStatusLog() len = %d, want 1", len(logs))
	}
	if logs[0].OldStatus != FindingStatusOpen {
		t.Errorf("OldStatus = %q, want %q", logs[0].OldStatus, FindingStatusOpen)
	}
	if logs[0].NewStatus != FindingStatusSuppressed {
		t.Errorf("NewStatus = %q, want %q", logs[0].NewStatus, FindingStatusSuppressed)
	}

	// Upsert with same status should NOT create a log entry.
	fs3 := &FindingStatus{
		VersionID:     10,
		VulnID:        "CVE-2024-1234",
		Purl:          "pkg:npm/lodash@4.17.20",
		Status:        FindingStatusSuppressed,
		Justification: "updated justification",
		UpdatedBy:     2,
	}
	_, err = store.UpsertFindingStatus(ctx, fs3)
	if err != nil {
		t.Fatalf("UpsertFindingStatus() same status error = %v", err)
	}
	logs, err = store.ListFindingStatusLog(ctx, result.ID)
	if err != nil {
		t.Fatalf("ListFindingStatusLog() error = %v", err)
	}
	if len(logs) != 1 {
		t.Errorf("ListFindingStatusLog() len = %d, want 1 (no new log for same status)", len(logs))
	}
}

func TestMockSBOMStore_GetFindingStatus(t *testing.T) {
	store := newMockSBOMStore()
	ctx := context.Background()

	// Not found case.
	got, err := store.GetFindingStatus(ctx, 10, "CVE-2024-0001", "pkg:npm/foo@1.0.0")
	if err != nil {
		t.Fatalf("GetFindingStatus() error = %v", err)
	}
	if got != nil {
		t.Fatal("GetFindingStatus() should return nil for non-existent")
	}

	// Insert and retrieve.
	fs := &FindingStatus{
		VersionID:     10,
		VulnID:        "CVE-2024-0001",
		Purl:          "pkg:npm/foo@1.0.0",
		Status:        FindingStatusInTriage,
		Justification: "under review",
		UpdatedBy:     1,
	}
	_, err = store.UpsertFindingStatus(ctx, fs)
	if err != nil {
		t.Fatalf("UpsertFindingStatus() error = %v", err)
	}

	got, err = store.GetFindingStatus(ctx, 10, "CVE-2024-0001", "pkg:npm/foo@1.0.0")
	if err != nil {
		t.Fatalf("GetFindingStatus() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetFindingStatus() returned nil")
	}
	if got.Status != FindingStatusInTriage {
		t.Errorf("Status = %q, want %q", got.Status, FindingStatusInTriage)
	}
}

func TestMockSBOMStore_ListFindingStatuses(t *testing.T) {
	store := newMockSBOMStore()
	ctx := context.Background()

	// Insert multiple finding statuses for the same version.
	statuses := []*FindingStatus{
		{VersionID: 10, VulnID: "CVE-1", Purl: "pkg:npm/a@1.0", Status: FindingStatusOpen, UpdatedBy: 1},
		{VersionID: 10, VulnID: "CVE-2", Purl: "pkg:npm/b@2.0", Status: FindingStatusSuppressed, UpdatedBy: 1},
		{VersionID: 10, VulnID: "CVE-3", Purl: "pkg:npm/c@3.0", Status: FindingStatusOpen, UpdatedBy: 1},
		{VersionID: 20, VulnID: "CVE-4", Purl: "pkg:npm/d@4.0", Status: FindingStatusOpen, UpdatedBy: 1},
	}
	for _, fs := range statuses {
		if _, err := store.UpsertFindingStatus(ctx, fs); err != nil {
			t.Fatalf("UpsertFindingStatus() error = %v", err)
		}
	}

	// List all for version 10.
	all, err := store.ListFindingStatuses(ctx, 10, nil)
	if err != nil {
		t.Fatalf("ListFindingStatuses() error = %v", err)
	}
	if len(all) != 3 {
		t.Errorf("ListFindingStatuses(no filter) len = %d, want 3", len(all))
	}

	// List with status filter.
	filtered, err := store.ListFindingStatuses(ctx, 10, []string{FindingStatusOpen})
	if err != nil {
		t.Fatalf("ListFindingStatuses(filtered) error = %v", err)
	}
	if len(filtered) != 2 {
		t.Errorf("ListFindingStatuses(open) len = %d, want 2", len(filtered))
	}

	// List with multiple status filter.
	multi, err := store.ListFindingStatuses(ctx, 10, []string{FindingStatusOpen, FindingStatusSuppressed})
	if err != nil {
		t.Fatalf("ListFindingStatuses(multi) error = %v", err)
	}
	if len(multi) != 3 {
		t.Errorf("ListFindingStatuses(open+suppressed) len = %d, want 3", len(multi))
	}

	// List for version 20.
	v20, err := store.ListFindingStatuses(ctx, 20, nil)
	if err != nil {
		t.Fatalf("ListFindingStatuses(v20) error = %v", err)
	}
	if len(v20) != 1 {
		t.Errorf("ListFindingStatuses(v20) len = %d, want 1", len(v20))
	}
}

func TestMockSBOMStore_ListFindingStatusLog(t *testing.T) {
	store := newMockSBOMStore()
	ctx := context.Background()

	// Insert and change status multiple times.
	fs := &FindingStatus{
		VersionID: 10, VulnID: "CVE-1", Purl: "pkg:npm/a@1.0",
		Status: FindingStatusOpen, UpdatedBy: 1,
	}
	result, err := store.UpsertFindingStatus(ctx, fs)
	if err != nil {
		t.Fatalf("UpsertFindingStatus() error = %v", err)
	}

	// Change to in_triage.
	fs.Status = FindingStatusInTriage
	_, err = store.UpsertFindingStatus(ctx, fs)
	if err != nil {
		t.Fatalf("UpsertFindingStatus() error = %v", err)
	}

	// Change to resolved.
	fs.Status = FindingStatusResolved
	_, err = store.UpsertFindingStatus(ctx, fs)
	if err != nil {
		t.Fatalf("UpsertFindingStatus() error = %v", err)
	}

	// Should have 2 log entries (open->in_triage, in_triage->resolved).
	logs, err := store.ListFindingStatusLog(ctx, result.ID)
	if err != nil {
		t.Fatalf("ListFindingStatusLog() error = %v", err)
	}
	if len(logs) != 2 {
		t.Fatalf("ListFindingStatusLog() len = %d, want 2", len(logs))
	}

	// Verify log entries content.
	foundOpenToTriage := false
	foundTriageToResolved := false
	for _, l := range logs {
		if l.OldStatus == FindingStatusOpen && l.NewStatus == FindingStatusInTriage {
			foundOpenToTriage = true
		}
		if l.OldStatus == FindingStatusInTriage && l.NewStatus == FindingStatusResolved {
			foundTriageToResolved = true
		}
	}
	if !foundOpenToTriage {
		t.Error("missing log entry: open -> in_triage")
	}
	if !foundTriageToResolved {
		t.Error("missing log entry: in_triage -> resolved")
	}

	// Empty log for non-existent finding status ID.
	empty, err := store.ListFindingStatusLog(ctx, 99999)
	if err != nil {
		t.Fatalf("ListFindingStatusLog(non-existent) error = %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("ListFindingStatusLog(non-existent) len = %d, want 0", len(empty))
	}
}
