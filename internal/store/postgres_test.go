//go:build integration

package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/kato83/mayu/internal/model"
	"github.com/kato83/mayu/internal/testhelper"
)

func setupTestStore(t *testing.T) *PostgresStore {
	t.Helper()
	ctx := context.Background()

	pg := testhelper.SetupPostgres(t)

	store, err := NewPostgresStore(ctx, pg.DatabaseURL)
	if err != nil {
		t.Fatalf("failed to connect to test database: %v", err)
	}

	t.Cleanup(func() {
		store.Close()
	})

	return store
}

func TestInsertAndGetByID(t *testing.T) {
	store := setupTestStore(t)
	ctx := context.Background()

	// Load test data (GO-2024-2687 has alias CVE-2023-45288)
	data, err := os.ReadFile("../../testdata/GO-2024-2687.json")
	if err != nil {
		t.Fatalf("failed to read test data: %v", err)
	}

	vuln, err := model.ParseVulnerability(data)
	if err != nil {
		t.Fatalf("failed to parse vulnerability: %v", err)
	}

	// Insert
	if err := store.Insert(ctx, vuln); err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	// Retrieve by OSV ID
	got, err := store.GetByID(ctx, "GO-2024-2687")
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if got == nil {
		t.Fatal("GetByID returned nil")
	}
	if got.ID != "GO-2024-2687" {
		t.Errorf("ID = %q, want GO-2024-2687", got.ID)
	}
	if got.Summary == "" {
		t.Error("Summary should not be empty")
	}
	if len(got.Affected) == 0 {
		t.Error("Affected should not be empty")
	}

	// Not found
	notFound, err := store.GetByID(ctx, "NONEXISTENT")
	if err != nil {
		t.Fatalf("GetByID (not found) failed: %v", err)
	}
	if notFound != nil {
		t.Errorf("expected nil for nonexistent ID, got %+v", notFound)
	}
}

func TestCVECanonicalID(t *testing.T) {
	store := setupTestStore(t)
	ctx := context.Background()

	// GO-2024-2687 has aliases: ["BIT-golang-2023-45288", "CVE-2023-45288", "GHSA-4v7x-pqxf-cx7m"]
	// canonical ID should be CVE-2023-45288
	data, err := os.ReadFile("../../testdata/GO-2024-2687.json")
	if err != nil {
		t.Fatalf("read test data: %v", err)
	}
	vuln, err := model.ParseVulnerability(data)
	if err != nil {
		t.Fatalf("parse vulnerability: %v", err)
	}

	if err := store.Insert(ctx, vuln); err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	// Verify vulnerabilities row uses CVE as id
	var vulnID string
	err = store.db.QueryRowContext(ctx, `SELECT id FROM vulnerabilities WHERE id = $1`, "CVE-2023-45288").Scan(&vulnID)
	if err != nil {
		t.Fatalf("vulnerabilities row with CVE ID not found: %v", err)
	}

	// Verify osv_entries points to CVE
	var osvVulnID string
	err = store.db.QueryRowContext(ctx, `SELECT vulnerability_id FROM osv_entries WHERE osv_id = $1`, "GO-2024-2687").Scan(&osvVulnID)
	if err != nil {
		t.Fatalf("osv_entries row not found: %v", err)
	}
	if osvVulnID != "CVE-2023-45288" {
		t.Errorf("osv_entries.vulnerability_id = %q, want CVE-2023-45288", osvVulnID)
	}

	// Verify OSV ID is in vulnerability_aliases
	var count int
	err = store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM vulnerability_aliases WHERE vulnerability_id = $1 AND alias = $2`, "CVE-2023-45288", "GO-2024-2687").Scan(&count)
	if err != nil {
		t.Fatalf("query aliases: %v", err)
	}
	if count != 1 {
		t.Errorf("expected OSV ID in aliases, got count=%d", count)
	}

	// Verify no vulnerabilities row with the OSV ID exists
	var orphanCount int
	err = store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM vulnerabilities WHERE id = $1`, "GO-2024-2687").Scan(&orphanCount)
	if err != nil {
		t.Fatalf("query orphan: %v", err)
	}
	if orphanCount != 0 {
		t.Errorf("expected no vulnerabilities row with OSV ID, got count=%d", orphanCount)
	}
}

func TestMultipleOSVEntriesSameCVE(t *testing.T) {
	store := setupTestStore(t)
	ctx := context.Background()

	// Simulate two different OSV entries (from different ecosystems) pointing to the same CVE
	now := time.Now().UTC().Truncate(time.Second)

	vuln1 := &model.Vulnerability{
		ID:       "USN-6789-1",
		Modified: now,
		Summary:  "Ubuntu advisory for CVE-2024-9999",
		Aliases:  []string{"CVE-2024-9999"},
		Affected: []model.Affected{{
			Package: model.Package{Ecosystem: "Ubuntu", Name: "apache2"},
		}},
	}

	vuln2 := &model.Vulnerability{
		ID:       "RHSA-2024:1234",
		Modified: now.Add(time.Hour),
		Summary:  "Red Hat advisory for CVE-2024-9999",
		Aliases:  []string{"CVE-2024-9999", "GHSA-xxxx-yyyy-zzzz"},
		Affected: []model.Affected{{
			Package: model.Package{Ecosystem: "Red Hat", Name: "httpd"},
		}},
	}

	// Insert first
	if err := store.Insert(ctx, vuln1); err != nil {
		t.Fatalf("Insert vuln1 failed: %v", err)
	}

	// Insert second — should share the same vulnerabilities row
	if err := store.Insert(ctx, vuln2); err != nil {
		t.Fatalf("Insert vuln2 failed: %v", err)
	}

	// Only one vulnerabilities row for CVE-2024-9999
	var vulnCount int
	err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM vulnerabilities WHERE id = $1`, "CVE-2024-9999").Scan(&vulnCount)
	if err != nil {
		t.Fatalf("query vulnerabilities: %v", err)
	}
	if vulnCount != 1 {
		t.Errorf("expected 1 vulnerability row for CVE-2024-9999, got %d", vulnCount)
	}

	// Two osv_entries both pointing to CVE-2024-9999
	var osvCount int
	err = store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM osv_entries WHERE vulnerability_id = $1`, "CVE-2024-9999").Scan(&osvCount)
	if err != nil {
		t.Fatalf("query osv_entries: %v", err)
	}
	if osvCount != 2 {
		t.Errorf("expected 2 osv_entries for CVE-2024-9999, got %d", osvCount)
	}

	// Verify both OSV IDs are in aliases
	var aliasCount int
	err = store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM vulnerability_aliases WHERE vulnerability_id = $1`, "CVE-2024-9999").Scan(&aliasCount)
	if err != nil {
		t.Fatalf("query aliases: %v", err)
	}
	// Expected aliases: USN-6789-1, CVE-2024-9999, RHSA-2024:1234, GHSA-xxxx-yyyy-zzzz
	if aliasCount < 4 {
		t.Errorf("expected at least 4 aliases for CVE-2024-9999, got %d", aliasCount)
	}

	// Verify modified uses GREATEST (vuln2 is newer)
	var modified time.Time
	err = store.db.QueryRowContext(ctx, `SELECT modified FROM vulnerabilities WHERE id = $1`, "CVE-2024-9999").Scan(&modified)
	if err != nil {
		t.Fatalf("query modified: %v", err)
	}
	if !modified.Equal(now.Add(time.Hour)) {
		t.Errorf("modified = %v, want %v (should use GREATEST)", modified, now.Add(time.Hour))
	}
}

func TestLateCVEAssignment(t *testing.T) {
	store := setupTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)

	// First: insert without CVE (no CVE alias yet)
	vuln := &model.Vulnerability{
		ID:       "GO-2024-9000",
		Modified: now,
		Summary:  "Some vulnerability without CVE yet",
		Aliases:  []string{"GHSA-aaaa-bbbb-cccc"},
		Affected: []model.Affected{{
			Package: model.Package{Ecosystem: "Go", Name: "example.com/pkg"},
		}},
	}
	if err := store.Insert(ctx, vuln); err != nil {
		t.Fatalf("Insert (no CVE) failed: %v", err)
	}

	// Verify: vulnerabilities.id = GO-2024-9000 (no CVE available)
	var id string
	err := store.db.QueryRowContext(ctx, `SELECT vulnerability_id FROM osv_entries WHERE osv_id = $1`, "GO-2024-9000").Scan(&id)
	if err != nil {
		t.Fatalf("query osv_entries: %v", err)
	}
	if id != "GO-2024-9000" {
		t.Errorf("initial vulnerability_id = %q, want GO-2024-9000", id)
	}

	// Second: re-import with CVE now assigned
	vulnUpdated := &model.Vulnerability{
		ID:       "GO-2024-9000",
		Modified: now.Add(24 * time.Hour),
		Summary:  "Some vulnerability with CVE now",
		Aliases:  []string{"GHSA-aaaa-bbbb-cccc", "CVE-2024-55555"},
		Affected: []model.Affected{{
			Package: model.Package{Ecosystem: "Go", Name: "example.com/pkg"},
		}},
	}
	if err := store.Insert(ctx, vulnUpdated); err != nil {
		t.Fatalf("Insert (with CVE) failed: %v", err)
	}

	// Verify: vulnerabilities.id is now CVE-2024-55555
	err = store.db.QueryRowContext(ctx, `SELECT vulnerability_id FROM osv_entries WHERE osv_id = $1`, "GO-2024-9000").Scan(&id)
	if err != nil {
		t.Fatalf("query osv_entries after CVE assignment: %v", err)
	}
	if id != "CVE-2024-55555" {
		t.Errorf("vulnerability_id after CVE assignment = %q, want CVE-2024-55555", id)
	}

	// Old vulnerability row (GO-2024-9000) should be cleaned up
	var oldCount int
	err = store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM vulnerabilities WHERE id = $1`, "GO-2024-9000").Scan(&oldCount)
	if err != nil {
		t.Fatalf("query old vulnerability: %v", err)
	}
	if oldCount != 0 {
		t.Errorf("expected old vulnerability row to be deleted, got count=%d", oldCount)
	}

	// New vulnerability row exists
	var newCount int
	err = store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM vulnerabilities WHERE id = $1`, "CVE-2024-55555").Scan(&newCount)
	if err != nil {
		t.Fatalf("query new vulnerability: %v", err)
	}
	if newCount != 1 {
		t.Errorf("expected new vulnerability row, got count=%d", newCount)
	}
}

func TestUpsertBatch(t *testing.T) {
	store := setupTestStore(t)
	ctx := context.Background()

	data1, err := os.ReadFile("../../testdata/GO-2024-2687.json")
	if err != nil {
		t.Fatalf("read test data: %v", err)
	}
	data2, err := os.ReadFile("../../testdata/GO-2023-1840.json")
	if err != nil {
		t.Fatalf("read test data: %v", err)
	}

	vuln1, _ := model.ParseVulnerability(data1)
	vuln2, _ := model.ParseVulnerability(data2)

	// Batch insert
	if err := store.UpsertBatch(ctx, []*model.Vulnerability{vuln1, vuln2}); err != nil {
		t.Fatalf("UpsertBatch failed: %v", err)
	}

	// Verify both exist (by OSV ID)
	got1, _ := store.GetByID(ctx, "GO-2024-2687")
	got2, _ := store.GetByID(ctx, "GO-2023-1840")
	if got1 == nil || got2 == nil {
		t.Fatal("expected both vulnerabilities to exist after batch insert")
	}

	// Verify canonical IDs are CVEs
	var vulnID1, vulnID2 string
	store.db.QueryRowContext(ctx, `SELECT vulnerability_id FROM osv_entries WHERE osv_id = $1`, "GO-2024-2687").Scan(&vulnID1)
	store.db.QueryRowContext(ctx, `SELECT vulnerability_id FROM osv_entries WHERE osv_id = $1`, "GO-2023-1840").Scan(&vulnID2)
	if vulnID1 != "CVE-2023-45288" {
		t.Errorf("GO-2024-2687 vulnerability_id = %q, want CVE-2023-45288", vulnID1)
	}
	if vulnID2 != "CVE-2023-29403" {
		t.Errorf("GO-2023-1840 vulnerability_id = %q, want CVE-2023-29403", vulnID2)
	}

	// Upsert (update) the first one — should be idempotent
	vuln1Updated, _ := model.ParseVulnerability(data1)
	if err := store.UpsertBatch(ctx, []*model.Vulnerability{vuln1Updated}); err != nil {
		t.Fatalf("UpsertBatch (update) failed: %v", err)
	}

	got1After, _ := store.GetByID(ctx, "GO-2024-2687")
	if got1After == nil {
		t.Fatal("GO-2024-2687 should still exist after upsert")
	}
}

func TestSearch(t *testing.T) {
	store := setupTestStore(t)
	ctx := context.Background()

	// Load and insert test data
	data1, _ := os.ReadFile("../../testdata/GO-2024-2687.json")
	data2, _ := os.ReadFile("../../testdata/GO-2023-1840.json")
	vuln1, _ := model.ParseVulnerability(data1)
	vuln2, _ := model.ParseVulnerability(data2)
	store.UpsertBatch(ctx, []*model.Vulnerability{vuln1, vuln2})

	t.Run("by ID", func(t *testing.T) {
		results, err := store.Search(ctx, SearchQuery{ID: "GO-2024-2687"})
		if err != nil {
			t.Fatalf("Search by ID failed: %v", err)
		}
		if len(results) != 1 {
			t.Fatalf("expected 1 result, got %d", len(results))
		}
		if results[0].ID != "GO-2024-2687" {
			t.Errorf("ID = %q, want GO-2024-2687", results[0].ID)
		}
	})

	t.Run("by ecosystem", func(t *testing.T) {
		results, err := store.Search(ctx, SearchQuery{Ecosystem: "Go"})
		if err != nil {
			t.Fatalf("Search by ecosystem failed: %v", err)
		}
		if len(results) != 2 {
			t.Errorf("expected 2 results, got %d", len(results))
		}
	})

	t.Run("by package name", func(t *testing.T) {
		results, err := store.Search(ctx, SearchQuery{PackageName: "golang.org/x/net"})
		if err != nil {
			t.Fatalf("Search by package failed: %v", err)
		}
		if len(results) == 0 {
			t.Error("expected at least 1 result for golang.org/x/net")
		}
	})

	t.Run("by alias", func(t *testing.T) {
		// GO-2024-2687 has alias CVE-2023-45288, which is now the canonical ID
		results, err := store.Search(ctx, SearchQuery{Alias: "CVE-2023-45288"})
		if err != nil {
			t.Fatalf("Search by alias failed: %v", err)
		}
		if len(results) != 1 {
			t.Fatalf("expected 1 result for CVE-2023-45288, got %d", len(results))
		}
		if results[0].ID != "GO-2024-2687" {
			t.Errorf("ID = %q, want GO-2024-2687", results[0].ID)
		}
	})

	t.Run("by alias using OSV ID", func(t *testing.T) {
		// OSV ID should be searchable as an alias too
		results, err := store.Search(ctx, SearchQuery{Alias: "GO-2024-2687"})
		if err != nil {
			t.Fatalf("Search by OSV ID alias failed: %v", err)
		}
		if len(results) != 1 {
			t.Fatalf("expected 1 result for GO-2024-2687 alias, got %d", len(results))
		}
	})

	t.Run("with limit", func(t *testing.T) {
		results, err := store.Search(ctx, SearchQuery{Ecosystem: "Go", Limit: 1})
		if err != nil {
			t.Fatalf("Search with limit failed: %v", err)
		}
		if len(results) != 1 {
			t.Errorf("expected 1 result with limit=1, got %d", len(results))
		}
	})

	t.Run("no results", func(t *testing.T) {
		results, err := store.Search(ctx, SearchQuery{ID: "NONEXISTENT"})
		if err != nil {
			t.Fatalf("Search no results failed: %v", err)
		}
		if len(results) != 0 {
			t.Errorf("expected 0 results, got %d", len(results))
		}
	})
}

func TestSyncState(t *testing.T) {
	store := setupTestStore(t)
	ctx := context.Background()

	// Initially no state
	state, err := store.GetSyncState(ctx, "Go")
	if err != nil {
		t.Fatalf("GetSyncState failed: %v", err)
	}
	if state != nil {
		t.Fatalf("expected nil state, got %+v", state)
	}

	// Create sync state
	now := time.Now().UTC().Truncate(time.Second)
	newState := &SyncState{
		Source:         "Go",
		LastModifiedAt: now.Format(time.RFC3339),
		RecordCount:    42,
	}
	if err := store.UpdateSyncState(ctx, newState); err != nil {
		t.Fatalf("UpdateSyncState failed: %v", err)
	}

	// Retrieve
	state, err = store.GetSyncState(ctx, "Go")
	if err != nil {
		t.Fatalf("GetSyncState failed: %v", err)
	}
	if state == nil {
		t.Fatal("GetSyncState returned nil after update")
	}
	if state.Source != "Go" {
		t.Errorf("Source = %q, want %q", state.Source, "Go")
	}
	if state.RecordCount != 42 {
		t.Errorf("RecordCount = %d, want 42", state.RecordCount)
	}

	// Update
	updatedState := &SyncState{
		Source:         "Go",
		LastModifiedAt: now.Add(time.Hour).Format(time.RFC3339),
		RecordCount:    100,
	}
	if err := store.UpdateSyncState(ctx, updatedState); err != nil {
		t.Fatalf("UpdateSyncState (update) failed: %v", err)
	}

	state, err = store.GetSyncState(ctx, "Go")
	if err != nil {
		t.Fatalf("GetSyncState (after update) failed: %v", err)
	}
	if state.RecordCount != 100 {
		t.Errorf("RecordCount after update = %d, want 100", state.RecordCount)
	}
}

func TestExtractCVE(t *testing.T) {
	tests := []struct {
		name    string
		aliases []string
		want    string
	}{
		{"no aliases", nil, ""},
		{"no CVE", []string{"GHSA-xxxx", "BIT-123"}, ""},
		{"single CVE", []string{"CVE-2024-1234"}, "CVE-2024-1234"},
		{"CVE among others", []string{"BIT-golang-2023-45288", "CVE-2023-45288", "GHSA-4v7x"}, "CVE-2023-45288"},
		{"first CVE wins", []string{"CVE-2024-1111", "CVE-2024-2222"}, "CVE-2024-1111"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractCVE(tt.aliases)
			if got != tt.want {
				t.Errorf("extractCVE(%v) = %q, want %q", tt.aliases, got, tt.want)
			}
		})
	}
}

func TestCanonicalID(t *testing.T) {
	tests := []struct {
		name    string
		osvID   string
		aliases []string
		want    string
	}{
		{"with CVE", "GO-2024-2687", []string{"BIT-golang-2023-45288", "CVE-2023-45288"}, "CVE-2023-45288"},
		{"without CVE", "GO-2024-9000", []string{"GHSA-aaaa-bbbb-cccc"}, "GO-2024-9000"},
		{"no aliases", "GO-2024-9000", nil, "GO-2024-9000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := canonicalID(tt.osvID, tt.aliases)
			if got != tt.want {
				t.Errorf("canonicalID(%q, %v) = %q, want %q", tt.osvID, tt.aliases, got, tt.want)
			}
		})
	}
}
