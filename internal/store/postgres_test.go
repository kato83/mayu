//go:build integration

package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/kato83/mayu/internal/model"
)

const defaultTestDBURL = "postgres://mayu:mayu@localhost:5432/mayu?sslmode=disable"

func testDatabaseURL() string {
	if url := os.Getenv("DATABASE_URL"); url != "" {
		return url
	}
	return defaultTestDBURL
}

func setupTestStore(t *testing.T) *PostgresStore {
	t.Helper()
	ctx := context.Background()

	store, err := NewPostgresStore(ctx, testDatabaseURL())
	if err != nil {
		t.Fatalf("failed to connect to test database: %v", err)
	}

	// Clean up test data
	t.Cleanup(func() {
		store.db.ExecContext(ctx, "DELETE FROM vulnerabilities")
		store.db.ExecContext(ctx, "DELETE FROM sync_state")
		store.Close()
	})

	return store
}

func TestInsertAndGetByID(t *testing.T) {
	store := setupTestStore(t)
	ctx := context.Background()

	// Load test data
	data, err := os.ReadFile("../../testdata/GO-2024-2687.json")
	if err != nil {
		t.Fatalf("failed to read test data: %v", err)
	}

	vuln, err := model.ParseVulnerability(data)
	if err != nil {
		t.Fatalf("failed to parse test data: %v", err)
	}

	// Insert
	if err := store.Insert(ctx, vuln); err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	// GetByID
	got, err := store.GetByID(ctx, "GO-2024-2687")
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if got == nil {
		t.Fatal("GetByID returned nil")
	}

	// Verify fields match
	if got.ID != vuln.ID {
		t.Errorf("ID = %q, want %q", got.ID, vuln.ID)
	}
	if got.Summary != vuln.Summary {
		t.Errorf("Summary = %q, want %q", got.Summary, vuln.Summary)
	}
	if len(got.Aliases) != len(vuln.Aliases) {
		t.Errorf("Aliases count = %d, want %d", len(got.Aliases), len(vuln.Aliases))
	}
	if len(got.Affected) != len(vuln.Affected) {
		t.Errorf("Affected count = %d, want %d", len(got.Affected), len(vuln.Affected))
	}
	if len(got.References) != len(vuln.References) {
		t.Errorf("References count = %d, want %d", len(got.References), len(vuln.References))
	}
	if len(got.Credits) != len(vuln.Credits) {
		t.Errorf("Credits count = %d, want %d", len(got.Credits), len(vuln.Credits))
	}

	// Verify RawJSON is preserved
	if got.RawJSON == nil {
		t.Error("RawJSON is nil after GetByID")
	}
}

func TestGetByID_NotFound(t *testing.T) {
	store := setupTestStore(t)
	ctx := context.Background()

	got, err := store.GetByID(ctx, "NONEXISTENT-0000")
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for non-existent ID, got %+v", got)
	}
}

func TestUpsertBatch(t *testing.T) {
	store := setupTestStore(t)
	ctx := context.Background()

	// Load two test files
	files := []string{
		"../../testdata/GO-2024-2687.json",
		"../../testdata/GO-2023-1840.json",
	}

	var vulns []*model.Vulnerability
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("failed to read %s: %v", f, err)
		}
		vuln, err := model.ParseVulnerability(data)
		if err != nil {
			t.Fatalf("failed to parse %s: %v", f, err)
		}
		vulns = append(vulns, vuln)
	}

	// UpsertBatch
	if err := store.UpsertBatch(ctx, vulns); err != nil {
		t.Fatalf("UpsertBatch failed: %v", err)
	}

	// Verify both are stored
	for _, vuln := range vulns {
		got, err := store.GetByID(ctx, vuln.ID)
		if err != nil {
			t.Fatalf("GetByID(%s) failed: %v", vuln.ID, err)
		}
		if got == nil {
			t.Fatalf("GetByID(%s) returned nil", vuln.ID)
		}
		if got.ID != vuln.ID {
			t.Errorf("ID = %q, want %q", got.ID, vuln.ID)
		}
	}

	// Upsert again (should not fail - idempotent)
	if err := store.UpsertBatch(ctx, vulns); err != nil {
		t.Fatalf("UpsertBatch (2nd) failed: %v", err)
	}
}

func TestSearch_ByEcosystemAndPackage(t *testing.T) {
	store := setupTestStore(t)
	ctx := context.Background()

	// Insert test data
	data, err := os.ReadFile("../../testdata/GO-2024-2687.json")
	if err != nil {
		t.Fatalf("failed to read test data: %v", err)
	}
	vuln, err := model.ParseVulnerability(data)
	if err != nil {
		t.Fatalf("failed to parse test data: %v", err)
	}
	if err := store.Insert(ctx, vuln); err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	// Search by ecosystem
	results, err := store.Search(ctx, SearchQuery{Ecosystem: "Go"})
	if err != nil {
		t.Fatalf("Search by ecosystem failed: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("Search by ecosystem returned no results")
	}
	if results[0].ID != "GO-2024-2687" {
		t.Errorf("result ID = %q, want GO-2024-2687", results[0].ID)
	}

	// Search by package name
	pkgName := vuln.Affected[0].Package.Name
	results, err = store.Search(ctx, SearchQuery{PackageName: pkgName})
	if err != nil {
		t.Fatalf("Search by package failed: %v", err)
	}
	if len(results) == 0 {
		t.Fatalf("Search by package %q returned no results", pkgName)
	}

	// Search by alias
	if len(vuln.Aliases) > 0 {
		results, err = store.Search(ctx, SearchQuery{Alias: vuln.Aliases[0]})
		if err != nil {
			t.Fatalf("Search by alias failed: %v", err)
		}
		if len(results) == 0 {
			t.Fatal("Search by alias returned no results")
		}
	}

	// Search with no results
	results, err = store.Search(ctx, SearchQuery{Ecosystem: "NonExistent"})
	if err != nil {
		t.Fatalf("Search with no matches failed: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
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
		Ecosystem:      "Go",
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
	if state.Ecosystem != "Go" {
		t.Errorf("Ecosystem = %q, want %q", state.Ecosystem, "Go")
	}
	if state.RecordCount != 42 {
		t.Errorf("RecordCount = %d, want 42", state.RecordCount)
	}

	// Update
	updatedState := &SyncState{
		Ecosystem:      "Go",
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
