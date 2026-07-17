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

	// Load test data
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

	// Retrieve
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

	// Verify both exist
	got1, _ := store.GetByID(ctx, "GO-2024-2687")
	got2, _ := store.GetByID(ctx, "GO-2023-1840")
	if got1 == nil || got2 == nil {
		t.Fatal("expected both vulnerabilities to exist after batch insert")
	}

	// Upsert (update) the first one
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
		// GO-2024-2687 has aliases including CVE-2023-45288
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
