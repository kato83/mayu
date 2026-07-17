//go:build integration

package ingest

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/kato83/mayu/internal/fetcher"
	"github.com/kato83/mayu/internal/parser"
	"github.com/kato83/mayu/internal/store"
)

const defaultTestDBURL = "postgres://mayu:mayu@localhost:5432/mayu?sslmode=disable"

func testDatabaseURL() string {
	if url := os.Getenv("DATABASE_URL"); url != "" {
		return url
	}
	return defaultTestDBURL
}

func setupTestStore(t *testing.T) *store.PostgresStore {
	t.Helper()
	ctx := context.Background()

	s, err := store.NewPostgresStore(ctx, testDatabaseURL())
	if err != nil {
		t.Fatalf("failed to connect to test database: %v", err)
	}

	t.Cleanup(func() {
		s.CleanAll(ctx)
		s.Close()
	})

	return s
}

func createTestZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatalf("create zip file: %v", err)
		}
		f.Write([]byte(content))
	}
	w.Close()
	return buf.Bytes()
}

func TestFullImport(t *testing.T) {
	// Read real test data
	data1, err := os.ReadFile("../../testdata/GO-2024-2687.json")
	if err != nil {
		t.Fatalf("read test data: %v", err)
	}
	data2, err := os.ReadFile("../../testdata/GO-2023-1840.json")
	if err != nil {
		t.Fatalf("read test data: %v", err)
	}

	// Create zip with real data
	zipData := createTestZip(t, map[string]string{
		"GO-2024-2687.json": string(data1),
		"GO-2023-1840.json": string(data2),
	})

	// Mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/Go/all.zip":
			w.Write(zipData)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	// Setup
	s := setupTestStore(t)
	f := fetcher.New(fetcher.WithBaseURL(server.URL))
	p := parser.New()

	var progressEvents []Progress
	ing := New(f, p, s,
		WithBatchSize(10),
		WithProgress(func(prog Progress) {
			progressEvents = append(progressEvents, prog)
		}),
	)

	// Execute full import
	ctx := context.Background()
	stats, err := ing.FullImport(ctx, "Go")
	if err != nil {
		t.Fatalf("FullImport failed: %v", err)
	}

	// Verify stats
	if stats.Total != 2 {
		t.Errorf("Total = %d, want 2", stats.Total)
	}
	if stats.Inserted != 2 {
		t.Errorf("Inserted = %d, want 2", stats.Inserted)
	}
	if stats.Errors != 0 {
		t.Errorf("Errors = %d, want 0", stats.Errors)
	}
	if !stats.IsFullSync {
		t.Error("IsFullSync should be true")
	}
	if stats.Duration <= 0 {
		t.Error("Duration should be > 0")
	}

	// Verify data is in DB
	vuln, err := s.GetByID(ctx, "GO-2024-2687")
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if vuln == nil {
		t.Fatal("GO-2024-2687 not found in DB")
	}
	if vuln.ID != "GO-2024-2687" {
		t.Errorf("ID = %q, want GO-2024-2687", vuln.ID)
	}

	vuln2, err := s.GetByID(ctx, "GO-2023-1840")
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if vuln2 == nil {
		t.Fatal("GO-2023-1840 not found in DB")
	}

	// Verify sync state was updated
	syncState, err := s.GetSyncState(ctx, "Go")
	if err != nil {
		t.Fatalf("GetSyncState failed: %v", err)
	}
	if syncState == nil {
		t.Fatal("sync state is nil")
	}
	if syncState.RecordCount != 2 {
		t.Errorf("RecordCount = %d, want 2", syncState.RecordCount)
	}

	// Verify progress was reported
	if len(progressEvents) == 0 {
		t.Error("no progress events reported")
	}
}

func TestDeltaImport(t *testing.T) {
	// Read real test data
	data1, err := os.ReadFile("../../testdata/GO-2024-2687.json")
	if err != nil {
		t.Fatalf("read test data: %v", err)
	}

	// Timestamps
	oldTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	newTime := time.Date(2024, 8, 15, 0, 5, 0, 0, time.UTC)

	// CSV showing GO-2024-2687 was updated after our last sync
	csv := fmt.Sprintf("%s,GO-2024-2687\n%s,GO-2023-1840\n",
		newTime.Format(time.RFC3339),
		oldTime.Format(time.RFC3339),
	)

	// Mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/Go/modified_id.csv":
			w.Write([]byte(csv))
		case "/Go/GO-2024-2687.json":
			w.Write(data1)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	// Setup
	s := setupTestStore(t)
	f := fetcher.New(fetcher.WithBaseURL(server.URL))
	p := parser.New()
	ing := New(f, p, s, WithBatchSize(10))

	ctx := context.Background()

	// Set up an existing sync state (last synced at a time between old and new)
	existingState := &store.SyncState{
		Ecosystem:      "Go",
		LastModifiedAt: time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339),
		RecordCount:    50,
	}
	if err := s.UpdateSyncState(ctx, existingState); err != nil {
		t.Fatalf("setup sync state: %v", err)
	}

	// Execute delta import
	stats, err := ing.DeltaImport(ctx, "Go")
	if err != nil {
		t.Fatalf("DeltaImport failed: %v", err)
	}

	// Should only have fetched GO-2024-2687 (newer than last sync)
	if stats.Total != 1 {
		t.Errorf("Total = %d, want 1", stats.Total)
	}
	if stats.Inserted != 1 {
		t.Errorf("Inserted = %d, want 1", stats.Inserted)
	}
	if stats.IsFullSync {
		t.Error("IsFullSync should be false")
	}

	// Verify it's in the DB
	vuln, err := s.GetByID(ctx, "GO-2024-2687")
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if vuln == nil {
		t.Fatal("GO-2024-2687 not found in DB")
	}

	// GO-2023-1840 should NOT be in DB (it was older than our last sync)
	vuln2, err := s.GetByID(ctx, "GO-2023-1840")
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if vuln2 != nil {
		t.Error("GO-2023-1840 should not be in DB (not modified since last sync)")
	}

	// Verify sync state was updated
	syncState, err := s.GetSyncState(ctx, "Go")
	if err != nil {
		t.Fatalf("GetSyncState failed: %v", err)
	}
	if syncState == nil {
		t.Fatal("sync state is nil")
	}
	if syncState.RecordCount != 51 {
		t.Errorf("RecordCount = %d, want 51 (50 + 1)", syncState.RecordCount)
	}
}

func TestDeltaImport_NoSyncState_FallsBackToFull(t *testing.T) {
	// Read test data
	data1, err := os.ReadFile("../../testdata/GO-2024-2687.json")
	if err != nil {
		t.Fatalf("read test data: %v", err)
	}

	zipData := createTestZip(t, map[string]string{
		"GO-2024-2687.json": string(data1),
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/Go/all.zip":
			w.Write(zipData)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	s := setupTestStore(t)
	f := fetcher.New(fetcher.WithBaseURL(server.URL))
	p := parser.New()
	ing := New(f, p, s, WithBatchSize(10))

	ctx := context.Background()

	// No sync state exists — should fall back to full import
	stats, err := ing.DeltaImport(ctx, "Go")
	if err != nil {
		t.Fatalf("DeltaImport failed: %v", err)
	}

	if !stats.IsFullSync {
		t.Error("should fall back to full sync when no sync state exists")
	}
	if stats.Inserted != 1 {
		t.Errorf("Inserted = %d, want 1", stats.Inserted)
	}
}
