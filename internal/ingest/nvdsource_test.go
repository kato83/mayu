package ingest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kato83/mayu/internal/fetcher"
	"github.com/kato83/mayu/internal/model"
	"github.com/kato83/mayu/internal/parser"
	"github.com/kato83/mayu/internal/store"
)

// mockStoreForNVDSources implements the minimal store interface for NVD source sync tests.
type mockStoreForNVDSources struct {
	store.Store
	syncState       *store.SyncState
	updatedState    *store.SyncState
	upsertedSources []model.NVDSource
}

func (m *mockStoreForNVDSources) GetSyncState(_ context.Context, source string) (*store.SyncState, error) {
	if m.syncState != nil && m.syncState.Source == source {
		return m.syncState, nil
	}
	return nil, nil
}

func (m *mockStoreForNVDSources) UpdateSyncState(_ context.Context, state *store.SyncState) error {
	m.updatedState = state
	return nil
}

func (m *mockStoreForNVDSources) UpsertNVDSources(_ context.Context, sources []model.NVDSource) error {
	m.upsertedSources = append(m.upsertedSources, sources...)
	return nil
}

func TestSyncNVDSourcesSkipsWhenRecent(t *testing.T) {
	// Setup a mock store that reports a recent sync
	ms := &mockStoreForNVDSources{
		syncState: &store.SyncState{
			Source:       "NVD-sources",
			SourceType:   "nvd",
			LastSyncedAt: time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339),
			RecordCount:  496,
		},
	}

	// Server should NOT be called if sync is recent
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"totalResults":0,"sources":[]}`))
	}))
	defer server.Close()

	f := fetcher.New(fetcher.WithNVDSourceURL(server.URL + "/rest/json/source/2.0"))
	p := parser.New()
	ing := New(f, p, ms)

	err := ing.SyncNVDSources(context.Background())
	if err != nil {
		t.Fatalf("SyncNVDSources() error = %v", err)
	}

	if called {
		t.Error("expected NVD Source API to NOT be called when sync is recent")
	}
}

func TestSyncNVDSourcesFetchesWhenStale(t *testing.T) {
	ms := &mockStoreForNVDSources{
		syncState: &store.SyncState{
			Source:       "NVD-sources",
			SourceType:   "nvd",
			LastSyncedAt: time.Now().Add(-25 * time.Hour).UTC().Format(time.RFC3339),
			RecordCount:  496,
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"totalResults": 1,
			"sources": [
				{
					"name": "kernel.org",
					"contactEmail": "cve@kernel.org",
					"sourceIdentifiers": ["416baaa9-dc9f-4396-8d5f-8c081fb06d67"],
					"lastModified": "2024-02-20T13:15:08.140",
					"created": "2024-02-20T13:15:08.140"
				}
			]
		}`))
	}))
	defer server.Close()

	f := fetcher.New(fetcher.WithNVDSourceURL(server.URL + "/rest/json/source/2.0"))
	p := parser.New()
	ing := New(f, p, ms)

	err := ing.SyncNVDSources(context.Background())
	if err != nil {
		t.Fatalf("SyncNVDSources() error = %v", err)
	}

	if len(ms.upsertedSources) != 1 {
		t.Errorf("expected 1 upserted source, got %d", len(ms.upsertedSources))
	}
	if ms.upsertedSources[0].Name != "kernel.org" {
		t.Errorf("expected name %q, got %q", "kernel.org", ms.upsertedSources[0].Name)
	}
	if ms.updatedState == nil {
		t.Fatal("expected sync state to be updated")
	}
	if ms.updatedState.Source != "NVD-sources" {
		t.Errorf("expected source %q, got %q", "NVD-sources", ms.updatedState.Source)
	}
}

func TestSyncNVDSourcesFetchesWhenNoState(t *testing.T) {
	ms := &mockStoreForNVDSources{
		syncState: nil, // no previous sync
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"totalResults": 1,
			"sources": [
				{
					"name": "CISA-ADP",
					"sourceIdentifiers": ["134c704f-9b21-4f2e-91b3-4a467353bcc0"]
				}
			]
		}`))
	}))
	defer server.Close()

	f := fetcher.New(fetcher.WithNVDSourceURL(server.URL + "/rest/json/source/2.0"))
	p := parser.New()
	ing := New(f, p, ms)

	err := ing.SyncNVDSources(context.Background())
	if err != nil {
		t.Fatalf("SyncNVDSources() error = %v", err)
	}

	if len(ms.upsertedSources) != 1 {
		t.Errorf("expected 1 upserted source, got %d", len(ms.upsertedSources))
	}
}
