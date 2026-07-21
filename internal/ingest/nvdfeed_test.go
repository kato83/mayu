package ingest

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kato83/mayu/internal/model"
	"github.com/kato83/mayu/internal/store"
)

func TestNVDNativeSourceName(t *testing.T) {
	if nvdNativeSource != "NVD-native" {
		t.Errorf("nvdNativeSource = %q, want %q", nvdNativeSource, "NVD-native")
	}
}

func TestShouldFallbackToFullImport(t *testing.T) {
	now := time.Now().UTC()

	tests := []struct {
		name     string
		state    *store.SyncState
		wantFull bool
	}{
		{"nil state", nil, true},
		{"empty last modified", &store.SyncState{Source: nvdNativeSource, LastModifiedAt: ""}, true},
		{"invalid date", &store.SyncState{Source: nvdNativeSource, LastModifiedAt: "invalid"}, true},
		{"9 days ago", &store.SyncState{Source: nvdNativeSource, LastModifiedAt: now.Add(-9 * 24 * time.Hour).Format(time.RFC3339)}, true},
		{"7 days ago", &store.SyncState{Source: nvdNativeSource, LastModifiedAt: now.Add(-7 * 24 * time.Hour).Format(time.RFC3339)}, false},
		{"1 hour ago", &store.SyncState{Source: nvdNativeSource, LastModifiedAt: now.Add(-1 * time.Hour).Format(time.RFC3339)}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldFallbackToFullImport(tt.state)
			if got != tt.wantFull {
				t.Errorf("shouldFallbackToFullImport() = %v, want %v", got, tt.wantFull)
			}
		})
	}
}

// mockNVDStore implements the nvdStore interface for testing storeNVDBatches.
type mockNVDStore struct {
	store.Store
	batches    [][]*model.NVDCVE
	failAt     int // fail at this batch index (-1 = never fail)
	syncStates map[string]*store.SyncState
}

func newMockNVDStore() *mockNVDStore {
	return &mockNVDStore{
		failAt:     -1,
		syncStates: make(map[string]*store.SyncState),
	}
}

func (m *mockNVDStore) UpsertNVDBatch(ctx context.Context, entries []*model.NVDCVE) error {
	if m.failAt >= 0 && len(m.batches) == m.failAt {
		return fmt.Errorf("simulated batch error at index %d", m.failAt)
	}
	m.batches = append(m.batches, entries)
	return nil
}

func (m *mockNVDStore) GetSyncState(ctx context.Context, source string) (*store.SyncState, error) {
	state, ok := m.syncStates[source]
	if !ok {
		return nil, nil
	}
	return state, nil
}

func (m *mockNVDStore) UpdateSyncState(ctx context.Context, state *store.SyncState) error {
	m.syncStates[state.Source] = state
	return nil
}

func (m *mockNVDStore) Insert(ctx context.Context, vuln *model.Vulnerability) error { return nil }
func (m *mockNVDStore) UpsertBatch(ctx context.Context, vulns []*model.Vulnerability) error {
	return nil
}
func (m *mockNVDStore) RefreshSummary(ctx context.Context, vulnIDs []string) error { return nil }
func (m *mockNVDStore) UpsertProductIdentifiers(ctx context.Context, identifiers []*model.ProductIdentifier) error {
	return nil
}
func (m *mockNVDStore) GetByID(ctx context.Context, id string) (*model.Vulnerability, error) {
	return nil, nil
}
func (m *mockNVDStore) Search(ctx context.Context, query store.SearchQuery) ([]*model.Vulnerability, error) {
	return nil, nil
}
func (m *mockNVDStore) Count(ctx context.Context, query store.SearchQuery) (int64, error) {
	return 0, nil
}
func (m *mockNVDStore) Close() error { return nil }

func TestStoreNVDBatches(t *testing.T) {
	tests := []struct {
		name      string
		entries   int
		batchSize int
		failAt    int
		wantCount int
		wantErr   bool
	}{
		{"empty entries", 0, 10, -1, 0, false},
		{"single batch", 5, 10, -1, 5, false},
		{"exact batch boundary", 10, 10, -1, 10, false},
		{"multiple batches", 25, 10, -1, 25, false},
		{"batch size 1", 3, 1, -1, 3, false},
		{"fail at second batch", 25, 10, 1, 10, true},
		{"fail at first batch", 10, 10, 0, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ms := newMockNVDStore()
			ms.failAt = tt.failAt

			ing := New(nil, nil, ms, WithBatchSize(tt.batchSize))

			// Create test entries
			entries := make([]*model.NVDCVE, tt.entries)
			for i := range entries {
				entries[i] = &model.NVDCVE{ID: fmt.Sprintf("CVE-2024-%04d", i)}
			}

			inserted, err := ing.storeNVDBatches(context.Background(), entries)
			if (err != nil) != tt.wantErr {
				t.Errorf("storeNVDBatches() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if inserted != tt.wantCount {
				t.Errorf("storeNVDBatches() inserted = %d, want %d", inserted, tt.wantCount)
			}

			// Verify batch sizes
			if !tt.wantErr && tt.entries > 0 {
				expectedBatches := (tt.entries + tt.batchSize - 1) / tt.batchSize
				if len(ms.batches) != expectedBatches {
					t.Errorf("got %d batches, want %d", len(ms.batches), expectedBatches)
				}
			}
		})
	}
}

func TestStoreNVDBatches_ContextCancellation(t *testing.T) {
	ms := newMockNVDStore()
	ing := New(nil, nil, ms, WithBatchSize(5))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	entries := make([]*model.NVDCVE, 20)
	for i := range entries {
		entries[i] = &model.NVDCVE{ID: fmt.Sprintf("CVE-2024-%04d", i)}
	}

	_, err := ing.storeNVDBatches(ctx, entries)
	if err == nil {
		t.Error("expected error from cancelled context, got nil")
	}
}

func TestStoreNVDBatches_UnsupportedStore(t *testing.T) {
	// Use a store that doesn't implement nvdStore interface
	type plainStore struct {
		store.Store
	}

	ing := New(nil, nil, &plainStore{}, WithBatchSize(10))

	entries := []*model.NVDCVE{{ID: "CVE-2024-0001"}}
	_, err := ing.storeNVDBatches(context.Background(), entries)
	if err == nil {
		t.Error("expected error for unsupported store, got nil")
	}
}
