package ingest

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kato83/mayu/internal/model"
	"github.com/kato83/mayu/internal/store"
)

func TestMITRESourceName(t *testing.T) {
	if mitreSource != "MITRE" {
		t.Errorf("mitreSource = %q, want %q", mitreSource, "MITRE")
	}
}

func TestShouldFallbackToFullMITREImport(t *testing.T) {
	now := time.Now().UTC()

	tests := []struct {
		name     string
		state    *store.SyncState
		wantFull bool
	}{
		{"nil state", nil, true},
		{"empty last modified", &store.SyncState{Source: mitreSource, LastModifiedAt: ""}, true},
		{"invalid date", &store.SyncState{Source: mitreSource, LastModifiedAt: "not-a-date"}, true},
		{"25 hours ago", &store.SyncState{Source: mitreSource, LastModifiedAt: now.Add(-25 * time.Hour).Format(time.RFC3339)}, true},
		{"48 hours ago", &store.SyncState{Source: mitreSource, LastModifiedAt: now.Add(-48 * time.Hour).Format(time.RFC3339)}, true},
		{"23 hours ago", &store.SyncState{Source: mitreSource, LastModifiedAt: now.Add(-23 * time.Hour).Format(time.RFC3339)}, false},
		{"1 hour ago", &store.SyncState{Source: mitreSource, LastModifiedAt: now.Add(-1 * time.Hour).Format(time.RFC3339)}, false},
		{"just now", &store.SyncState{Source: mitreSource, LastModifiedAt: now.Format(time.RFC3339)}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldFallbackToFullMITREImport(tt.state)
			if got != tt.wantFull {
				t.Errorf("shouldFallbackToFullMITREImport() = %v, want %v", got, tt.wantFull)
			}
		})
	}
}

// mockMITREStore implements the mitreBatchStore and store.Store interfaces for testing.
type mockMITREStore struct {
	store.Store
	batches    [][]*model.MITRECVERecord
	failAt     int // fail at this batch index (-1 = never fail)
	syncStates map[string]*store.SyncState
}

func newMockMITREStore() *mockMITREStore {
	return &mockMITREStore{
		failAt:     -1,
		syncStates: make(map[string]*store.SyncState),
	}
}

func (m *mockMITREStore) UpsertMITREBatch(ctx context.Context, entries []*model.MITRECVERecord) error {
	if m.failAt >= 0 && len(m.batches) == m.failAt {
		return fmt.Errorf("simulated batch error at index %d", m.failAt)
	}
	m.batches = append(m.batches, entries)
	return nil
}

func (m *mockMITREStore) GetSyncState(ctx context.Context, source string) (*store.SyncState, error) {
	state, ok := m.syncStates[source]
	if !ok {
		return nil, nil
	}
	return state, nil
}

func (m *mockMITREStore) UpdateSyncState(ctx context.Context, state *store.SyncState) error {
	m.syncStates[state.Source] = state
	return nil
}

func (m *mockMITREStore) Insert(ctx context.Context, vuln *model.Vulnerability) error { return nil }
func (m *mockMITREStore) UpsertBatch(ctx context.Context, vulns []*model.Vulnerability) error {
	return nil
}
func (m *mockMITREStore) RefreshSummary(ctx context.Context, vulnIDs []string) error     { return nil }
func (m *mockMITREStore) RefreshEPSSSummary(ctx context.Context, vulnIDs []string) error { return nil }
func (m *mockMITREStore) UpsertProductIdentifiers(ctx context.Context, identifiers []*model.ProductIdentifier) error {
	return nil
}
func (m *mockMITREStore) GetByID(ctx context.Context, id string) (*model.Vulnerability, error) {
	return nil, nil
}
func (m *mockMITREStore) Search(ctx context.Context, query store.SearchQuery) ([]*model.Vulnerability, error) {
	return nil, nil
}
func (m *mockMITREStore) Count(ctx context.Context, query store.SearchQuery) (int64, error) {
	return 0, nil
}
func (m *mockMITREStore) Close() error { return nil }

func TestStoreMITREBatches(t *testing.T) {
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
			ms := newMockMITREStore()
			ms.failAt = tt.failAt

			ing := New(nil, nil, ms, WithBatchSize(tt.batchSize))

			// Create test entries.
			entries := make([]*model.MITRECVERecord, tt.entries)
			for i := range entries {
				entries[i] = &model.MITRECVERecord{
					CVEMetadata: model.MITREMetadata{
						CVEID: fmt.Sprintf("CVE-2024-%04d", i),
						State: "PUBLISHED",
					},
				}
			}

			inserted, err := ing.storeMITREBatches(context.Background(), entries)
			if (err != nil) != tt.wantErr {
				t.Errorf("storeMITREBatches() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if inserted != tt.wantCount {
				t.Errorf("storeMITREBatches() inserted = %d, want %d", inserted, tt.wantCount)
			}

			// Verify batch sizes.
			if !tt.wantErr && tt.entries > 0 {
				expectedBatches := (tt.entries + tt.batchSize - 1) / tt.batchSize
				if len(ms.batches) != expectedBatches {
					t.Errorf("got %d batches, want %d", len(ms.batches), expectedBatches)
				}
			}
		})
	}
}

func TestStoreMITREBatches_ContextCancellation(t *testing.T) {
	ms := newMockMITREStore()
	ing := New(nil, nil, ms, WithBatchSize(5))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	entries := make([]*model.MITRECVERecord, 20)
	for i := range entries {
		entries[i] = &model.MITRECVERecord{
			CVEMetadata: model.MITREMetadata{
				CVEID: fmt.Sprintf("CVE-2024-%04d", i),
				State: "PUBLISHED",
			},
		}
	}

	_, err := ing.storeMITREBatches(ctx, entries)
	if err == nil {
		t.Error("expected error from cancelled context, got nil")
	}
}

func TestStoreMITREBatches_UnsupportedStore(t *testing.T) {
	// Use a store that doesn't implement mitreBatchStore interface.
	type plainStore struct {
		store.Store
	}

	ing := New(nil, nil, &plainStore{}, WithBatchSize(10))

	entries := []*model.MITRECVERecord{
		{CVEMetadata: model.MITREMetadata{CVEID: "CVE-2024-0001", State: "PUBLISHED"}},
	}
	_, err := ing.storeMITREBatches(context.Background(), entries)
	if err == nil {
		t.Error("expected error for unsupported store, got nil")
	}
}
