package ingest

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kato83/mayu/internal/model"
	"github.com/kato83/mayu/internal/store"
)

func TestKEVSourceName(t *testing.T) {
	if kevSource != "KEV" {
		t.Errorf("kevSource = %q, want %q", kevSource, "KEV")
	}
}

// mockKEVStore implements the kevBatchStore and store.Store interfaces for testing.
type mockKEVStore struct {
	store.Store
	batches    [][]*model.KEVRecord
	failAt     int // fail at this batch index (-1 = never fail)
	syncStates map[string]*store.SyncState
}

func newMockKEVStore() *mockKEVStore {
	return &mockKEVStore{
		failAt:     -1,
		syncStates: make(map[string]*store.SyncState),
	}
}

func (m *mockKEVStore) UpsertKEVBatch(ctx context.Context, records []*model.KEVRecord) error {
	if m.failAt >= 0 && len(m.batches) == m.failAt {
		return fmt.Errorf("simulated batch error at index %d", m.failAt)
	}
	m.batches = append(m.batches, records)
	return nil
}

func (m *mockKEVStore) GetSyncState(ctx context.Context, source string) (*store.SyncState, error) {
	state, ok := m.syncStates[source]
	if !ok {
		return nil, nil
	}
	return state, nil
}

func (m *mockKEVStore) UpdateSyncState(ctx context.Context, state *store.SyncState) error {
	m.syncStates[state.Source] = state
	return nil
}

func (m *mockKEVStore) Insert(ctx context.Context, vuln *model.Vulnerability) error { return nil }
func (m *mockKEVStore) UpsertBatch(ctx context.Context, vulns []*model.Vulnerability) error {
	return nil
}
func (m *mockKEVStore) GetByID(ctx context.Context, id string) (*model.Vulnerability, error) {
	return nil, nil
}
func (m *mockKEVStore) GetVulnerabilityDetail(ctx context.Context, id string) (*model.VulnerabilityDetail, error) {
	return nil, nil
}
func (m *mockKEVStore) Search(ctx context.Context, query store.SearchQuery) ([]*model.Vulnerability, error) {
	return nil, nil
}
func (m *mockKEVStore) Count(ctx context.Context, query store.SearchQuery) (int64, error) {
	return 0, nil
}
func (m *mockKEVStore) Close() error { return nil }

func TestStoreKEVBatches(t *testing.T) {
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
			ms := newMockKEVStore()
			ms.failAt = tt.failAt

			ing := New(nil, nil, ms, WithBatchSize(tt.batchSize))

			// Create test records.
			records := make([]*model.KEVRecord, tt.entries)
			for i := range records {
				records[i] = &model.KEVRecord{
					CVEID:                      fmt.Sprintf("CVE-2024-%04d", i),
					VendorProject:              "TestVendor",
					Product:                    "TestProduct",
					VulnerabilityName:          "Test Vulnerability",
					DateAdded:                  time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
					ShortDescription:           "Test description",
					RequiredAction:             "Apply patch",
					DueDate:                    time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC),
					KnownRansomwareCampaignUse: "Unknown",
				}
			}

			inserted, err := ing.storeKEVBatches(context.Background(), records)
			if (err != nil) != tt.wantErr {
				t.Errorf("storeKEVBatches() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if inserted != tt.wantCount {
				t.Errorf("storeKEVBatches() inserted = %d, want %d", inserted, tt.wantCount)
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

func TestStoreKEVBatches_ContextCancellation(t *testing.T) {
	ms := newMockKEVStore()
	ing := New(nil, nil, ms, WithBatchSize(5))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	records := make([]*model.KEVRecord, 20)
	for i := range records {
		records[i] = &model.KEVRecord{
			CVEID:                      fmt.Sprintf("CVE-2024-%04d", i),
			VendorProject:              "TestVendor",
			Product:                    "TestProduct",
			VulnerabilityName:          "Test Vulnerability",
			DateAdded:                  time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			ShortDescription:           "Test description",
			RequiredAction:             "Apply patch",
			DueDate:                    time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC),
			KnownRansomwareCampaignUse: "Unknown",
		}
	}

	_, err := ing.storeKEVBatches(ctx, records)
	if err == nil {
		t.Error("expected error from cancelled context, got nil")
	}
}

func TestStoreKEVBatches_UnsupportedStore(t *testing.T) {
	// Use a store that doesn't implement kevBatchStore interface.
	type plainStore struct {
		store.Store
	}

	ing := New(nil, nil, &plainStore{}, WithBatchSize(10))

	records := []*model.KEVRecord{
		{
			CVEID:                      "CVE-2024-0001",
			VendorProject:              "TestVendor",
			Product:                    "TestProduct",
			VulnerabilityName:          "Test Vulnerability",
			DateAdded:                  time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			ShortDescription:           "Test description",
			RequiredAction:             "Apply patch",
			DueDate:                    time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC),
			KnownRansomwareCampaignUse: "Unknown",
		},
	}
	_, err := ing.storeKEVBatches(context.Background(), records)
	if err == nil {
		t.Error("expected error for unsupported store, got nil")
	}
}
