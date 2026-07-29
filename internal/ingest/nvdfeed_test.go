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

func TestNvdYearSource(t *testing.T) {
	tests := []struct {
		year int
		want string
	}{
		{2002, "NVD-native:2002"},
		{2024, "NVD-native:2024"},
		{2026, "NVD-native:2026"},
	}
	for _, tt := range tests {
		got := nvdYearSource(tt.year)
		if got != tt.want {
			t.Errorf("nvdYearSource(%d) = %q, want %q", tt.year, got, tt.want)
		}
	}
}

func TestNeedsFullYearImport(t *testing.T) {
	now := time.Now().UTC()

	tests := []struct {
		name     string
		state    *store.SyncState
		wantFull bool
	}{
		{"nil state", nil, true},
		{"empty last synced", &store.SyncState{Source: "NVD-native:2024", LastSyncedAt: ""}, true},
		{"invalid date", &store.SyncState{Source: "NVD-native:2024", LastSyncedAt: "invalid"}, true},
		{"9 days ago", &store.SyncState{Source: "NVD-native:2024", LastSyncedAt: now.Add(-9 * 24 * time.Hour).Format(time.RFC3339)}, true},
		{"8 days 1 hour ago", &store.SyncState{Source: "NVD-native:2024", LastSyncedAt: now.Add(-8*24*time.Hour - time.Hour).Format(time.RFC3339)}, true},
		{"7 days ago", &store.SyncState{Source: "NVD-native:2024", LastSyncedAt: now.Add(-7 * 24 * time.Hour).Format(time.RFC3339)}, false},
		{"1 hour ago", &store.SyncState{Source: "NVD-native:2024", LastSyncedAt: now.Add(-1 * time.Hour).Format(time.RFC3339)}, false},
		{"7 days ago (RFC3339Nano)", &store.SyncState{Source: "NVD-native:2024", LastSyncedAt: now.Add(-7 * 24 * time.Hour).Format(time.RFC3339Nano)}, false},
		{"1 hour ago (RFC3339Nano)", &store.SyncState{Source: "NVD-native:2024", LastSyncedAt: now.Add(-1 * time.Hour).Format(time.RFC3339Nano)}, false},
		{"9 days ago (RFC3339Nano)", &store.SyncState{Source: "NVD-native:2024", LastSyncedAt: now.Add(-9 * 24 * time.Hour).Format(time.RFC3339Nano)}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := needsFullYearImport(tt.state)
			if got != tt.wantFull {
				t.Errorf("needsFullYearImport() = %v, want %v", got, tt.wantFull)
			}
		})
	}
}

func TestExtractCVEYear(t *testing.T) {
	tests := []struct {
		cveID string
		want  int
	}{
		{"CVE-2002-0001", 2002},
		{"CVE-2017-6770", 2017},
		{"CVE-2024-12345", 2024},
		{"CVE-2026-99999", 2026},
		{"INVALID-ID", 0},
		{"CVE-", 0},
		{"CVE-notayear-123", 0},
		{"", 0},
	}

	for _, tt := range tests {
		t.Run(tt.cveID, func(t *testing.T) {
			got := extractCVEYear(tt.cveID)
			if got != tt.want {
				t.Errorf("extractCVEYear(%q) = %d, want %d", tt.cveID, got, tt.want)
			}
		})
	}
}

func TestGroupCVEsByYear(t *testing.T) {
	entries := []*model.NVDCVE{
		{ID: "CVE-2017-0001"},
		{ID: "CVE-2017-0002"},
		{ID: "CVE-2024-1000"},
		{ID: "CVE-2024-2000"},
		{ID: "CVE-2024-3000"},
		{ID: "CVE-2002-0001"},
	}

	result := groupCVEsByYear(entries)

	if len(result[2017]) != 2 {
		t.Errorf("year 2017: got %d entries, want 2", len(result[2017]))
	}
	if len(result[2024]) != 3 {
		t.Errorf("year 2024: got %d entries, want 3", len(result[2024]))
	}
	if len(result[2002]) != 1 {
		t.Errorf("year 2002: got %d entries, want 1", len(result[2002]))
	}
	if len(result[2023]) != 0 {
		t.Errorf("year 2023: got %d entries, want 0", len(result[2023]))
	}
}

func TestGroupCVEsByYear_InvalidIDs(t *testing.T) {
	entries := []*model.NVDCVE{
		{ID: "INVALID"},
		{ID: "CVE-2024-1000"},
		{ID: ""},
	}

	result := groupCVEsByYear(entries)

	if len(result[2024]) != 1 {
		t.Errorf("year 2024: got %d entries, want 1", len(result[2024]))
	}
	// Invalid entries should not appear in any group
	total := 0
	for _, v := range result {
		total += len(v)
	}
	if total != 1 {
		t.Errorf("total grouped entries: got %d, want 1", total)
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
func (m *mockNVDStore) RefreshSummary(ctx context.Context, vulnIDs []string) error     { return nil }
func (m *mockNVDStore) RefreshEPSSSummary(ctx context.Context, vulnIDs []string) error { return nil }
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
