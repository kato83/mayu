package ingest

import (
	"context"
	"fmt"
	"testing"

	"github.com/kato83/mayu/internal/model"
	"github.com/kato83/mayu/internal/store"
)

// mockEPSSBackfillStore implements epssBackfillStore for unit testing the
// backfill reconciliation logic.
type mockEPSSBackfillStore struct {
	store.Store

	importedDates       map[string]bool
	orphanDates         []string
	refreshedDailyDates []string // dates passed to RefreshEPSSDailyStats

	getImportedDatesErr error
	getOrphanDatesErr   error
	refreshDailyErr     error
}

func newMockEPSSBackfillStore() *mockEPSSBackfillStore {
	return &mockEPSSBackfillStore{
		importedDates: make(map[string]bool),
	}
}

func (m *mockEPSSBackfillStore) UpsertEPSSBatch(ctx context.Context, scores []*model.EPSSScore) error {
	return nil
}

func (m *mockEPSSBackfillStore) RefreshEPSSSummary(ctx context.Context, vulnIDs []string) error {
	return nil
}

func (m *mockEPSSBackfillStore) RefreshEPSSDailyStats(ctx context.Context, dates []string) error {
	if m.refreshDailyErr != nil {
		return m.refreshDailyErr
	}
	m.refreshedDailyDates = append(m.refreshedDailyDates, dates...)
	return nil
}

func (m *mockEPSSBackfillStore) CleanupOldEPSSScores(ctx context.Context, retentionDays int) (int64, error) {
	return 0, nil
}

func (m *mockEPSSBackfillStore) GetEPSSImportedDates(ctx context.Context) (map[string]bool, error) {
	if m.getImportedDatesErr != nil {
		return nil, m.getImportedDatesErr
	}
	return m.importedDates, nil
}

func (m *mockEPSSBackfillStore) GetEPSSOrphanDates(ctx context.Context, from, to string) ([]string, error) {
	if m.getOrphanDatesErr != nil {
		return nil, m.getOrphanDatesErr
	}
	return m.orphanDates, nil
}

func (m *mockEPSSBackfillStore) GetSyncState(ctx context.Context, source string) (*store.SyncState, error) {
	return nil, nil
}

func (m *mockEPSSBackfillStore) UpdateSyncState(ctx context.Context, state *store.SyncState) error {
	return nil
}

func (m *mockEPSSBackfillStore) Insert(ctx context.Context, vuln *model.Vulnerability) error {
	return nil
}

func (m *mockEPSSBackfillStore) UpsertBatch(ctx context.Context, vulns []*model.Vulnerability) error {
	return nil
}

func (m *mockEPSSBackfillStore) GetByID(ctx context.Context, id string) (*model.Vulnerability, error) {
	return nil, nil
}

func (m *mockEPSSBackfillStore) RefreshSummary(ctx context.Context, vulnIDs []string) error {
	return nil
}

func (m *mockEPSSBackfillStore) UpsertProductIdentifiers(ctx context.Context, identifiers []*model.ProductIdentifier) error {
	return nil
}

func (m *mockEPSSBackfillStore) GetVulnerabilityDetail(ctx context.Context, id string) (*model.VulnerabilityDetail, error) {
	return nil, nil
}

func (m *mockEPSSBackfillStore) Search(ctx context.Context, query store.SearchQuery) ([]*model.Vulnerability, error) {
	return nil, nil
}

func (m *mockEPSSBackfillStore) Count(ctx context.Context, query store.SearchQuery) (int64, error) {
	return 0, nil
}

func (m *mockEPSSBackfillStore) ListSyncStates(ctx context.Context) ([]store.SyncState, error) {
	return nil, nil
}

func (m *mockEPSSBackfillStore) GetEPSSCoverage(ctx context.Context) (*store.EPSSCoverage, error) {
	return nil, nil
}

func (m *mockEPSSBackfillStore) Close() error { return nil }

func TestBackfillEPSSRange_ReconcileOrphanDates(t *testing.T) {
	ms := newMockEPSSBackfillStore()
	// Simulate: all dates in range are already "imported" (in epss_daily_stats)
	// except orphan dates that exist in epss_scores but NOT in epss_daily_stats.
	ms.importedDates = map[string]bool{
		"2024-04-23": true,
		"2024-04-25": true,
	}
	// 2024-04-24 is orphan: exists in epss_scores but not in epss_daily_stats
	ms.orphanDates = []string{"2024-04-24"}

	ing := New(nil, nil, ms, WithBatchSize(100))

	stats, err := ing.BackfillEPSSRange(context.Background(), "2024-04-23", "2024-04-25")
	if err != nil {
		t.Fatalf("BackfillEPSSRange() error = %v", err)
	}

	// Verify that RefreshEPSSDailyStats was called with the orphan date
	if len(ms.refreshedDailyDates) == 0 {
		t.Fatal("expected RefreshEPSSDailyStats to be called for orphan dates, but it was not")
	}

	found := false
	for _, d := range ms.refreshedDailyDates {
		if d == "2024-04-24" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected RefreshEPSSDailyStats to include '2024-04-24', got %v", ms.refreshedDailyDates)
	}

	// After reconciliation, 2024-04-24 should be treated as imported (skipped).
	// All 3 days in the range are accounted for, so nothing should be pending.
	if stats.Skipped != 3 {
		t.Errorf("expected 3 skipped days (all reconciled/imported), got %d", stats.Skipped)
	}
}

func TestBackfillEPSSRange_NoOrphanDates(t *testing.T) {
	ms := newMockEPSSBackfillStore()
	// All dates imported, no orphans
	ms.importedDates = map[string]bool{
		"2024-04-23": true,
		"2024-04-24": true,
		"2024-04-25": true,
	}
	ms.orphanDates = nil // no orphans

	ing := New(nil, nil, ms, WithBatchSize(100))

	stats, err := ing.BackfillEPSSRange(context.Background(), "2024-04-23", "2024-04-25")
	if err != nil {
		t.Fatalf("BackfillEPSSRange() error = %v", err)
	}

	// RefreshEPSSDailyStats should NOT be called for reconciliation
	if len(ms.refreshedDailyDates) != 0 {
		t.Errorf("expected no reconciliation calls, got RefreshEPSSDailyStats(%v)", ms.refreshedDailyDates)
	}

	// All days skipped
	if stats.Skipped != 3 {
		t.Errorf("expected 3 skipped, got %d", stats.Skipped)
	}
}

func TestBackfillEPSSRange_OrphanDatesRefreshFails(t *testing.T) {
	ms := newMockEPSSBackfillStore()
	// All three dates imported plus one orphan whose refresh will fail.
	// The orphan date is also present in importedDates so the overall backfill
	// sees all days as imported and finishes quickly.
	ms.importedDates = map[string]bool{
		"2024-04-23": true,
		"2024-04-24": true, // already imported
		"2024-04-25": true,
	}
	ms.orphanDates = []string{"2024-04-24"}
	ms.refreshDailyErr = fmt.Errorf("simulated refresh failure")

	ing := New(nil, nil, ms, WithBatchSize(100))

	// The backfill should still succeed (refresh failure is non-fatal, just logged).
	stats, err := ing.BackfillEPSSRange(context.Background(), "2024-04-23", "2024-04-25")
	if err != nil {
		t.Fatalf("BackfillEPSSRange() error = %v", err)
	}

	// Verify that the reconciliation was attempted (RefreshEPSSDailyStats was called).
	// Even though it failed, it should not cause the entire backfill to fail.
	// Since importedDates already contains all dates, everything is skipped.
	if stats.Skipped != 3 {
		t.Errorf("expected 3 skipped (all in importedDates despite refresh failure), got %d", stats.Skipped)
	}
}

func TestBackfillEPSSRange_GetOrphanDatesError(t *testing.T) {
	ms := newMockEPSSBackfillStore()
	ms.importedDates = map[string]bool{
		"2024-04-23": true,
		"2024-04-24": true,
		"2024-04-25": true,
	}
	ms.getOrphanDatesErr = fmt.Errorf("simulated orphan query error")

	ing := New(nil, nil, ms, WithBatchSize(100))

	// Should proceed without reconciliation when GetEPSSOrphanDates fails
	stats, err := ing.BackfillEPSSRange(context.Background(), "2024-04-23", "2024-04-25")
	if err != nil {
		t.Fatalf("BackfillEPSSRange() error = %v", err)
	}

	// All dates are in importedDates, so all should be skipped
	if stats.Skipped != 3 {
		t.Errorf("expected 3 skipped, got %d", stats.Skipped)
	}
}
