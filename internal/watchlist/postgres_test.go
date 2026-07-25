//go:build integration

package watchlist

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/kato83/mayu/internal/testhelper"
)

type testEnv struct {
	store  *PostgresWatchlistStore
	db     *sql.DB
	userID int64
}

func setupTestStore(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()

	pg := testhelper.SetupPostgres(t)

	db, err := sql.Open("pgx", pg.DatabaseURL)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("failed to ping database: %v", err)
	}

	t.Cleanup(func() {
		db.Close()
	})

	// Create a test user for watchlist operations
	var userID int64
	err = db.QueryRowContext(ctx, `
		INSERT INTO users (email, name, role)
		VALUES ('test@example.com', 'Test User', 'admin')
		RETURNING id`).Scan(&userID)
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	// Create a test vulnerability for match operations
	_, err = db.ExecContext(ctx, `
		INSERT INTO vulnerabilities (id, summary, modified)
		VALUES ('CVE-2024-0001', 'Test vulnerability', NOW())
		ON CONFLICT DO NOTHING`)
	if err != nil {
		t.Fatalf("failed to create test vulnerability: %v", err)
	}

	return &testEnv{
		store:  NewPostgresWatchlistStore(db),
		db:     db,
		userID: userID,
	}
}


func TestCreateAndGetWatchlist(t *testing.T) {
	env := setupTestStore(t)
	ctx := context.Background()

	eco := "Go"
	pkg := "golang.org/x/net"
	sev := int16(4)
	epss := 0.5

	w := &Watchlist{
		UserID:        env.userID,
		Name:          "My Go packages",
		MatchType:     MatchTypePackage,
		Ecosystem:     &eco,
		PackageName:   &pkg,
		SeverityMin:   &sev,
		EpssThreshold: &epss,
		Enabled:       true,
	}

	id, err := env.store.CreateWatchlist(ctx, w)
	if err != nil {
		t.Fatalf("CreateWatchlist failed: %v", err)
	}
	if id == 0 {
		t.Fatal("expected non-zero ID")
	}

	got, err := env.store.GetWatchlist(ctx, id, env.userID)
	if err != nil {
		t.Fatalf("GetWatchlist failed: %v", err)
	}
	if got == nil {
		t.Fatal("GetWatchlist returned nil")
	}

	if got.ID != id {
		t.Errorf("expected ID %d, got %d", id, got.ID)
	}
	if got.UserID != env.userID {
		t.Errorf("expected UserID %d, got %d", env.userID, got.UserID)
	}
	if got.Name != "My Go packages" {
		t.Errorf("expected Name 'My Go packages', got %q", got.Name)
	}
	if got.MatchType != MatchTypePackage {
		t.Errorf("expected MatchType %q, got %q", MatchTypePackage, got.MatchType)
	}
	if got.Ecosystem == nil || *got.Ecosystem != "Go" {
		t.Errorf("expected Ecosystem 'Go', got %v", got.Ecosystem)
	}
	if got.PackageName == nil || *got.PackageName != "golang.org/x/net" {
		t.Errorf("expected PackageName 'golang.org/x/net', got %v", got.PackageName)
	}
	if got.SeverityMin == nil || *got.SeverityMin != 4 {
		t.Errorf("expected SeverityMin 4, got %v", got.SeverityMin)
	}
	if got.EpssThreshold == nil || *got.EpssThreshold != 0.5 {
		t.Errorf("expected EpssThreshold 0.5, got %v", got.EpssThreshold)
	}
	if !got.Enabled {
		t.Error("expected Enabled true")
	}
	if got.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be set")
	}
}

func TestGetWatchlist_NotFound(t *testing.T) {
	env := setupTestStore(t)
	ctx := context.Background()

	got, err := env.store.GetWatchlist(ctx, 99999, env.userID)
	if err != nil {
		t.Fatalf("GetWatchlist failed: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for non-existent watchlist, got %+v", got)
	}
}

func TestGetWatchlist_WrongUser(t *testing.T) {
	env := setupTestStore(t)
	ctx := context.Background()

	w := &Watchlist{
		UserID:    env.userID,
		Name:      "Private watchlist",
		MatchType: MatchTypeEcosystem,
		Enabled:   true,
	}

	id, err := env.store.CreateWatchlist(ctx, w)
	if err != nil {
		t.Fatalf("CreateWatchlist failed: %v", err)
	}

	// Try to get with a different user ID
	got, err := env.store.GetWatchlist(ctx, id, env.userID+999)
	if err != nil {
		t.Fatalf("GetWatchlist failed: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for wrong user, got %+v", got)
	}
}

func TestListWatchlists(t *testing.T) {
	env := setupTestStore(t)
	ctx := context.Background()

	// Create 3 watchlists
	for i := 0; i < 3; i++ {
		w := &Watchlist{
			UserID:    env.userID,
			Name:      "Watchlist " + string(rune('A'+i)),
			MatchType: MatchTypeEcosystem,
			Enabled:   true,
		}
		if _, err := env.store.CreateWatchlist(ctx, w); err != nil {
			t.Fatalf("CreateWatchlist #%d failed: %v", i, err)
		}
	}

	list, err := env.store.ListWatchlists(ctx, env.userID)
	if err != nil {
		t.Fatalf("ListWatchlists failed: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("expected 3 watchlists, got %d", len(list))
	}
}

func TestUpdateWatchlist(t *testing.T) {
	env := setupTestStore(t)
	ctx := context.Background()

	eco := "Go"
	w := &Watchlist{
		UserID:    env.userID,
		Name:      "Original name",
		MatchType: MatchTypeEcosystem,
		Ecosystem: &eco,
		Enabled:   true,
	}

	id, err := env.store.CreateWatchlist(ctx, w)
	if err != nil {
		t.Fatalf("CreateWatchlist failed: %v", err)
	}

	// Update
	newEco := "npm"
	updated := &Watchlist{
		ID:        id,
		Name:      "Updated name",
		MatchType: MatchTypePackage,
		Ecosystem: &newEco,
		Enabled:   false,
	}
	if err := env.store.UpdateWatchlist(ctx, updated); err != nil {
		t.Fatalf("UpdateWatchlist failed: %v", err)
	}

	got, err := env.store.GetWatchlist(ctx, id, env.userID)
	if err != nil {
		t.Fatalf("GetWatchlist failed: %v", err)
	}
	if got.Name != "Updated name" {
		t.Errorf("expected Name 'Updated name', got %q", got.Name)
	}
	if got.MatchType != MatchTypePackage {
		t.Errorf("expected MatchType 'package', got %q", got.MatchType)
	}
	if got.Ecosystem == nil || *got.Ecosystem != "npm" {
		t.Errorf("expected Ecosystem 'npm', got %v", got.Ecosystem)
	}
	if got.Enabled {
		t.Error("expected Enabled false after update")
	}
	if !got.UpdatedAt.After(got.CreatedAt) {
		t.Error("expected UpdatedAt to be after CreatedAt")
	}
}

func TestDeleteWatchlist(t *testing.T) {
	env := setupTestStore(t)
	ctx := context.Background()

	w := &Watchlist{
		UserID:    env.userID,
		Name:      "To delete",
		MatchType: MatchTypeEcosystem,
		Enabled:   true,
	}

	id, err := env.store.CreateWatchlist(ctx, w)
	if err != nil {
		t.Fatalf("CreateWatchlist failed: %v", err)
	}

	if err := env.store.DeleteWatchlist(ctx, id, env.userID); err != nil {
		t.Fatalf("DeleteWatchlist failed: %v", err)
	}

	got, err := env.store.GetWatchlist(ctx, id, env.userID)
	if err != nil {
		t.Fatalf("GetWatchlist after delete failed: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil after delete, got %+v", got)
	}
}

func TestDeleteWatchlist_WrongUser(t *testing.T) {
	env := setupTestStore(t)
	ctx := context.Background()

	w := &Watchlist{
		UserID:    env.userID,
		Name:      "Protected",
		MatchType: MatchTypeEcosystem,
		Enabled:   true,
	}

	id, err := env.store.CreateWatchlist(ctx, w)
	if err != nil {
		t.Fatalf("CreateWatchlist failed: %v", err)
	}

	// Delete with wrong user should not remove it
	if err := env.store.DeleteWatchlist(ctx, id, env.userID+999); err != nil {
		t.Fatalf("DeleteWatchlist failed: %v", err)
	}

	// Should still exist
	got, err := env.store.GetWatchlist(ctx, id, env.userID)
	if err != nil {
		t.Fatalf("GetWatchlist failed: %v", err)
	}
	if got == nil {
		t.Error("expected watchlist to still exist after wrong-user delete")
	}
}

func TestRecordMatches(t *testing.T) {
	env := setupTestStore(t)
	ctx := context.Background()

	w := &Watchlist{
		UserID:    env.userID,
		Name:      "Match test",
		MatchType: MatchTypeEcosystem,
		Enabled:   true,
	}
	wID, err := env.store.CreateWatchlist(ctx, w)
	if err != nil {
		t.Fatalf("CreateWatchlist failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	matches := []WatchlistMatch{
		{
			WatchlistID:     wID,
			VulnerabilityID: "CVE-2024-0001",
			MatchedAt:       now,
			Notified:        false,
		},
	}

	if err := env.store.RecordMatches(ctx, matches); err != nil {
		t.Fatalf("RecordMatches failed: %v", err)
	}

	// Verify match was recorded
	results, err := env.store.ListMatchesByWatchlist(ctx, wID, 10, 0)
	if err != nil {
		t.Fatalf("ListMatchesByWatchlist failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 match, got %d", len(results))
	}
	if results[0].VulnerabilityID != "CVE-2024-0001" {
		t.Errorf("expected vulnerability_id 'CVE-2024-0001', got %q", results[0].VulnerabilityID)
	}
	if results[0].Notified {
		t.Error("expected Notified false")
	}
}

func TestRecordMatches_UniqueConstraint(t *testing.T) {
	env := setupTestStore(t)
	ctx := context.Background()

	w := &Watchlist{
		UserID:    env.userID,
		Name:      "Unique test",
		MatchType: MatchTypeEcosystem,
		Enabled:   true,
	}
	wID, err := env.store.CreateWatchlist(ctx, w)
	if err != nil {
		t.Fatalf("CreateWatchlist failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	matches := []WatchlistMatch{
		{WatchlistID: wID, VulnerabilityID: "CVE-2024-0001", MatchedAt: now},
	}

	// First insert should succeed
	if err := env.store.RecordMatches(ctx, matches); err != nil {
		t.Fatalf("RecordMatches (first) failed: %v", err)
	}

	// Second insert with same (watchlist_id, vulnerability_id) should be ignored
	if err := env.store.RecordMatches(ctx, matches); err != nil {
		t.Fatalf("RecordMatches (duplicate) failed: %v", err)
	}

	// Still only one match
	results, err := env.store.ListMatchesByWatchlist(ctx, wID, 10, 0)
	if err != nil {
		t.Fatalf("ListMatchesByWatchlist failed: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 match after duplicate insert, got %d", len(results))
	}
}

func TestRecordMatches_Empty(t *testing.T) {
	env := setupTestStore(t)
	ctx := context.Background()
	_ = env

	// Should be no-op
	if err := env.store.RecordMatches(ctx, nil); err != nil {
		t.Fatalf("RecordMatches with nil failed: %v", err)
	}
	if err := env.store.RecordMatches(ctx, []WatchlistMatch{}); err != nil {
		t.Fatalf("RecordMatches with empty slice failed: %v", err)
	}
}

func TestListMatchesByUser(t *testing.T) {
	env := setupTestStore(t)
	ctx := context.Background()

	// Create 2 watchlists with matches
	w1 := &Watchlist{UserID: env.userID, Name: "WL1", MatchType: MatchTypeEcosystem, Enabled: true}
	w2 := &Watchlist{UserID: env.userID, Name: "WL2", MatchType: MatchTypeEcosystem, Enabled: true}

	wID1, err := env.store.CreateWatchlist(ctx, w1)
	if err != nil {
		t.Fatalf("CreateWatchlist 1 failed: %v", err)
	}
	wID2, err := env.store.CreateWatchlist(ctx, w2)
	if err != nil {
		t.Fatalf("CreateWatchlist 2 failed: %v", err)
	}

	// Insert a second vulnerability for the second watchlist
	_, err = env.db.ExecContext(ctx, `
		INSERT INTO vulnerabilities (id, summary, modified)
		VALUES ('CVE-2024-0002', 'Another test vulnerability', NOW())
		ON CONFLICT DO NOTHING`)
	if err != nil {
		t.Fatalf("failed to create second test vulnerability: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	matches := []WatchlistMatch{
		{WatchlistID: wID1, VulnerabilityID: "CVE-2024-0001", MatchedAt: now},
		{WatchlistID: wID2, VulnerabilityID: "CVE-2024-0002", MatchedAt: now.Add(time.Second)},
	}
	if err := env.store.RecordMatches(ctx, matches); err != nil {
		t.Fatalf("RecordMatches failed: %v", err)
	}

	results, err := env.store.ListMatchesByUser(ctx, env.userID, 10, 0)
	if err != nil {
		t.Fatalf("ListMatchesByUser failed: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(results))
	}

	// Should be ordered by matched_at DESC (newest first)
	if results[0].MatchedAt.Before(results[1].MatchedAt) {
		t.Error("matches should be ordered by matched_at DESC")
	}
}

func TestCountMatchesByUser(t *testing.T) {
	env := setupTestStore(t)
	ctx := context.Background()

	w := &Watchlist{UserID: env.userID, Name: "Count test", MatchType: MatchTypeEcosystem, Enabled: true}
	wID, err := env.store.CreateWatchlist(ctx, w)
	if err != nil {
		t.Fatalf("CreateWatchlist failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	matches := []WatchlistMatch{
		{WatchlistID: wID, VulnerabilityID: "CVE-2024-0001", MatchedAt: now},
	}
	if err := env.store.RecordMatches(ctx, matches); err != nil {
		t.Fatalf("RecordMatches failed: %v", err)
	}

	count, err := env.store.CountMatchesByUser(ctx, env.userID)
	if err != nil {
		t.Fatalf("CountMatchesByUser failed: %v", err)
	}
	if count != 1 {
		t.Errorf("expected count 1, got %d", count)
	}
}

func TestGetActiveWatchlists(t *testing.T) {
	env := setupTestStore(t)
	ctx := context.Background()

	// Create enabled and disabled watchlists
	w1 := &Watchlist{UserID: env.userID, Name: "Active", MatchType: MatchTypeEcosystem, Enabled: true}
	w2 := &Watchlist{UserID: env.userID, Name: "Inactive", MatchType: MatchTypeEcosystem, Enabled: false}

	if _, err := env.store.CreateWatchlist(ctx, w1); err != nil {
		t.Fatalf("CreateWatchlist (active) failed: %v", err)
	}
	if _, err := env.store.CreateWatchlist(ctx, w2); err != nil {
		t.Fatalf("CreateWatchlist (inactive) failed: %v", err)
	}

	active, err := env.store.GetActiveWatchlists(ctx)
	if err != nil {
		t.Fatalf("GetActiveWatchlists failed: %v", err)
	}
	if len(active) != 1 {
		t.Fatalf("expected 1 active watchlist, got %d", len(active))
	}
	if active[0].Name != "Active" {
		t.Errorf("expected active watchlist name 'Active', got %q", active[0].Name)
	}
}

func TestWatchlistMatchesCascadeOnDelete(t *testing.T) {
	env := setupTestStore(t)
	ctx := context.Background()

	w := &Watchlist{UserID: env.userID, Name: "Cascade test", MatchType: MatchTypeEcosystem, Enabled: true}
	wID, err := env.store.CreateWatchlist(ctx, w)
	if err != nil {
		t.Fatalf("CreateWatchlist failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	matches := []WatchlistMatch{
		{WatchlistID: wID, VulnerabilityID: "CVE-2024-0001", MatchedAt: now},
	}
	if err := env.store.RecordMatches(ctx, matches); err != nil {
		t.Fatalf("RecordMatches failed: %v", err)
	}

	// Delete the watchlist
	if err := env.store.DeleteWatchlist(ctx, wID, env.userID); err != nil {
		t.Fatalf("DeleteWatchlist failed: %v", err)
	}

	// Matches should be cascade-deleted
	var count int
	err = env.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM watchlist_matches WHERE watchlist_id = $1`, wID).Scan(&count)
	if err != nil {
		t.Fatalf("count matches failed: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 matches after cascade delete, got %d", count)
	}
}

