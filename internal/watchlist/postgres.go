package watchlist

import (
	"context"
	"database/sql"
	"fmt"
)

// Compile-time interface compliance check.
var _ WatchlistStore = (*PostgresWatchlistStore)(nil)

// PostgresWatchlistStore implements WatchlistStore using database/sql with the pgx stdlib driver.
type PostgresWatchlistStore struct {
	db *sql.DB
}

// NewPostgresWatchlistStore creates a new PostgresWatchlistStore with the given database connection.
func NewPostgresWatchlistStore(db *sql.DB) *PostgresWatchlistStore {
	return &PostgresWatchlistStore{db: db}
}

// CreateWatchlist creates a new watchlist entry and returns the generated ID.
func (s *PostgresWatchlistStore) CreateWatchlist(ctx context.Context, w *Watchlist) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO watchlists (user_id, name, match_type, ecosystem, package_name, purl_pattern, cpe_pattern, severity_min, epss_threshold, enabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id`,
		w.UserID,
		w.Name,
		w.MatchType,
		nullableString(w.Ecosystem),
		nullableString(w.PackageName),
		nullableString(w.PurlPattern),
		nullableString(w.CpePattern),
		nullableInt16(w.SeverityMin),
		nullableFloat64(w.EpssThreshold),
		w.Enabled,
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("insert watchlist: %w", err)
	}
	return id, nil
}

// GetWatchlist retrieves a watchlist by ID, scoped to a user.
// Returns nil, nil if not found.
func (s *PostgresWatchlistStore) GetWatchlist(ctx context.Context, id int64, userID int64) (*Watchlist, error) {
	var w Watchlist
	var ecosystem, packageName, purlPattern, cpePattern sql.NullString
	var severityMin sql.NullInt16
	var epssThreshold sql.NullFloat64

	err := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, name, match_type, ecosystem, package_name, purl_pattern, cpe_pattern,
		       severity_min, epss_threshold, enabled, created_at, updated_at
		FROM watchlists
		WHERE id = $1 AND user_id = $2`,
		id, userID,
	).Scan(
		&w.ID, &w.UserID, &w.Name, &w.MatchType,
		&ecosystem, &packageName, &purlPattern, &cpePattern,
		&severityMin, &epssThreshold, &w.Enabled, &w.CreatedAt, &w.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get watchlist %d: %w", id, err)
	}

	assignNullableString(&w.Ecosystem, ecosystem)
	assignNullableString(&w.PackageName, packageName)
	assignNullableString(&w.PurlPattern, purlPattern)
	assignNullableString(&w.CpePattern, cpePattern)
	assignNullableInt16(&w.SeverityMin, severityMin)
	assignNullableFloat64(&w.EpssThreshold, epssThreshold)

	return &w, nil
}

// ListWatchlists returns all watchlists for a user, ordered by creation time.
func (s *PostgresWatchlistStore) ListWatchlists(ctx context.Context, userID int64) ([]*Watchlist, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_id, name, match_type, ecosystem, package_name, purl_pattern, cpe_pattern,
		       severity_min, epss_threshold, enabled, created_at, updated_at
		FROM watchlists
		WHERE user_id = $1
		ORDER BY created_at`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("list watchlists for user %d: %w", userID, err)
	}
	defer func() { _ = rows.Close() }()

	var watchlists []*Watchlist
	for rows.Next() {
		var w Watchlist
		var ecosystem, packageName, purlPattern, cpePattern sql.NullString
		var severityMin sql.NullInt16
		var epssThreshold sql.NullFloat64

		if err := rows.Scan(
			&w.ID, &w.UserID, &w.Name, &w.MatchType,
			&ecosystem, &packageName, &purlPattern, &cpePattern,
			&severityMin, &epssThreshold, &w.Enabled, &w.CreatedAt, &w.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan watchlist: %w", err)
		}

		assignNullableString(&w.Ecosystem, ecosystem)
		assignNullableString(&w.PackageName, packageName)
		assignNullableString(&w.PurlPattern, purlPattern)
		assignNullableString(&w.CpePattern, cpePattern)
		assignNullableInt16(&w.SeverityMin, severityMin)
		assignNullableFloat64(&w.EpssThreshold, epssThreshold)

		watchlists = append(watchlists, &w)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate watchlists: %w", err)
	}
	return watchlists, nil
}

// UpdateWatchlist updates an existing watchlist entry.
func (s *PostgresWatchlistStore) UpdateWatchlist(ctx context.Context, w *Watchlist) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE watchlists
		SET name = $2, match_type = $3, ecosystem = $4, package_name = $5,
		    purl_pattern = $6, cpe_pattern = $7, severity_min = $8,
		    epss_threshold = $9, enabled = $10, updated_at = NOW()
		WHERE id = $1`,
		w.ID,
		w.Name,
		w.MatchType,
		nullableString(w.Ecosystem),
		nullableString(w.PackageName),
		nullableString(w.PurlPattern),
		nullableString(w.CpePattern),
		nullableInt16(w.SeverityMin),
		nullableFloat64(w.EpssThreshold),
		w.Enabled,
	)
	if err != nil {
		return fmt.Errorf("update watchlist %d: %w", w.ID, err)
	}
	return nil
}

// DeleteWatchlist removes a watchlist by ID, scoped to a user.
func (s *PostgresWatchlistStore) DeleteWatchlist(ctx context.Context, id int64, userID int64) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM watchlists
		WHERE id = $1 AND user_id = $2`,
		id, userID,
	)
	if err != nil {
		return fmt.Errorf("delete watchlist %d: %w", id, err)
	}
	return nil
}

// ListMatchesByWatchlist returns matches for a specific watchlist with pagination.
func (s *PostgresWatchlistStore) ListMatchesByWatchlist(ctx context.Context, watchlistID int64, limit int, offset int) ([]*WatchlistMatch, error) {
	if limit <= 0 {
		limit = 20
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, watchlist_id, vulnerability_id, matched_at, notified, notified_at
		FROM watchlist_matches
		WHERE watchlist_id = $1
		ORDER BY matched_at DESC
		LIMIT $2 OFFSET $3`,
		watchlistID, limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("list matches for watchlist %d: %w", watchlistID, err)
	}
	defer func() { _ = rows.Close() }()

	return scanMatches(rows)
}

// ListMatchesByUser returns all matches across a user's watchlists with pagination.
func (s *PostgresWatchlistStore) ListMatchesByUser(ctx context.Context, userID int64, limit int, offset int) ([]*WatchlistMatch, error) {
	if limit <= 0 {
		limit = 20
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT wm.id, wm.watchlist_id, wm.vulnerability_id, wm.matched_at, wm.notified, wm.notified_at
		FROM watchlist_matches wm
		JOIN watchlists w ON w.id = wm.watchlist_id
		WHERE w.user_id = $1
		ORDER BY wm.matched_at DESC
		LIMIT $2 OFFSET $3`,
		userID, limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("list matches for user %d: %w", userID, err)
	}
	defer func() { _ = rows.Close() }()

	return scanMatches(rows)
}

// CountMatchesByUser returns the total number of matches across a user's watchlists.
func (s *PostgresWatchlistStore) CountMatchesByUser(ctx context.Context, userID int64) (int64, error) {
	var count int64
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM watchlist_matches wm
		JOIN watchlists w ON w.id = wm.watchlist_id
		WHERE w.user_id = $1`,
		userID,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count matches for user %d: %w", userID, err)
	}
	return count, nil
}

// RecordMatches records one or more watchlist matches in a batch.
// Conflicts on (watchlist_id, vulnerability_id) are ignored.
func (s *PostgresWatchlistStore) RecordMatches(ctx context.Context, matches []WatchlistMatch) error {
	if len(matches) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO watchlist_matches (watchlist_id, vulnerability_id, matched_at, notified, notified_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (watchlist_id, vulnerability_id) DO NOTHING`)
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	for _, m := range matches {
		var notifiedAt sql.NullTime
		if m.NotifiedAt != nil {
			notifiedAt = sql.NullTime{Time: *m.NotifiedAt, Valid: true}
		}

		_, err := stmt.ExecContext(ctx, m.WatchlistID, m.VulnerabilityID, m.MatchedAt, m.Notified, notifiedAt)
		if err != nil {
			return fmt.Errorf("insert match for watchlist %d, vuln %s: %w", m.WatchlistID, m.VulnerabilityID, err)
		}
	}

	return tx.Commit()
}

// GetActiveWatchlists returns all enabled watchlists across all users.
func (s *PostgresWatchlistStore) GetActiveWatchlists(ctx context.Context) ([]*Watchlist, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_id, name, match_type, ecosystem, package_name, purl_pattern, cpe_pattern,
		       severity_min, epss_threshold, enabled, created_at, updated_at
		FROM watchlists
		WHERE enabled = true
		ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list active watchlists: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var watchlists []*Watchlist
	for rows.Next() {
		var w Watchlist
		var ecosystem, packageName, purlPattern, cpePattern sql.NullString
		var severityMin sql.NullInt16
		var epssThreshold sql.NullFloat64

		if err := rows.Scan(
			&w.ID, &w.UserID, &w.Name, &w.MatchType,
			&ecosystem, &packageName, &purlPattern, &cpePattern,
			&severityMin, &epssThreshold, &w.Enabled, &w.CreatedAt, &w.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan active watchlist: %w", err)
		}

		assignNullableString(&w.Ecosystem, ecosystem)
		assignNullableString(&w.PackageName, packageName)
		assignNullableString(&w.PurlPattern, purlPattern)
		assignNullableString(&w.CpePattern, cpePattern)
		assignNullableInt16(&w.SeverityMin, severityMin)
		assignNullableFloat64(&w.EpssThreshold, epssThreshold)

		watchlists = append(watchlists, &w)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate active watchlists: %w", err)
	}
	return watchlists, nil
}

// --- Helper functions ---

func scanMatches(rows *sql.Rows) ([]*WatchlistMatch, error) {
	var matches []*WatchlistMatch
	for rows.Next() {
		var m WatchlistMatch
		var notifiedAt sql.NullTime

		if err := rows.Scan(&m.ID, &m.WatchlistID, &m.VulnerabilityID, &m.MatchedAt, &m.Notified, &notifiedAt); err != nil {
			return nil, fmt.Errorf("scan watchlist_match: %w", err)
		}
		if notifiedAt.Valid {
			m.NotifiedAt = &notifiedAt.Time
		}
		matches = append(matches, &m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate watchlist_matches: %w", err)
	}
	return matches, nil
}

func nullableString(s *string) sql.NullString {
	if s == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *s, Valid: true}
}

func nullableInt16(v *int16) sql.NullInt16 {
	if v == nil {
		return sql.NullInt16{}
	}
	return sql.NullInt16{Int16: *v, Valid: true}
}

func nullableFloat64(v *float64) sql.NullFloat64 {
	if v == nil {
		return sql.NullFloat64{}
	}
	return sql.NullFloat64{Float64: *v, Valid: true}
}

func assignNullableString(dst **string, src sql.NullString) {
	if src.Valid {
		*dst = &src.String
	}
}

func assignNullableInt16(dst **int16, src sql.NullInt16) {
	if src.Valid {
		*dst = &src.Int16
	}
}

func assignNullableFloat64(dst **float64, src sql.NullFloat64) {
	if src.Valid {
		*dst = &src.Float64
	}
}
