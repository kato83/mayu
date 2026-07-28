package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/kato83/mayu/internal/model"
)

// UpsertEPSSBatch stores multiple EPSS score entries using bulk multi-value INSERT.
// It retries automatically on deadlock (same pattern as NVD/MITRE UpsertBatch).
//
// The upsert strategy:
//   - Bulk-ensure corresponding vulnerabilities rows exist (INSERT ... ON CONFLICT DO NOTHING).
//   - Bulk-upsert EPSS scores using (cve_id, score_date) unique constraint.
//
// Both operations use a single SQL statement with multi-value VALUES clause,
// reducing round-trips from 2*N to 2 per batch.
func (s *PostgresStore) UpsertEPSSBatch(ctx context.Context, scores []*model.EPSSScore) error {
	if len(scores) == 0 {
		return nil
	}

	const maxRetries = 5
	for attempt := 0; attempt <= maxRetries; attempt++ {
		err := s.upsertEPSSBatchOnce(ctx, scores)
		if err == nil {
			return nil
		}
		if isDeadlock(err) && attempt < maxRetries {
			backoff := time.Duration(10<<uint(attempt)) * time.Millisecond
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			continue
		}
		return err
	}
	return fmt.Errorf("upsert EPSS batch: exceeded max retries due to deadlock")
}

func (s *PostgresStore) upsertEPSSBatchOnce(ctx context.Context, scores []*model.EPSSScore) error {
	// PostgreSQL parameter limit is 65535. We use 1 param per vuln row (step 1)
	// and 6 params per EPSS score row (step 2). Process in sub-chunks if needed.
	const maxParamsPerChunk = 60000
	const colsPerRow = 6

	maxRowsPerChunk := maxParamsPerChunk / colsPerRow
	for i := 0; i < len(scores); i += maxRowsPerChunk {
		end := i + maxRowsPerChunk
		if end > len(scores) {
			end = len(scores)
		}
		if err := s.upsertEPSSChunk(ctx, scores[i:end]); err != nil {
			return err
		}
	}
	return nil
}

func (s *PostgresStore) upsertEPSSChunk(ctx context.Context, scores []*model.EPSSScore) error {
	if len(scores) == 0 {
		return nil
	}

	// --- Step 1: Bulk ensure vulnerability rows exist ---
	// Build: INSERT INTO vulnerabilities (id, ...) VALUES ($1,...),($2,...),... ON CONFLICT DO NOTHING
	// Deduplicate CVE IDs within this chunk
	seen := make(map[string]struct{}, len(scores))
	uniqueCVEs := make([]string, 0, len(scores))
	for _, s := range scores {
		if _, ok := seen[s.CVEID]; !ok {
			seen[s.CVEID] = struct{}{}
			uniqueCVEs = append(uniqueCVEs, s.CVEID)
		}
	}

	vulnArgs := make([]interface{}, 0, len(uniqueCVEs))
	vulnValues := make([]string, 0, len(uniqueCVEs))
	for i, cveID := range uniqueCVEs {
		vulnValues = append(vulnValues, fmt.Sprintf("($%d, NULL, NULL, NULL, NULL, NULL)", i+1))
		vulnArgs = append(vulnArgs, cveID)
	}

	vulnQuery := `INSERT INTO vulnerabilities (id, summary, details, published, modified, withdrawn) VALUES ` +
		strings.Join(vulnValues, ", ") +
		` ON CONFLICT (id) DO NOTHING`

	_, err := s.db.ExecContext(ctx, vulnQuery, vulnArgs...)
	if err != nil {
		return fmt.Errorf("bulk ensure vulnerabilities: %w", err)
	}

	// --- Step 2: Bulk upsert EPSS scores ---
	// Build: INSERT INTO epss_scores (...) VALUES ($1,$2,$3,$4,$5,$6),($7,...),... ON CONFLICT DO UPDATE
	const colsPerRow = 6
	epssArgs := make([]interface{}, 0, len(scores)*colsPerRow)
	epssValues := make([]string, 0, len(scores))
	for i, score := range scores {
		base := i*colsPerRow + 1
		epssValues = append(epssValues, fmt.Sprintf(
			"($%d, $%d, $%d, $%d, $%d, $%d)",
			base, base+1, base+2, base+3, base+4, base+5,
		))
		epssArgs = append(epssArgs,
			score.CVEID,                  // cve_id
			score.CVEID,                  // vulnerability_id (same as cve_id)
			score.EPSS,                   // epss
			score.Percentile,             // percentile
			score.ScoreDate,              // score_date
			sanitizeJSONB(score.RawJSON), // raw_json
		)
	}

	epssQuery := `INSERT INTO epss_scores (cve_id, vulnerability_id, epss, percentile, score_date, raw_json) VALUES ` +
		strings.Join(epssValues, ", ") +
		` ON CONFLICT (cve_id, score_date) DO UPDATE SET
			epss = EXCLUDED.epss,
			percentile = EXCLUDED.percentile,
			raw_json = EXCLUDED.raw_json`

	_, err = s.db.ExecContext(ctx, epssQuery, epssArgs...)
	if err != nil {
		return fmt.Errorf("bulk upsert epss_scores: %w", err)
	}

	return nil
}

// RefreshEPSSSummary performs a lightweight update of vulnerability_summary
// for EPSS-related fields only (epss_score, epss_percentile).
// Unlike the full RefreshSummary which recomputes severity, CWEs, ecosystems etc.,
// this only updates the two EPSS columns using a single bulk query.
// This is safe because EPSS import does not change any other summary fields.
//
// Retries automatically on deadlock (SQLSTATE 40P01) which can occur during
// concurrent batch processing.
func (s *PostgresStore) RefreshEPSSSummary(ctx context.Context, vulnIDs []string) error {
	if len(vulnIDs) == 0 {
		return nil
	}

	// Process in batches to avoid exceeding parameter limits
	const batchSize = 5000
	for i := 0; i < len(vulnIDs); i += batchSize {
		end := i + batchSize
		if end > len(vulnIDs) {
			end = len(vulnIDs)
		}
		if err := s.refreshEPSSSummaryBatchWithRetry(ctx, vulnIDs[i:end]); err != nil {
			return err
		}
	}
	return nil
}

func (s *PostgresStore) refreshEPSSSummaryBatchWithRetry(ctx context.Context, vulnIDs []string) error {
	const maxRetries = 5
	for attempt := 0; attempt <= maxRetries; attempt++ {
		err := s.refreshEPSSSummaryBatch(ctx, vulnIDs)
		if err == nil {
			return nil
		}
		if isDeadlock(err) && attempt < maxRetries {
			backoff := time.Duration(10<<uint(attempt)) * time.Millisecond
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			continue
		}
		return err
	}
	return fmt.Errorf("refresh EPSS summary: exceeded max retries due to deadlock")
}

func (s *PostgresStore) refreshEPSSSummaryBatch(ctx context.Context, vulnIDs []string) error {
	// Build parameter placeholders for the IN clause
	placeholders := make([]string, len(vulnIDs))
	args := make([]interface{}, len(vulnIDs))
	for i, id := range vulnIDs {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}

	// Single query: update epss_score and epss_percentile in vulnerability_summary
	// using a lateral join to get the latest EPSS score per vulnerability.
	// Uses INSERT ... ON CONFLICT to handle both existing and new summary rows.
	query := `
		INSERT INTO vulnerability_summary (vulnerability_id, epss_score, epss_percentile, computed_at)
		SELECT e.vulnerability_id, e.epss, e.percentile, NOW()
		FROM (
			SELECT DISTINCT ON (vulnerability_id)
				vulnerability_id, epss, percentile
			FROM epss_scores
			WHERE vulnerability_id IN (` + strings.Join(placeholders, ", ") + `)
			ORDER BY vulnerability_id, score_date DESC
		) e
		ON CONFLICT (vulnerability_id) DO UPDATE SET
			epss_score = EXCLUDED.epss_score,
			epss_percentile = EXCLUDED.epss_percentile,
			computed_at = EXCLUDED.computed_at`

	_, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("refresh EPSS summary: %w", err)
	}
	return nil
}

// GetEPSSByVulnerabilityID retrieves the latest EPSS score for a vulnerability.
// Returns nil, nil if no EPSS score exists for the given vulnerability.
func (s *PostgresStore) GetEPSSByVulnerabilityID(ctx context.Context, vulnID string) (*model.EPSSScore, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT cve_id, epss, percentile, score_date, raw_json
		FROM epss_scores
		WHERE vulnerability_id = $1
		ORDER BY score_date DESC
		LIMIT 1`,
		vulnID,
	)

	var score model.EPSSScore
	var rawJSON []byte
	if err := row.Scan(&score.CVEID, &score.EPSS, &score.Percentile, &score.ScoreDate, &rawJSON); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("query EPSS score: %w", err)
	}
	score.RawJSON = rawJSON
	return &score, nil
}

// GetEPSSByCVEID retrieves the latest EPSS score for a specific CVE ID.
// Returns nil, nil if no EPSS score exists.
func (s *PostgresStore) GetEPSSByCVEID(ctx context.Context, cveID string) (*model.EPSSScore, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT cve_id, epss, percentile, score_date, raw_json
		FROM epss_scores
		WHERE cve_id = $1
		ORDER BY score_date DESC
		LIMIT 1`,
		cveID,
	)

	var score model.EPSSScore
	var rawJSON []byte
	if err := row.Scan(&score.CVEID, &score.EPSS, &score.Percentile, &score.ScoreDate, &rawJSON); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("query EPSS score by CVE: %w", err)
	}
	score.RawJSON = rawJSON
	return &score, nil
}

// CountEPSSScores returns the total number of EPSS score entries in the database.
func (s *PostgresStore) CountEPSSScores(ctx context.Context) (int64, error) {
	var count int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM epss_scores`).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count EPSS scores: %w", err)
	}
	return count, nil
}

// GetEPSSCoverage returns summary statistics about EPSS data coverage.
// It queries the lightweight epss_daily_stats table (at most ~900 rows)
// instead of scanning the massive epss_scores table (millions of rows).
func (s *PostgresStore) GetEPSSCoverage(ctx context.Context) (*EPSSCoverage, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT
			COUNT(*) AS total_days,
			COALESCE(MIN(score_date)::text, '') AS first_date,
			COALESCE(MAX(score_date)::text, '') AS last_date,
			COALESCE(SUM(score_count), 0) AS total_scores
		FROM epss_daily_stats`)

	var cov EPSSCoverage
	if err := row.Scan(&cov.TotalDays, &cov.FirstDate, &cov.LastDate, &cov.TotalScores); err != nil {
		return nil, fmt.Errorf("query EPSS coverage: %w", err)
	}

	// Compute missing dates by generating the full date series and finding gaps
	// against epss_daily_stats (which has at most ~900 rows, making NOT EXISTS fast).
	if cov.FirstDate != "" && cov.LastDate != "" {
		rows, err := s.db.QueryContext(ctx, `
			SELECT d::date::text
			FROM generate_series($1::date, $2::date, '1 day'::interval) AS d
			WHERE NOT EXISTS (
				SELECT 1 FROM epss_daily_stats WHERE score_date = d::date
			)
			ORDER BY d`,
			cov.FirstDate, cov.LastDate,
		)
		if err != nil {
			return nil, fmt.Errorf("query EPSS missing dates: %w", err)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var date string
			if err := rows.Scan(&date); err != nil {
				return nil, fmt.Errorf("scan EPSS missing date: %w", err)
			}
			if len(date) >= 10 {
				cov.MissingDates = append(cov.MissingDates, date[:10])
			}
		}
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("iterate EPSS missing dates: %w", err)
		}
	}

	return &cov, nil
}

// RefreshEPSSDailyStats updates the epss_daily_stats summary table for the
// given dates. It queries epss_scores for actual counts and upserts them into
// the summary table. This keeps the lightweight stats table in sync after each
// batch import without requiring a full table scan.
func (s *PostgresStore) RefreshEPSSDailyStats(ctx context.Context, dates []string) error {
	if len(dates) == 0 {
		return nil
	}

	// Deduplicate dates
	seen := make(map[string]struct{}, len(dates))
	unique := make([]string, 0, len(dates))
	for _, d := range dates {
		if _, ok := seen[d]; !ok {
			seen[d] = struct{}{}
			unique = append(unique, d)
		}
	}

	// Build placeholders for the ANY($1) array parameter
	args := make([]interface{}, len(unique))
	for i, d := range unique {
		args[i] = d
	}

	// Use a single query: compute counts from epss_scores and upsert into epss_daily_stats
	placeholders := make([]string, len(unique))
	for i := range unique {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
	}

	query := `
		INSERT INTO epss_daily_stats (score_date, score_count, updated_at)
		SELECT score_date, COUNT(*), NOW()
		FROM epss_scores
		WHERE score_date IN (` + strings.Join(placeholders, ", ") + `)
		GROUP BY score_date
		ON CONFLICT (score_date) DO UPDATE SET
			score_count = EXCLUDED.score_count,
			updated_at = NOW()`

	_, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("refresh EPSS daily stats: %w", err)
	}
	return nil
}

// GetEPSSImportedDates returns a set of dates (YYYY-MM-DD) for which EPSS scores
// already exist in the database. This is used by the backfill process to skip
// dates that have already been imported, avoiding redundant downloads.
func (s *PostgresStore) GetEPSSImportedDates(ctx context.Context) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT score_date::text FROM epss_scores`)
	if err != nil {
		return nil, fmt.Errorf("query distinct EPSS dates: %w", err)
	}
	defer func() { _ = rows.Close() }()

	dates := make(map[string]bool)
	for rows.Next() {
		var date string
		if err := rows.Scan(&date); err != nil {
			return nil, fmt.Errorf("scan EPSS date: %w", err)
		}
		// Normalize to YYYY-MM-DD (PostgreSQL may return "2024-01-15" directly)
		if len(date) >= 10 {
			dates[date[:10]] = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate EPSS dates: %w", err)
	}

	return dates, nil
}

// CleanupOldEPSSScores deletes EPSS scores older than the specified number of days.
// The retention period is counted from yesterday (since today's data may not exist yet).
// For example, retentionDays=365 retains data from yesterday back 365 days.
// Also removes corresponding epss_daily_stats entries. Returns the number of deleted scores.
func (s *PostgresStore) CleanupOldEPSSScores(ctx context.Context, retentionDays int) (int64, error) {
	if retentionDays <= 0 {
		// Negative means retain all, skip cleanup
		return 0, nil
	}

	// Cutoff: keep retentionDays days counting from yesterday.
	// yesterday - (retentionDays - 1) = today - retentionDays
	cutoffDate := time.Now().UTC().AddDate(0, 0, -retentionDays).Format("2006-01-02")

	// Delete old scores
	result, err := s.db.ExecContext(ctx,
		`DELETE FROM epss_scores WHERE score_date < $1`, cutoffDate)
	if err != nil {
		return 0, fmt.Errorf("cleanup old EPSS scores: %w", err)
	}

	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("get rows affected: %w", err)
	}

	// Also clean up epss_daily_stats for removed dates
	_, err = s.db.ExecContext(ctx,
		`DELETE FROM epss_daily_stats WHERE score_date < $1`, cutoffDate)
	if err != nil {
		return deleted, fmt.Errorf("cleanup old EPSS daily stats: %w", err)
	}

	return deleted, nil
}

// GetEmptyVulnerabilityIDs returns CVE IDs from the given list that have NULL published
// and NULL summary in the vulnerabilities table (i.e., placeholder records created by
// EPSS ingest that lack real vulnerability data).
func (s *PostgresStore) GetEmptyVulnerabilityIDs(ctx context.Context, cveIDs []string) ([]string, error) {
	if len(cveIDs) == 0 {
		return nil, nil
	}

	// Build parameterized query
	placeholders := make([]string, len(cveIDs))
	args := make([]interface{}, len(cveIDs))
	for i, id := range cveIDs {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}

	query := fmt.Sprintf(`
		SELECT id FROM vulnerabilities
		WHERE id IN (%s)
			AND published IS NULL
			AND summary IS NULL`,
		strings.Join(placeholders, ", "))

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get empty vulnerability IDs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var result []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan empty vulnerability ID: %w", err)
		}
		result = append(result, id)
	}
	return result, rows.Err()
}

// UpdateVulnerabilityFromCvelistV5 updates a vulnerability record with data
// fetched from the cvelistV5 repository (summary, published, modified).
func (s *PostgresStore) UpdateVulnerabilityFromCvelistV5(ctx context.Context, id, summary string, published, modified *time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE vulnerabilities
		SET summary = COALESCE(NULLIF($2, ''), summary),
			published = LEAST($3, published),
			modified = GREATEST($4, modified)
		WHERE id = $1`,
		id, nullIfEmpty(summary), published, modified,
	)
	if err != nil {
		return fmt.Errorf("update vulnerability from cvelistV5: %w", err)
	}
	return nil
}
