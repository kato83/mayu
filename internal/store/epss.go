package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/kato83/mayu/internal/model"
)

// UpsertEPSSBatch stores multiple EPSS score entries in a single transaction.
// It retries automatically on deadlock (same pattern as NVD/MITRE UpsertBatch).
//
// The upsert strategy:
//   - Ensure a corresponding vulnerabilities row exists (INSERT ... ON CONFLICT DO NOTHING).
//   - For each EPSS score, INSERT or UPDATE on (cve_id, score_date) conflict.
//
// This design supports future scoring systems (e.g., LEV) by keeping the
// vulnerability creation logic generic and separate from scoring-specific storage.
func (s *PostgresStore) UpsertEPSSBatch(ctx context.Context, scores []*model.EPSSScore) error {
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
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, score := range scores {
		if err := s.upsertEPSSScore(ctx, tx, score); err != nil {
			return fmt.Errorf("upsert EPSS %s: %w", score.CVEID, err)
		}
	}

	return tx.Commit()
}

// upsertEPSSScore inserts or updates a single EPSS score within a transaction.
// Strategy:
//  1. Ensure the CVE exists in the vulnerabilities table (source='epss').
//     Uses ON CONFLICT DO NOTHING to avoid overwriting existing vulnerability data
//     contributed by other sources (OSV, NVD, MITRE).
//  2. Upsert into epss_scores using (cve_id, score_date) unique constraint.
//     On conflict, updates the score values and raw_json (newer data wins).
func (s *PostgresStore) upsertEPSSScore(ctx context.Context, tx *sql.Tx, score *model.EPSSScore) error {
	cveID := score.CVEID

	// --- Step 1: Ensure vulnerability row exists ---
	// EPSS only contributes the CVE ID; it doesn't provide summary/details/dates.
	// Use DO NOTHING to preserve data from richer sources (OSV, NVD, MITRE).
	_, err := tx.ExecContext(ctx, `
		INSERT INTO vulnerabilities (id, source, summary, details, published, modified, withdrawn)
		VALUES ($1, 'epss', NULL, NULL, NULL, NULL, NULL)
		ON CONFLICT (id) DO NOTHING`,
		cveID,
	)
	if err != nil {
		return fmt.Errorf("ensure vulnerability exists: %w", err)
	}

	// --- Step 2: Upsert EPSS score ---
	_, err = tx.ExecContext(ctx, `
		INSERT INTO epss_scores (cve_id, vulnerability_id, epss, percentile, score_date, raw_json)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (cve_id, score_date) DO UPDATE SET
			epss = EXCLUDED.epss,
			percentile = EXCLUDED.percentile,
			raw_json = EXCLUDED.raw_json`,
		cveID,
		cveID,
		score.EPSS,
		score.Percentile,
		score.ScoreDate,
		[]byte(score.RawJSON),
	)
	if err != nil {
		return fmt.Errorf("upsert epss_score: %w", err)
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
