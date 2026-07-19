package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/kato83/mayu/internal/model"
)

// GetLEVByVulnerabilityID computes the LEV (Likely Exploited Vulnerabilities) score
// for a given vulnerability ID by:
//  1. Checking if the CVE is in the CISA KEV catalog (confirmed exploitation → LEV=1.0)
//  2. Querying all historical EPSS scores for the CVE
//  3. Computing LEV using the rigorous probability compounding method
//
// Returns nil if the vulnerability has neither EPSS scores nor KEV membership
// (i.e., LEV cannot be computed).
func (s *PostgresStore) GetLEVByVulnerabilityID(ctx context.Context, vulnID string) (*model.LEVScore, error) {
	// Step 1: Check KEV membership
	inKEV, err := s.isInKEV(ctx, vulnID)
	if err != nil {
		return nil, fmt.Errorf("check KEV membership: %w", err)
	}

	// Step 2: Fetch all historical EPSS scores
	epssScores, err := s.fetchAllEPSSScores(ctx, vulnID)
	if err != nil {
		return nil, fmt.Errorf("fetch EPSS history: %w", err)
	}

	// If no EPSS data and not in KEV, we cannot compute LEV
	if len(epssScores) == 0 && !inKEV {
		return nil, nil
	}

	// Step 3: Compute LEV
	input := model.LEVInput{
		CVEID:      vulnID,
		InKEV:      inKEV,
		EPSSScores: epssScores,
	}

	lev := model.ComputeLEV(input)
	return &lev, nil
}

// isInKEV checks whether a vulnerability ID exists in the CISA KEV catalog.
func (s *PostgresStore) isInKEV(ctx context.Context, vulnID string) (bool, error) {
	var exists bool
	err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM kev_entries WHERE vulnerability_id = $1)`,
		vulnID,
	).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("query kev_entries: %w", err)
	}
	return exists, nil
}

// fetchAllEPSSScores retrieves all historical EPSS scores for a vulnerability,
// ordered by date ascending. Each row represents one day's EPSS P30 score.
//
// The epss_scores table stores one row per (cve_id, score_date), so when
// multiple days of EPSS data have been ingested, we get the full time series
// needed for LEV computation.
func (s *PostgresStore) fetchAllEPSSScores(ctx context.Context, vulnID string) ([]model.EPSSDailyScore, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT epss, score_date
		FROM epss_scores
		WHERE vulnerability_id = $1
		ORDER BY score_date ASC`,
		vulnID,
	)
	if err != nil {
		return nil, fmt.Errorf("query epss_scores: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var scores []model.EPSSDailyScore
	for rows.Next() {
		var epss float64
		var scoreDate time.Time
		if err := rows.Scan(&epss, &scoreDate); err != nil {
			return nil, fmt.Errorf("scan epss_score: %w", err)
		}
		scores = append(scores, model.EPSSDailyScore{
			Date: scoreDate,
			P30:  epss,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate epss_scores: %w", err)
	}

	return scores, nil
}

// GetLEVByCVEID computes the LEV score for a specific CVE ID.
// This is a convenience wrapper that uses the CVE ID directly for lookup.
// Returns nil if no data is available for computation.
func (s *PostgresStore) GetLEVByCVEID(ctx context.Context, cveID string) (*model.LEVScore, error) {
	// Check KEV membership by cve_id
	var inKEV bool
	err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM kev_entries WHERE cve_id = $1)`,
		cveID,
	).Scan(&inKEV)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("check KEV by cve_id: %w", err)
	}

	// Fetch all historical EPSS scores by cve_id
	rows, err := s.db.QueryContext(ctx, `
		SELECT epss, score_date
		FROM epss_scores
		WHERE cve_id = $1
		ORDER BY score_date ASC`,
		cveID,
	)
	if err != nil {
		return nil, fmt.Errorf("query epss_scores by cve_id: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var epssScores []model.EPSSDailyScore
	for rows.Next() {
		var epss float64
		var scoreDate time.Time
		if err := rows.Scan(&epss, &scoreDate); err != nil {
			return nil, fmt.Errorf("scan epss_score: %w", err)
		}
		epssScores = append(epssScores, model.EPSSDailyScore{
			Date: scoreDate,
			P30:  epss,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate epss_scores: %w", err)
	}

	// If no data available, cannot compute LEV
	if len(epssScores) == 0 && !inKEV {
		return nil, nil
	}

	input := model.LEVInput{
		CVEID:      cveID,
		InKEV:      inKEV,
		EPSSScores: epssScores,
	}

	lev := model.ComputeLEV(input)
	return &lev, nil
}
