package store

import (
	"context"
	"database/sql"
	"fmt"
	"math"
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

// GetLEVHistory returns the LEV time-series for a vulnerability.
// It queries all EPSS scores for the vulnerability, computes cumulative LEV at
// each date point, and returns an array of data points. If since is non-nil,
// only entries on or after that date are included in the response (but all
// historical scores are still used for cumulative computation).
func (s *PostgresStore) GetLEVHistory(ctx context.Context, vulnID string, since *time.Time) ([]LEVHistoryEntry, error) {
	// Check KEV membership
	inKEV, err := s.isInKEV(ctx, vulnID)
	if err != nil {
		return nil, fmt.Errorf("check KEV membership: %w", err)
	}

	// Fetch all historical EPSS scores (need full history for cumulative LEV)
	epssScores, err := s.fetchAllEPSSScores(ctx, vulnID)
	if err != nil {
		return nil, fmt.Errorf("fetch EPSS history: %w", err)
	}

	if len(epssScores) == 0 {
		return nil, nil
	}

	// Compute cumulative LEV at each date point
	var entries []LEVHistoryEntry
	var logProduct float64

	for _, score := range epssScores {
		p1 := p30ToP1(score.P30)
		if p1 > 0 && p1 < 1.0 {
			logProduct += math.Log(1 - p1)
		}

		levScore := 1 - math.Exp(logProduct)
		if levScore < 0 {
			levScore = 0
		}
		if levScore > 1 {
			levScore = 1
		}

		// If in KEV, override LEV to 1.0
		if inKEV {
			levScore = 1.0
		}

		// Apply the since filter for the response
		if since != nil && score.Date.Before(*since) {
			continue
		}

		entries = append(entries, LEVHistoryEntry{
			Date:      score.Date.Format("2006-01-02"),
			LEVScore:  levScore,
			EPSSScore: score.P30,
			IsKEV:     inKEV,
		})
	}

	return entries, nil
}

// p30ToP1 converts a 30-day exploitation probability (EPSS score) to a
// daily probability using: P1 = 1 - (1 - P30)^(1/30)
func p30ToP1(p30 float64) float64 {
	if p30 <= 0 {
		return 0
	}
	if p30 >= 1 {
		return 1
	}
	return 1 - math.Pow(1-p30, 1.0/30.0)
}
