package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/kato83/mayu/internal/model"
)

// GetEPSSTrending returns CVEs with rapidly rising EPSS scores (spike detection).
// It compares the latest EPSS score vs the score N days ago, filtering for
// delta >= threshold, ordered by delta descending.
//
// The previous_scores CTE uses a bounded window (sinceDate +/- 3 days) to avoid
// selecting stale scores from months ago for CVEs with sparse history.
// CVEs with no score within the bounded window are excluded (INNER JOIN).
func (s *PostgresStore) GetEPSSTrending(ctx context.Context, params EPSSTrendingQuery) ([]EPSSTrendingEntry, error) {
	// Apply defaults
	if params.Days <= 0 {
		params.Days = 7
	}
	if params.Threshold <= 0 {
		params.Threshold = 0.1
	}
	if params.Limit <= 0 {
		params.Limit = 20
	}

	sinceDate := time.Now().UTC().AddDate(0, 0, -params.Days)
	// Lower bound: 3 extra days of tolerance to handle gaps in ingested data.
	sinceDateLower := sinceDate.AddDate(0, 0, -3)

	rows, err := s.db.QueryContext(ctx, `
		WITH latest_scores AS (
			SELECT DISTINCT ON (vulnerability_id)
				vulnerability_id,
				epss AS current_epss,
				percentile AS current_percentile,
				score_date AS latest_date
			FROM epss_scores
			ORDER BY vulnerability_id, score_date DESC
		),
		previous_scores AS (
			SELECT DISTINCT ON (vulnerability_id)
				vulnerability_id,
				epss AS previous_epss,
				score_date AS previous_date
			FROM epss_scores
			WHERE score_date BETWEEN $1 AND $2
			ORDER BY vulnerability_id, score_date DESC
		)
		SELECT
			ls.vulnerability_id,
			ls.vulnerability_id AS cve_id,
			ls.current_epss,
			ps.previous_epss,
			ls.current_epss - ps.previous_epss AS delta,
			ls.current_percentile,
			COALESCE(vs.severity_worst, 0) AS severity_worst,
			COALESCE(v.summary, '') AS summary
		FROM latest_scores ls
		INNER JOIN previous_scores ps ON ps.vulnerability_id = ls.vulnerability_id
		LEFT JOIN vulnerabilities v ON v.id = ls.vulnerability_id
		LEFT JOIN vulnerability_summary vs ON vs.vulnerability_id = ls.vulnerability_id
		WHERE ls.current_epss - ps.previous_epss >= $3
		ORDER BY delta DESC
		LIMIT $4`,
		sinceDateLower, sinceDate, params.Threshold, params.Limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query epss trending: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var entries []EPSSTrendingEntry
	for rows.Next() {
		var e EPSSTrendingEntry
		var summary sql.NullString
		var severityLevel int
		if err := rows.Scan(&e.VulnerabilityID, &e.CVEID, &e.CurrentEPSS,
			&e.PreviousEPSS, &e.Delta, &e.CurrentPercentile, &severityLevel, &summary); err != nil {
			return nil, fmt.Errorf("scan epss trending: %w", err)
		}
		e.Summary = summary.String
		if severityLevel > 0 {
			e.Severity = model.SeverityLevelName(severityLevel)
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}
