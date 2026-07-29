package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/kato83/mayu/internal/model"
)

// GetEPSSTrending returns CVEs with rapidly rising EPSS scores (spike detection).
// It compares the latest EPSS score vs the score N days ago, filtering for
// delta >= threshold, ordered by delta descending.
//
// Instead of scanning the entire table with DISTINCT ON, this uses a two-step
// approach: first identify the latest and previous score dates via index lookups,
// then join only those specific date slices. This avoids full-table scans on the
// 100M+ row epss_scores table.
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

	rows, err := s.db.QueryContext(ctx, `
		WITH latest_date AS (
			SELECT MAX(score_date) AS d FROM epss_scores
		),
		previous_date AS (
			SELECT MAX(score_date) AS d FROM epss_scores
			WHERE score_date <= (SELECT d FROM latest_date) - ($1::int)
		)
		SELECT
			cur.vulnerability_id,
			cur.vulnerability_id AS cve_id,
			cur.epss AS current_epss,
			prev.epss AS previous_epss,
			cur.epss - prev.epss AS delta,
			cur.percentile AS current_percentile,
			COALESCE(vs.severity_worst, 0) AS severity_worst,
			COALESCE(v.summary, '') AS summary
		FROM epss_scores cur
		JOIN epss_scores prev ON prev.vulnerability_id = cur.vulnerability_id
			AND prev.score_date = (SELECT d FROM previous_date)
		LEFT JOIN vulnerabilities v ON v.id = cur.vulnerability_id
		LEFT JOIN vulnerability_summary vs ON vs.vulnerability_id = cur.vulnerability_id
		WHERE cur.score_date = (SELECT d FROM latest_date)
			AND cur.epss - prev.epss >= $2
		ORDER BY cur.epss - prev.epss DESC
		LIMIT $3`,
		params.Days, params.Threshold, params.Limit,
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
