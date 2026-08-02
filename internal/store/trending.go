package store

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

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
//
// Uses LEFT JOIN so that CVEs without a previous score (new entries) are still
// included with previous_epss = 0.
func (s *PostgresStore) GetEPSSTrending(ctx context.Context, params EPSSTrendingQuery) (*EPSSTrendingResult, error) {
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
			COALESCE(prev.epss, 0) AS previous_epss,
			cur.epss - COALESCE(prev.epss, 0) AS delta,
			cur.percentile AS current_percentile,
			COALESCE(vs.severity_worst, 0) AS severity_worst,
			COALESCE(v.summary, '') AS summary,
			(SELECT d FROM latest_date) AS latest_date,
			(SELECT d FROM previous_date) AS previous_date
		FROM epss_scores cur
		LEFT JOIN epss_scores prev ON prev.vulnerability_id = cur.vulnerability_id
			AND prev.score_date = (SELECT d FROM previous_date)
		LEFT JOIN vulnerabilities v ON v.id = cur.vulnerability_id
		LEFT JOIN vulnerability_summary vs ON vs.vulnerability_id = cur.vulnerability_id
		WHERE cur.score_date = (SELECT d FROM latest_date)
			AND cur.epss - COALESCE(prev.epss, 0) >= $2
		ORDER BY cur.epss - COALESCE(prev.epss, 0) DESC
		LIMIT $3`,
		params.Days, params.Threshold, params.Limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query epss trending: %w", err)
	}
	defer func() { _ = rows.Close() }()

	result := &EPSSTrendingResult{}
	for rows.Next() {
		var e EPSSTrendingEntry
		var summary sql.NullString
		var severityLevel int
		var latestDate, previousDate sql.NullTime
		if err := rows.Scan(&e.VulnerabilityID, &e.CVEID, &e.CurrentEPSS,
			&e.PreviousEPSS, &e.Delta, &e.CurrentPercentile, &severityLevel, &summary,
			&latestDate, &previousDate); err != nil {
			return nil, fmt.Errorf("scan epss trending: %w", err)
		}
		e.Summary = summary.String
		if severityLevel > 0 {
			e.Severity = model.SeverityLevelName(severityLevel)
		}
		result.Entries = append(result.Entries, e)
		// Set dates from first row (same for all rows)
		if result.LatestDate == "" && latestDate.Valid {
			result.LatestDate = latestDate.Time.Format("2006-01-02")
		}
		if result.PreviousDate == "" && previousDate.Valid {
			result.PreviousDate = previousDate.Time.Format("2006-01-02")
		}
	}

	// If no rows returned, fetch dates separately to still report them
	if result.LatestDate == "" {
		var latestDate, previousDate sql.NullTime
		err := s.db.QueryRowContext(ctx, `
			WITH latest_date AS (
				SELECT MAX(score_date) AS d FROM epss_scores
			),
			previous_date AS (
				SELECT MAX(score_date) AS d FROM epss_scores
				WHERE score_date <= (SELECT d FROM latest_date) - ($1::int)
			)
			SELECT (SELECT d FROM latest_date), (SELECT d FROM previous_date)`,
			params.Days,
		).Scan(&latestDate, &previousDate)
		if err != nil {
			slog.Debug("failed to fetch fallback dates for trending", "error", err)
		} else {
			if latestDate.Valid {
				result.LatestDate = latestDate.Time.Format("2006-01-02")
			}
			if previousDate.Valid {
				result.PreviousDate = previousDate.Time.Format("2006-01-02")
			}
		}
	}

	// Compute expected previous date from latest_date - N days
	if result.LatestDate != "" {
		if lt, err := time.Parse("2006-01-02", result.LatestDate); err == nil {
			result.ExpectedPreviousDate = lt.AddDate(0, 0, -params.Days).Format("2006-01-02")
		}
	}

	return result, rows.Err()
}
