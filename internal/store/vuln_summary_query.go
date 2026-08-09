package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// GetVulnSummariesByIDs returns pre-computed vulnerability summary data for the given IDs.
// Returns a map keyed by vulnerability ID.
func (s *PostgresStore) GetVulnSummariesByIDs(ctx context.Context, ids []string) (map[string]*VulnSummaryRow, error) {
	if len(ids) == 0 {
		return make(map[string]*VulnSummaryRow), nil
	}

	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}

	query := fmt.Sprintf(`
		SELECT vulnerability_id, severity_worst, severity_best,
		       epss_score, epss_percentile, in_kev, lev_score
		FROM vulnerability_summary
		WHERE vulnerability_id IN (%s)`,
		strings.Join(placeholders, ","))

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get vuln summaries by IDs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	result := make(map[string]*VulnSummaryRow, len(ids))
	for rows.Next() {
		var row VulnSummaryRow
		var severityWorst, severityBest sql.NullInt32
		var epssScore, epssPercentile, levScore sql.NullFloat64
		var inKEV sql.NullBool

		if err := rows.Scan(
			&row.VulnerabilityID,
			&severityWorst,
			&severityBest,
			&epssScore,
			&epssPercentile,
			&inKEV,
			&levScore,
		); err != nil {
			return nil, fmt.Errorf("scan vuln summary: %w", err)
		}

		if severityWorst.Valid {
			row.SeverityWorst = int(severityWorst.Int32)
		}
		if severityBest.Valid {
			row.SeverityBest = int(severityBest.Int32)
		}
		if epssScore.Valid {
			v := epssScore.Float64
			row.EPSSScore = &v
		}
		if epssPercentile.Valid {
			v := epssPercentile.Float64
			row.EPSSPercentile = &v
		}
		if inKEV.Valid {
			row.InKEV = inKEV.Bool
		}
		if levScore.Valid {
			v := levScore.Float64
			row.LEVScore = &v
		}

		result[row.VulnerabilityID] = &row
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate vuln summaries: %w", err)
	}
	return result, nil
}
