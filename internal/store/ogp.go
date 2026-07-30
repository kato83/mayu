package store

import (
	"context"
	"database/sql"
)

// GetVulnOGPMeta retrieves minimal vulnerability metadata for OGP rendering.
// Tries direct ID lookup first, then alias lookup.
func (s *PostgresStore) GetVulnOGPMeta(ctx context.Context, id string) (*VulnOGPMeta, error) {
	var summary sql.NullString
	var severityWorst sql.NullInt16
	var vulnID string

	// Try direct lookup by vulnerability ID
	row := s.db.QueryRowContext(ctx, `
		SELECT v.id, v.summary, vs.severity_worst
		FROM vulnerabilities v
		LEFT JOIN vulnerability_summary vs ON vs.vulnerability_id = v.id
		WHERE v.id = $1`, id)

	if err := row.Scan(&vulnID, &summary, &severityWorst); err != nil {
		if err != sql.ErrNoRows {
			return nil, err
		}

		// Try alias lookup
		row = s.db.QueryRowContext(ctx, `
			SELECT v.id, v.summary, vs.severity_worst
			FROM vulnerabilities v
			JOIN vulnerability_aliases va ON va.vulnerability_id = v.id
			LEFT JOIN vulnerability_summary vs ON vs.vulnerability_id = v.id
			WHERE va.alias = $1
			LIMIT 1`, id)
		if err := row.Scan(&vulnID, &summary, &severityWorst); err != nil {
			if err == sql.ErrNoRows {
				return nil, nil
			}
			return nil, err
		}
	}

	result := &VulnOGPMeta{ID: vulnID}
	if summary.Valid {
		result.Summary = summary.String
	}
	if severityWorst.Valid {
		result.SeverityWorst = int(severityWorst.Int16)
	}
	return result, nil
}
