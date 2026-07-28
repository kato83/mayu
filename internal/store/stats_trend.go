package store

import (
	"context"
	"fmt"
)

// rangeToInterval returns the number of days for the given range string.
// Returns "" for "all" (no date filter).
func rangeToInterval(r string) string {
	switch r {
	case "30d":
		return "30"
	case "90d":
		return "90"
	case "180d":
		return "180"
	case "365d":
		return "365"
	default:
		return "" // "all" - no filter
	}
}

// GetStatsTrend returns time-series vulnerability trend data.
func (s *PostgresStore) GetStatsTrend(ctx context.Context, query StatsTrendQuery) (*StatsTrendResponse, error) {
	if query.ProjectID > 0 {
		return s.getProjectStatsTrend(ctx, query)
	}
	return s.getGlobalStatsTrend(ctx, query)
}

// getGlobalStatsTrend aggregates from vulnerabilities + vulnerability_summary by published date.
func (s *PostgresStore) getGlobalStatsTrend(ctx context.Context, query StatsTrendQuery) (*StatsTrendResponse, error) {
	interval := rangeToInterval(query.Range)

	var whereClause string
	var args []interface{}
	argIdx := 1

	if interval != "" {
		whereClause = fmt.Sprintf("WHERE v.published >= NOW() - INTERVAL '%s days'", interval)
	}

	sqlQuery := fmt.Sprintf(`
		SELECT
			date_trunc('%s', v.published)::DATE::TEXT AS date,
			COUNT(*) AS total,
			COALESCE(SUM(CASE WHEN vs.severity_worst = 5 THEN 1 ELSE 0 END), 0) AS critical,
			COALESCE(SUM(CASE WHEN vs.severity_worst = 4 THEN 1 ELSE 0 END), 0) AS high,
			COALESCE(SUM(CASE WHEN vs.severity_worst = 3 THEN 1 ELSE 0 END), 0) AS medium,
			COALESCE(SUM(CASE WHEN vs.severity_worst = 2 THEN 1 ELSE 0 END), 0) AS low
		FROM vulnerabilities v
		LEFT JOIN vulnerability_summary vs ON vs.vulnerability_id = v.id
		%s
		GROUP BY date_trunc('%s', v.published)
		ORDER BY date_trunc('%s', v.published) ASC`,
		query.GroupBy,
		whereClause,
		query.GroupBy,
		query.GroupBy,
	)
	_ = argIdx
	_ = args

	rows, err := s.db.QueryContext(ctx, sqlQuery)
	if err != nil {
		return nil, fmt.Errorf("query global stats trend: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var dataPoints []StatsTrendDataPoint
	for rows.Next() {
		var dp StatsTrendDataPoint
		if err := rows.Scan(&dp.Date, &dp.Total, &dp.Critical, &dp.High, &dp.Medium, &dp.Low); err != nil {
			return nil, fmt.Errorf("scan global stats trend row: %w", err)
		}
		dataPoints = append(dataPoints, dp)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate global stats trend rows: %w", err)
	}

	if dataPoints == nil {
		dataPoints = []StatsTrendDataPoint{}
	}

	return &StatsTrendResponse{
		Range:      query.Range,
		GroupBy:    query.GroupBy,
		DataPoints: dataPoints,
	}, nil
}

// getProjectStatsTrend aggregates from sbom_scan_results by scanned_at date for a given project.
func (s *PostgresStore) getProjectStatsTrend(ctx context.Context, query StatsTrendQuery) (*StatsTrendResponse, error) {
	interval := rangeToInterval(query.Range)

	whereClause := "WHERE sv.project_id = $1 AND sr.status = 'completed'"
	args := []interface{}{query.ProjectID}

	if interval != "" {
		whereClause += fmt.Sprintf(" AND sr.scanned_at >= NOW() - INTERVAL '%s days'", interval)
	}

	// For project-level trends, we take the last scan per date_trunc bucket
	// and report total_findings, new_findings, resolved_findings.
	sqlQuery := fmt.Sprintf(`
		SELECT
			date_trunc('%s', sr.scanned_at)::DATE::TEXT AS date,
			COALESCE(SUM(sr.total_findings), 0) AS total,
			COALESCE(SUM(sr.new_findings), 0) AS new_findings,
			COALESCE(SUM(sr.resolved_findings), 0) AS resolved_findings
		FROM sbom_scan_results sr
		JOIN sbom_versions sv ON sr.version_id = sv.id
		%s
		GROUP BY date_trunc('%s', sr.scanned_at)
		ORDER BY date_trunc('%s', sr.scanned_at) ASC`,
		query.GroupBy,
		whereClause,
		query.GroupBy,
		query.GroupBy,
	)

	rows, err := s.db.QueryContext(ctx, sqlQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("query project stats trend: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var dataPoints []StatsTrendDataPoint
	for rows.Next() {
		var dp StatsTrendDataPoint
		if err := rows.Scan(&dp.Date, &dp.Total, &dp.New, &dp.Resolved); err != nil {
			return nil, fmt.Errorf("scan project stats trend row: %w", err)
		}
		dataPoints = append(dataPoints, dp)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate project stats trend rows: %w", err)
	}

	if dataPoints == nil {
		dataPoints = []StatsTrendDataPoint{}
	}

	return &StatsTrendResponse{
		Range:      query.Range,
		GroupBy:    query.GroupBy,
		DataPoints: dataPoints,
	}, nil
}
