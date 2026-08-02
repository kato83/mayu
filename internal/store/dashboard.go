package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// severityLevelLabel converts a numeric severity level (1-5) to a human-readable label.
func severityLevelLabel(level int) string {
	switch level {
	case 5:
		return "CRITICAL"
	case 4:
		return "HIGH"
	case 3:
		return "MEDIUM"
	case 2:
		return "LOW"
	case 1:
		return "NONE"
	default:
		return "UNKNOWN"
	}
}

// GetDashboardSummary returns summary counts for the dashboard overview cards.
func (s *PostgresStore) GetDashboardSummary(ctx context.Context) (*DashboardSummary, error) {
	summary := &DashboardSummary{}

	// Total vulnerabilities
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM vulnerabilities`,
	).Scan(&summary.TotalVulnerabilities)
	if err != nil {
		return nil, fmt.Errorf("count total vulnerabilities: %w", err)
	}

	// Last 7 days
	err = s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM vulnerabilities WHERE published >= NOW() - INTERVAL '7 days'`,
	).Scan(&summary.Last7Days)
	if err != nil {
		return nil, fmt.Errorf("count last 7 days: %w", err)
	}

	// Last 30 days
	err = s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM vulnerabilities WHERE published >= NOW() - INTERVAL '30 days'`,
	).Scan(&summary.Last30Days)
	if err != nil {
		return nil, fmt.Errorf("count last 30 days: %w", err)
	}

	// Critical count (severity_worst = 5)
	err = s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM vulnerability_summary WHERE severity_worst = 5`,
	).Scan(&summary.CriticalCount)
	if err != nil {
		return nil, fmt.Errorf("count critical: %w", err)
	}

	// High count (severity_worst = 4)
	err = s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM vulnerability_summary WHERE severity_worst = 4`,
	).Scan(&summary.HighCount)
	if err != nil {
		return nil, fmt.Errorf("count high: %w", err)
	}

	// In KEV count
	err = s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM vulnerability_summary WHERE in_kev = true`,
	).Scan(&summary.InKEVCount)
	if err != nil {
		return nil, fmt.Errorf("count in_kev: %w", err)
	}

	return summary, nil
}

// GetDashboardTrends returns time-series data for dashboard trend charts.
func (s *PostgresStore) GetDashboardTrends(ctx context.Context, days int) (*DashboardTrends, error) {
	query := `
		SELECT d.date::DATE::TEXT, COALESCE(c.cnt, 0) AS count
		FROM generate_series(
			(CURRENT_DATE - $1::INT + 1),
			CURRENT_DATE,
			'1 day'::INTERVAL
		) AS d(date)
		LEFT JOIN (
			SELECT DATE(published) AS pub_date, COUNT(*) AS cnt
			FROM vulnerabilities
			WHERE published >= (CURRENT_DATE - $1::INT + 1)
			GROUP BY DATE(published)
		) c ON d.date = c.pub_date
		ORDER BY d.date ASC`

	rows, err := s.db.QueryContext(ctx, query, days)
	if err != nil {
		return nil, fmt.Errorf("query daily trends: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var points []TrendDataPoint
	for rows.Next() {
		var p TrendDataPoint
		if err := rows.Scan(&p.Date, &p.Count); err != nil {
			return nil, fmt.Errorf("scan trend row: %w", err)
		}
		points = append(points, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate trend rows: %w", err)
	}

	if points == nil {
		points = []TrendDataPoint{}
	}

	return &DashboardTrends{DailyNewVulns: points}, nil
}

// GetDashboardDistributions returns distribution data for dashboard charts.
func (s *PostgresStore) GetDashboardDistributions(ctx context.Context) (*DashboardDistributions, error) {
	dist := &DashboardDistributions{}

	// Severity distribution
	sevRows, err := s.db.QueryContext(ctx,
		`SELECT severity_worst, COUNT(*) AS cnt
		 FROM vulnerability_summary
		 WHERE severity_worst IS NOT NULL
		 GROUP BY severity_worst
		 ORDER BY severity_worst DESC`)
	if err != nil {
		return nil, fmt.Errorf("query severity distribution: %w", err)
	}
	defer func() { _ = sevRows.Close() }()

	for sevRows.Next() {
		var level int
		var count int64
		if err := sevRows.Scan(&level, &count); err != nil {
			return nil, fmt.Errorf("scan severity row: %w", err)
		}
		dist.Severity = append(dist.Severity, DistributionItem{
			Label: severityLevelLabel(level),
			Count: count,
		})
	}
	if err := sevRows.Err(); err != nil {
		return nil, fmt.Errorf("iterate severity rows: %w", err)
	}
	if dist.Severity == nil {
		dist.Severity = []DistributionItem{}
	}

	// Severity distribution (best / optimistic)
	sevBestRows, err := s.db.QueryContext(ctx,
		`SELECT severity_best, COUNT(*) AS cnt
		 FROM vulnerability_summary
		 WHERE severity_best IS NOT NULL
		 GROUP BY severity_best
		 ORDER BY severity_best DESC`)
	if err != nil {
		return nil, fmt.Errorf("query severity_best distribution: %w", err)
	}
	defer func() { _ = sevBestRows.Close() }()

	for sevBestRows.Next() {
		var level int
		var count int64
		if err := sevBestRows.Scan(&level, &count); err != nil {
			return nil, fmt.Errorf("scan severity_best row: %w", err)
		}
		dist.SeverityBest = append(dist.SeverityBest, DistributionItem{
			Label: severityLevelLabel(level),
			Count: count,
		})
	}
	if err := sevBestRows.Err(); err != nil {
		return nil, fmt.Errorf("iterate severity_best rows: %w", err)
	}
	if dist.SeverityBest == nil {
		dist.SeverityBest = []DistributionItem{}
	}

	// Ecosystem distribution (top 15)
	ecoRows, err := s.db.QueryContext(ctx,
		`SELECT eco, COUNT(*) AS cnt
		 FROM vulnerability_summary, UNNEST(ecosystem_list) AS eco
		 GROUP BY eco
		 ORDER BY cnt DESC
		 LIMIT 15`)
	if err != nil {
		return nil, fmt.Errorf("query ecosystem distribution: %w", err)
	}
	defer func() { _ = ecoRows.Close() }()

	for ecoRows.Next() {
		var item DistributionItem
		if err := ecoRows.Scan(&item.Label, &item.Count); err != nil {
			return nil, fmt.Errorf("scan ecosystem row: %w", err)
		}
		dist.Ecosystems = append(dist.Ecosystems, item)
	}
	if err := ecoRows.Err(); err != nil {
		return nil, fmt.Errorf("iterate ecosystem rows: %w", err)
	}
	if dist.Ecosystems == nil {
		dist.Ecosystems = []DistributionItem{}
	}

	// EPSS histogram (10 buckets: 0-0.1, 0.1-0.2, ..., 0.9-1.0)
	dist.EPSSHistogram, err = s.queryScoreHistogram(ctx, "epss_score")
	if err != nil {
		return nil, fmt.Errorf("query EPSS histogram: %w", err)
	}

	// LEV histogram (10 buckets: 0-0.1, 0.1-0.2, ..., 0.9-1.0)
	dist.LEVHistogram, err = s.queryScoreHistogram(ctx, "lev_score")
	if err != nil {
		return nil, fmt.Errorf("query LEV histogram: %w", err)
	}

	return dist, nil
}

// queryScoreHistogram generates a 10-bucket histogram for a float8 column in vulnerability_summary.
func (s *PostgresStore) queryScoreHistogram(ctx context.Context, column string) ([]HistogramBucket, error) {
	// Build the query with 10 fixed buckets using width_bucket
	// width_bucket(score, 0, 1, 10) returns 1..10 for values in [0,1)
	// Values exactly 1.0 go to bucket 11, which we merge into bucket 10
	query := fmt.Sprintf(`
		SELECT
			CASE WHEN bucket > 10 THEN 10 ELSE bucket END AS b,
			COUNT(*) AS cnt
		FROM (
			SELECT width_bucket(%s, 0, 1, 10) AS bucket
			FROM vulnerability_summary
			WHERE %s IS NOT NULL AND %s >= 0
		) sub
		GROUP BY b
		ORDER BY b ASC`, column, column, column)

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	// Initialize all 10 buckets with zero counts
	buckets := make([]HistogramBucket, 10)
	for i := range buckets {
		min := float64(i) * 0.1
		max := float64(i+1) * 0.1
		buckets[i] = HistogramBucket{
			RangeLabel: fmt.Sprintf("%.1f-%.1f", min, max),
			Min:        min,
			Max:        max,
			Count:      0,
		}
	}

	// Fill in actual counts from query results
	for rows.Next() {
		var bucket int
		var count int64
		if err := rows.Scan(&bucket, &count); err != nil {
			return nil, err
		}
		// width_bucket returns 1-based index; convert to 0-based
		idx := bucket - 1
		if idx >= 0 && idx < 10 {
			buckets[idx].Count = count
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return buckets, nil
}

// GetDashboardTopRisks returns top risky CVEs by EPSS and LEV scores.
func (s *PostgresStore) GetDashboardTopRisks(ctx context.Context, limit int) (*DashboardTopRisks, error) {
	result := &DashboardTopRisks{}

	// Top EPSS
	topEPSS, err := s.queryTopRisks(ctx, "epss_score", "epss_score > 0", limit)
	if err != nil {
		return nil, fmt.Errorf("query top EPSS: %w", err)
	}
	result.TopEPSS = topEPSS

	// Top LEV
	topLEV, err := s.queryTopRisks(ctx, "lev_score", "lev_score > 0", limit)
	if err != nil {
		return nil, fmt.Errorf("query top LEV: %w", err)
	}
	result.TopLEV = topLEV

	return result, nil
}

// queryTopRisks fetches the top N vulnerabilities ordered by the specified score column.
func (s *PostgresStore) queryTopRisks(ctx context.Context, scoreColumn, whereClause string, limit int) ([]RiskEntry, error) {
	// Build dynamic query parts safely (columns are hardcoded strings, not user input)
	var cols []string
	cols = append(cols, "vs.vulnerability_id")
	cols = append(cols, fmt.Sprintf("vs.%s", scoreColumn))
	cols = append(cols, "vs.epss_percentile")
	cols = append(cols, "vs.severity_worst")
	cols = append(cols, "COALESCE(v.summary, '')")

	query := fmt.Sprintf(`
		SELECT %s
		FROM vulnerability_summary vs
		JOIN vulnerabilities v ON v.id = vs.vulnerability_id
		WHERE %s
		ORDER BY vs.%s DESC, v.published DESC NULLS LAST
		LIMIT $1`,
		strings.Join(cols, ", "),
		whereClause,
		scoreColumn,
	)

	rows, err := s.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var entries []RiskEntry
	for rows.Next() {
		var entry RiskEntry
		var percentile sql.NullFloat64
		var severityLevel sql.NullInt32
		if err := rows.Scan(
			&entry.VulnerabilityID,
			&entry.Score,
			&percentile,
			&severityLevel,
			&entry.Summary,
		); err != nil {
			return nil, err
		}
		if percentile.Valid {
			entry.Percentile = percentile.Float64
		}
		if severityLevel.Valid {
			entry.Severity = severityLevelLabel(int(severityLevel.Int32))
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if entries == nil {
		entries = []RiskEntry{}
	}

	return entries, nil
}

// GetEOLReport returns products that have reached EOL and products approaching EOL
// within the specified number of days.
func (s *PostgresStore) GetEOLReport(ctx context.Context, days int) ([]EOLReportProduct, []EOLUpcomingProduct, error) {
	// Products that are already EOL
	eolRows, err := s.db.QueryContext(ctx, `
		SELECT p.name, p.label, r.release_name, r.eol_from::TEXT
		FROM eol_releases r
		JOIN eol_products p ON p.name = r.product_name
		WHERE r.is_eol = true AND r.eol_from IS NOT NULL AND r.eol_from <= CURRENT_DATE
		ORDER BY r.eol_from DESC
		LIMIT 100`)
	if err != nil {
		return nil, nil, fmt.Errorf("query EOL products: %w", err)
	}
	defer func() { _ = eolRows.Close() }()

	var eolProducts []EOLReportProduct
	for eolRows.Next() {
		var p EOLReportProduct
		if err := eolRows.Scan(&p.Name, &p.Label, &p.Release, &p.EOLDate); err != nil {
			return nil, nil, fmt.Errorf("scan EOL product: %w", err)
		}
		eolProducts = append(eolProducts, p)
	}
	if err := eolRows.Err(); err != nil {
		return nil, nil, fmt.Errorf("iterate EOL products: %w", err)
	}
	if eolProducts == nil {
		eolProducts = []EOLReportProduct{}
	}

	// Products approaching EOL (within N days from today)
	upcomingRows, err := s.db.QueryContext(ctx, `
		SELECT p.name, p.label, r.release_name, r.eol_from::TEXT,
		       (r.eol_from - CURRENT_DATE)::INT AS days_until_eol
		FROM eol_releases r
		JOIN eol_products p ON p.name = r.product_name
		WHERE r.eol_from IS NOT NULL
		  AND r.eol_from > CURRENT_DATE
		  AND r.eol_from <= CURRENT_DATE + $1::INT
		  AND (r.is_eol IS NULL OR r.is_eol = false)
		ORDER BY r.eol_from ASC
		LIMIT 100`, days)
	if err != nil {
		return nil, nil, fmt.Errorf("query upcoming EOL: %w", err)
	}
	defer func() { _ = upcomingRows.Close() }()

	var upcoming []EOLUpcomingProduct
	for upcomingRows.Next() {
		var p EOLUpcomingProduct
		if err := upcomingRows.Scan(&p.Name, &p.Label, &p.Release, &p.EOLDate, &p.DaysUntilEOL); err != nil {
			return nil, nil, fmt.Errorf("scan upcoming EOL: %w", err)
		}
		upcoming = append(upcoming, p)
	}
	if err := upcomingRows.Err(); err != nil {
		return nil, nil, fmt.Errorf("iterate upcoming EOL: %w", err)
	}
	if upcoming == nil {
		upcoming = []EOLUpcomingProduct{}
	}

	return eolProducts, upcoming, nil
}
