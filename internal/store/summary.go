package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kato83/mayu/internal/cvss"
	"github.com/kato83/mayu/internal/model"
)

// RefreshSummary recomputes vulnerability_summary rows for the given vulnerability IDs.
// It aggregates scores from all sources (OSV severity, NVD metrics, MITRE metrics),
// EPSS, KEV, LEV, ecosystems, and CWEs into the pre-computed summary table.
//
// This method is called synchronously at the end of each import pipeline.
// It performs the following for each vulnerability:
//  1. Collect all scores from osv_severity, nvd_metrics, mitre_metrics
//  2. Normalize each score to the 5-level severity scale
//  3. Compute severity_worst and severity_best
//  4. Fetch latest EPSS score and percentile
//  5. Check KEV membership
//  6. Compute LEV score
//  7. Aggregate ecosystems from product_identifiers
//  8. Aggregate CWEs from nvd_weaknesses and mitre_problem_types
//  9. UPSERT into vulnerability_summary
func (s *PostgresStore) RefreshSummary(ctx context.Context, vulnIDs []string) error {
	if len(vulnIDs) == 0 {
		return nil
	}

	// Process in batches to avoid overly large queries
	const batchSize = 500
	for i := 0; i < len(vulnIDs); i += batchSize {
		end := i + batchSize
		if end > len(vulnIDs) {
			end = len(vulnIDs)
		}
		if err := s.refreshSummaryBatch(ctx, vulnIDs[i:end]); err != nil {
			return err
		}
	}
	return nil
}

func (s *PostgresStore) refreshSummaryBatch(ctx context.Context, vulnIDs []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, vulnID := range vulnIDs {
		if err := s.refreshSingleSummary(ctx, tx, vulnID); err != nil {
			return fmt.Errorf("refresh summary for %s: %w", vulnID, err)
		}
	}

	return tx.Commit()
}

func (s *PostgresStore) refreshSingleSummary(ctx context.Context, tx *sql.Tx, vulnID string) error {
	// --- Step 1: Collect all scores ---
	scores, err := s.collectScores(ctx, tx, vulnID)
	if err != nil {
		return err
	}

	// --- Step 2: Compute severity levels ---
	severityWorst, severityBest := model.ComputeSummaryFromScores(scores)

	// --- Step 3: Marshal scores_detail ---
	var scoresDetailJSON []byte
	if len(scores) > 0 {
		scoresDetailJSON, err = json.Marshal(scores)
		if err != nil {
			return fmt.Errorf("marshal scores_detail: %w", err)
		}
	}

	// --- Step 4: Fetch latest EPSS ---
	var epssScore, epssPercentile *float64
	err = tx.QueryRowContext(ctx, `
		SELECT epss, percentile FROM epss_scores
		WHERE vulnerability_id = $1
		ORDER BY score_date DESC LIMIT 1`, vulnID).Scan(&epssScore, &epssPercentile)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("fetch EPSS: %w", err)
	}

	// --- Step 5: Check KEV ---
	var inKEV bool
	err = tx.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM kev_entries WHERE vulnerability_id = $1)`,
		vulnID).Scan(&inKEV)
	if err != nil {
		return fmt.Errorf("check KEV: %w", err)
	}

	// --- Step 6: Compute LEV (simplified - use existing function if EPSS data available) ---
	var levScore *float64
	if inKEV {
		one := 1.0
		levScore = &one
	}
	// Note: Full LEV computation requires fetching all historical EPSS scores.
	// For summary refresh, we compute a simplified version using only KEV status.
	// The full LEV is computed on-demand in GetVulnerabilityDetail.

	// --- Step 7: Aggregate ecosystems from product_identifiers ---
	ecosystemList, err := s.aggregateEcosystems(ctx, tx, vulnID)
	if err != nil {
		return err
	}

	// --- Step 8: Aggregate CWEs ---
	cweList, err := s.aggregateCWEs(ctx, tx, vulnID)
	if err != nil {
		return err
	}

	// --- Step 9: UPSERT into vulnerability_summary ---
	_, err = tx.ExecContext(ctx, `
		INSERT INTO vulnerability_summary (
			vulnerability_id, severity_worst, severity_best,
			scores_detail, epss_score, epss_percentile,
			in_kev, lev_score, ecosystem_list, cwe_list, computed_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
		ON CONFLICT (vulnerability_id) DO UPDATE SET
			severity_worst = EXCLUDED.severity_worst,
			severity_best = EXCLUDED.severity_best,
			scores_detail = EXCLUDED.scores_detail,
			epss_score = EXCLUDED.epss_score,
			epss_percentile = EXCLUDED.epss_percentile,
			in_kev = EXCLUDED.in_kev,
			lev_score = EXCLUDED.lev_score,
			ecosystem_list = EXCLUDED.ecosystem_list,
			cwe_list = EXCLUDED.cwe_list,
			computed_at = EXCLUDED.computed_at`,
		vulnID,
		nullableInt(severityWorst),
		nullableInt(severityBest),
		nullableBytes(scoresDetailJSON),
		epssScore,
		epssPercentile,
		inKEV,
		levScore,
		pgTextArray(ecosystemList),
		pgTextArray(cweList),
	)
	if err != nil {
		return fmt.Errorf("upsert vulnerability_summary: %w", err)
	}

	return nil
}

// collectScores gathers all severity/score data from OSV, NVD, and MITRE for a vulnerability.
func (s *PostgresStore) collectScores(ctx context.Context, tx *sql.Tx, vulnID string) ([]model.ScoreEntry, error) {
	var scores []model.ScoreEntry

	// --- OSV severity ---
	rows, err := tx.QueryContext(ctx, `
		SELECT os.severity_type, os.score
		FROM osv_severity os
		JOIN osv_entries oe ON oe.osv_id = os.osv_entry_id
		WHERE oe.vulnerability_id = $1
		AND os.severity_type IN ('CVSS_V2', 'CVSS_V3', 'CVSS_V4')`, vulnID)
	if err != nil {
		return nil, fmt.Errorf("query osv_severity: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var sevType, scoreStr string
		if err := rows.Scan(&sevType, &scoreStr); err != nil {
			return nil, fmt.Errorf("scan osv_severity: %w", err)
		}
		// Extract base score from CVSS vector string if present
		baseScore := extractBaseScoreFromVector(scoreStr)
		ver := mapOSVSeverityTypeToVersion(sevType)
		entry := model.ScoreEntry{
			Src:    "osv",
			System: "cvss",
			Ver:    ver,
			Score:  baseScore,
		}
		// Preserve vector string if scoreStr is a CVSS vector (not a plain number)
		if len(scoreStr) > 0 && (scoreStr[0] < '0' || scoreStr[0] > '9') {
			entry.Vector = scoreStr
		}
		if baseScore != nil {
			entry.Sev = model.SeverityLevelName(model.NormalizeSeverity("cvss", baseScore, ""))
			entry.Normalized = model.NormalizeSeverity("cvss", baseScore, "")
		}
		scores = append(scores, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// --- NVD metrics ---
	nvdRows, err := tx.QueryContext(ctx, `
		SELECT nm.version, nm.source, nm.type, nm.base_score, nm.base_severity,
		       nm.cvss_data->>'vectorString'
		FROM nvd_metrics nm
		JOIN nvd_entries ne ON ne.id = nm.nvd_entry_id
		WHERE ne.vulnerability_id = $1`, vulnID)
	if err != nil {
		return nil, fmt.Errorf("query nvd_metrics: %w", err)
	}
	defer func() { _ = nvdRows.Close() }()

	for nvdRows.Next() {
		var ver, source, metricType string
		var baseScore sql.NullFloat64
		var baseSeverity, vectorString sql.NullString
		if err := nvdRows.Scan(&ver, &source, &metricType, &baseScore, &baseSeverity, &vectorString); err != nil {
			return nil, fmt.Errorf("scan nvd_metrics: %w", err)
		}
		entry := model.ScoreEntry{
			Src:    "nvd",
			System: "cvss",
			Ver:    ver,
			Vector: vectorString.String,
		}
		if baseScore.Valid {
			s := baseScore.Float64
			entry.Score = &s
			entry.Sev = baseSeverity.String
			entry.Normalized = model.NormalizeSeverity("cvss", &s, baseSeverity.String)
		} else {
			entry.Sev = baseSeverity.String
			entry.Normalized = model.NormalizeSeverity("", nil, baseSeverity.String)
		}
		scores = append(scores, entry)
	}
	if err := nvdRows.Err(); err != nil {
		return nil, err
	}

	// --- MITRE metrics ---
	mitreRows, err := tx.QueryContext(ctx, `
		SELECT mm.format, mm.cvss_version, mm.base_score, mm.base_severity,
		       mm.vector_string, mc.container_type, mc.provider_short_name
		FROM mitre_metrics mm
		JOIN mitre_containers mc ON mc.id = mm.container_id
		JOIN mitre_entries me ON me.id = mc.mitre_entry_id
		WHERE me.vulnerability_id = $1`, vulnID)
	if err != nil {
		return nil, fmt.Errorf("query mitre_metrics: %w", err)
	}
	defer func() { _ = mitreRows.Close() }()

	for mitreRows.Next() {
		var format string
		var cvssVersion sql.NullString
		var baseScore sql.NullFloat64
		var baseSeverity sql.NullString
		var vectorString sql.NullString
		var containerType, providerShortName sql.NullString
		if err := mitreRows.Scan(&format, &cvssVersion, &baseScore, &baseSeverity, &vectorString, &containerType, &providerShortName); err != nil {
			return nil, fmt.Errorf("scan mitre_metrics: %w", err)
		}

		// Determine source label
		src := "mitre_cna"
		if containerType.String == "adp" {
			src = "mitre_adp"
		}

		// Handle SSVC
		system := "cvss"
		if strings.EqualFold(format, "Other") || strings.EqualFold(format, "SSVC") {
			system = "ssvc"
		}

		entry := model.ScoreEntry{
			Src:    src,
			System: system,
			Ver:    cvssVersion.String,
			Vector: vectorString.String,
		}
		if baseScore.Valid {
			s := baseScore.Float64
			entry.Score = &s
			entry.Sev = baseSeverity.String
			entry.Normalized = model.NormalizeSeverity(system, &s, baseSeverity.String)
		} else {
			entry.Sev = baseSeverity.String
			entry.Normalized = model.NormalizeSeverity(system, nil, baseSeverity.String)
		}
		scores = append(scores, entry)
	}
	if err := mitreRows.Err(); err != nil {
		return nil, err
	}

	return scores, nil
}

// aggregateEcosystems collects unique ecosystem values from product_identifiers.
func (s *PostgresStore) aggregateEcosystems(ctx context.Context, tx *sql.Tx, vulnID string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT DISTINCT ecosystem FROM product_identifiers
		WHERE vulnerability_id = $1 AND ecosystem IS NOT NULL AND ecosystem != ''`,
		vulnID)
	if err != nil {
		return nil, fmt.Errorf("query ecosystems: %w", err)
	}
	defer func() { _ = rows.Close() }()

	seen := make(map[string]bool)
	var ecosystems []string
	for rows.Next() {
		var eco string
		if err := rows.Scan(&eco); err != nil {
			return nil, err
		}
		if !seen[eco] {
			seen[eco] = true
			ecosystems = append(ecosystems, eco)
		}
		// Also add the base ecosystem name (before first colon) for prefix search support.
		// e.g., "Ubuntu:22.04:LTS" -> also add "Ubuntu"
		if idx := strings.IndexByte(eco, ':'); idx > 0 {
			base := eco[:idx]
			if !seen[base] {
				seen[base] = true
				ecosystems = append(ecosystems, base)
			}
		}
	}
	return ecosystems, rows.Err()
}

// aggregateCWEs collects unique CWE IDs from NVD, MITRE, and OSV sources.
func (s *PostgresStore) aggregateCWEs(ctx context.Context, tx *sql.Tx, vulnID string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT DISTINCT cwe_id FROM (
			SELECT nw.cwe_id FROM nvd_weaknesses nw
			JOIN nvd_entries ne ON ne.id = nw.nvd_entry_id
			WHERE ne.vulnerability_id = $1 AND nw.cwe_id IS NOT NULL AND nw.cwe_id != ''
			UNION
			SELECT mpt.cwe_id FROM mitre_problem_types mpt
			JOIN mitre_containers mc ON mc.id = mpt.container_id
			JOIN mitre_entries me ON me.id = mc.mitre_entry_id
			WHERE me.vulnerability_id = $1 AND mpt.cwe_id IS NOT NULL AND mpt.cwe_id != ''
			UNION
			SELECT jsonb_array_elements_text(oe.database_specific->'cwe_ids') AS cwe_id
			FROM osv_entries oe
			WHERE oe.vulnerability_id = $1
			AND oe.database_specific ? 'cwe_ids'
			AND jsonb_typeof(oe.database_specific->'cwe_ids') = 'array'
		) combined
		WHERE cwe_id IS NOT NULL AND cwe_id != ''`, vulnID)
	if err != nil {
		return nil, fmt.Errorf("query CWEs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var cwes []string
	for rows.Next() {
		var cwe string
		if err := rows.Scan(&cwe); err != nil {
			return nil, err
		}
		cwes = append(cwes, cwe)
	}
	return cwes, rows.Err()
}

// --- Helper functions ---

// mapOSVSeverityTypeToVersion maps OSV severity type to a CVSS version string.
func mapOSVSeverityTypeToVersion(sevType string) string {
	switch sevType {
	case "CVSS_V4":
		return "v40"
	case "CVSS_V3":
		return "v31"
	case "CVSS_V2":
		return "v2"
	default:
		return ""
	}
}

// extractBaseScoreFromVector attempts to parse a base score from a CVSS vector string.
// CVSS vectors contain the score as a separate element in some OSV entries.
// If the score string looks like a plain number (e.g., "7.5"), it's returned directly.
// If it's a CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/..."), the base score is
// computed using the cvss package.
func extractBaseScoreFromVector(scoreStr string) *float64 {
	// Try to parse as a plain float (some OSV entries store just the score)
	if len(scoreStr) > 0 && scoreStr[0] >= '0' && scoreStr[0] <= '9' {
		var score float64
		_, err := fmt.Sscanf(scoreStr, "%f", &score)
		if err == nil && score >= 0 && score <= 10 {
			return &score
		}
	}
	// Try to compute from CVSS vector string
	if score, ok := cvss.BaseScore(scoreStr); ok {
		return &score
	}
	return nil
}

// nullableInt returns nil for zero values, otherwise returns the int.
func nullableInt(i int) interface{} {
	if i == 0 {
		return nil
	}
	return i
}

// nullableBytes returns nil for empty/nil byte slices.
func nullableBytes(b []byte) interface{} {
	if len(b) == 0 {
		return nil
	}
	return b
}
