package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/kato83/mayu/internal/model"
)

// GetVulnerabilityDetail retrieves enriched vulnerability information by ID,
// combining OSV, NVD, MITRE, EPSS, KEV, and LEV data sources. The id can be
// a vulnerability_id (e.g., CVE-xxx) or an osv_id (e.g., GHSA-xxx, GO-xxx).
// Returns nil, nil if not found.
func (s *PostgresStore) GetVulnerabilityDetail(ctx context.Context, id string) (*model.VulnerabilityDetail, error) {
	// Step 1: Resolve vulnerability_id from either vulnerabilities.id or osv_entries.osv_id or aliases
	vulnID, err := s.resolveVulnerabilityID(ctx, id)
	if err != nil {
		return nil, err
	}
	if vulnID == "" {
		return nil, nil
	}

	// Step 2: Build base detail from OSV data (existing Search path)
	detail, err := s.buildBaseDetail(ctx, vulnID)
	if err != nil {
		return nil, err
	}

	// Step 3: Enrich with NVD data
	nvdDetail, err := s.fetchNVDDetail(ctx, vulnID)
	if err != nil {
		return nil, fmt.Errorf("fetch NVD detail: %w", err)
	}
	detail.NVD = nvdDetail

	// Step 4: Enrich with MITRE data
	mitreDetail, err := s.fetchMITREDetail(ctx, vulnID)
	if err != nil {
		return nil, fmt.Errorf("fetch MITRE detail: %w", err)
	}
	detail.MITRE = mitreDetail

	// Step 5: Enrich with EPSS data (latest score)
	epssDetail, err := s.fetchEPSSDetail(ctx, vulnID)
	if err != nil {
		return nil, fmt.Errorf("fetch EPSS detail: %w", err)
	}
	detail.EPSS = epssDetail

	// Step 6: Enrich with KEV data
	kevDetail, err := s.fetchKEVDetail(ctx, vulnID)
	if err != nil {
		return nil, fmt.Errorf("fetch KEV detail: %w", err)
	}
	detail.KEV = kevDetail

	// Step 7: Compute LEV score (combines EPSS history + KEV status)
	levScore, err := s.GetLEVByVulnerabilityID(ctx, vulnID)
	if err != nil {
		return nil, fmt.Errorf("compute LEV: %w", err)
	}
	if levScore != nil {
		levDetail := &model.LEVDetail{
			LEV:            levScore.LEV,
			InKEV:          levScore.InKEV,
			EPSSScoreCount: levScore.EPSSScoreCount,
			ComputedAt:     levScore.ComputedAt.Format("2006-01-02T15:04:05Z"),
		}
		if levScore.FirstEPSSDate != nil {
			levDetail.FirstEPSSDate = levScore.FirstEPSSDate.Format("2006-01-02")
		}
		if levScore.LastEPSSDate != nil {
			levDetail.LastEPSSDate = levScore.LastEPSSDate.Format("2006-01-02")
		}
		detail.LEV = levDetail
	}

	// Step 8: Fetch severity levels from vulnerability_summary
	var sevWorst, sevBest sql.NullInt32
	err = s.db.QueryRowContext(ctx,
		`SELECT severity_worst, severity_best FROM vulnerability_summary WHERE vulnerability_id = $1`,
		vulnID).Scan(&sevWorst, &sevBest)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("fetch severity summary: %w", err)
	}
	if sevWorst.Valid && sevWorst.Int32 > 0 {
		detail.SeverityWorst = model.SeverityLevelName(int(sevWorst.Int32))
		if sevBest.Valid && sevBest.Int32 > 0 {
			detail.SeverityBest = model.SeverityLevelName(int(sevBest.Int32))
		} else {
			detail.SeverityBest = detail.SeverityWorst
		}
	}

	return detail, nil
}

// resolveVulnerabilityID resolves an input ID to a vulnerabilities.id value.
// Checks vulnerabilities.id, osv_entries.osv_id, and vulnerability_aliases.alias.
func (s *PostgresStore) resolveVulnerabilityID(ctx context.Context, id string) (string, error) {
	// Try direct match on vulnerabilities.id
	var vulnID string
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM vulnerabilities WHERE id = $1`, id).Scan(&vulnID)
	if err == nil {
		return vulnID, nil
	}
	if err != sql.ErrNoRows {
		return "", fmt.Errorf("resolve vulnerability ID: %w", err)
	}

	// Try osv_entries.osv_id → vulnerability_id
	err = s.db.QueryRowContext(ctx,
		`SELECT vulnerability_id FROM osv_entries WHERE osv_id = $1`, id).Scan(&vulnID)
	if err == nil {
		return vulnID, nil
	}
	if err != sql.ErrNoRows {
		return "", fmt.Errorf("resolve via osv_entries: %w", err)
	}

	// Try vulnerability_aliases.alias → vulnerability_id
	err = s.db.QueryRowContext(ctx,
		`SELECT vulnerability_id FROM vulnerability_aliases WHERE alias = $1 LIMIT 1`, id).Scan(&vulnID)
	if err == nil {
		return vulnID, nil
	}
	if err != sql.ErrNoRows {
		return "", fmt.Errorf("resolve via aliases: %w", err)
	}

	return "", nil
}

// buildBaseDetail constructs the base VulnerabilityDetail from the vulnerabilities
// table and OSV data.
func (s *PostgresStore) buildBaseDetail(ctx context.Context, vulnID string) (*model.VulnerabilityDetail, error) {
	// Get base info from vulnerabilities table
	var summary, details sql.NullString
	var published, modified sql.NullTime
	err := s.db.QueryRowContext(ctx,
		`SELECT summary, details, published, modified FROM vulnerabilities WHERE id = $1`,
		vulnID).Scan(&summary, &details, &published, &modified)
	if err != nil {
		return nil, fmt.Errorf("query vulnerability base: %w", err)
	}

	detail := &model.VulnerabilityDetail{
		ID:      vulnID,
		Summary: summary.String,
		Details: details.String,
	}
	if modified.Valid {
		detail.Modified = modified.Time
	}
	if published.Valid {
		detail.Published = &published.Time
	}

	// Get aliases
	aliases, err := s.fetchAliases(ctx, vulnID)
	if err != nil {
		return nil, err
	}
	detail.Aliases = aliases

	// Try to enrich from OSV raw_json (gets severity, affected, references, credits)
	var rawJSON []byte
	err = s.db.QueryRowContext(ctx,
		`SELECT raw_json FROM osv_entries WHERE vulnerability_id = $1 LIMIT 1`,
		vulnID).Scan(&rawJSON)
	if err == nil && rawJSON != nil {
		vuln, parseErr := model.ParseVulnerability(rawJSON)
		if parseErr == nil {
			detail.Severity = vuln.Severity
			detail.Affected = vuln.Affected
			detail.References = vuln.References
			detail.Credits = vuln.Credits
			detail.Related = vuln.Related
			if vuln.Details != "" {
				detail.Details = vuln.Details
			}
			if vuln.Summary != "" {
				detail.Summary = vuln.Summary
			}
			if vuln.Withdrawn != nil {
				detail.Withdrawn = vuln.Withdrawn
			}
		}
	}

	return detail, nil
}

// fetchAliases retrieves all aliases for a vulnerability.
func (s *PostgresStore) fetchAliases(ctx context.Context, vulnID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT alias FROM vulnerability_aliases WHERE vulnerability_id = $1 ORDER BY alias`,
		vulnID)
	if err != nil {
		return nil, fmt.Errorf("query aliases: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var aliases []string
	for rows.Next() {
		var alias string
		if err := rows.Scan(&alias); err != nil {
			return nil, fmt.Errorf("scan alias: %w", err)
		}
		aliases = append(aliases, alias)
	}
	return aliases, rows.Err()
}

// fetchNVDDetail retrieves NVD enrichment data for a vulnerability.
func (s *PostgresStore) fetchNVDDetail(ctx context.Context, vulnID string) (*model.NVDDetail, error) {
	// Get NVD entry
	var entryID int64
	var vulnStatus, sourceIdentifier sql.NullString
	var nvdPublished, nvdLastModified sql.NullTime
	err := s.db.QueryRowContext(ctx,
		`SELECT id, vuln_status, source_identifier, published, last_modified
		 FROM nvd_entries WHERE vulnerability_id = $1`, vulnID).
		Scan(&entryID, &vulnStatus, &sourceIdentifier, &nvdPublished, &nvdLastModified)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query nvd_entries: %w", err)
	}

	nvd := &model.NVDDetail{
		VulnStatus:       vulnStatus.String,
		SourceIdentifier: sourceIdentifier.String,
	}
	if nvdPublished.Valid {
		t := nvdPublished.Time
		nvd.Published = &t
	}
	if nvdLastModified.Valid {
		t := nvdLastModified.Time
		nvd.LastModified = &t
	}

	// Get English description
	var descValue sql.NullString
	err = s.db.QueryRowContext(ctx,
		`SELECT value FROM nvd_descriptions WHERE nvd_entry_id = $1 AND lang = 'en' LIMIT 1`,
		entryID).Scan(&descValue)
	if err == nil {
		nvd.Description = descValue.String
	}

	// Get metrics
	nvd.Metrics, err = s.fetchNVDMetrics(ctx, entryID)
	if err != nil {
		return nil, err
	}

	// Get weaknesses
	nvd.Weaknesses, err = s.fetchNVDWeaknesses(ctx, entryID)
	if err != nil {
		return nil, err
	}

	// Get references
	nvd.References, err = s.fetchNVDReferences(ctx, entryID)
	if err != nil {
		return nil, err
	}

	return nvd, nil
}

// fetchNVDMetrics retrieves CVSS metrics for an NVD entry.
func (s *PostgresStore) fetchNVDMetrics(ctx context.Context, entryID int64) ([]model.NVDMetricDetail, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT version, source, type, base_score, base_severity,
		        cvss_data->>'vectorString' AS vector_string,
		        exploitability_score, impact_score
		 FROM nvd_metrics WHERE nvd_entry_id = $1
		 ORDER BY base_score DESC`, entryID)
	if err != nil {
		return nil, fmt.Errorf("query nvd_metrics: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var metrics []model.NVDMetricDetail
	for rows.Next() {
		var m model.NVDMetricDetail
		var vector sql.NullString
		var exploitability, impact sql.NullFloat64
		if err := rows.Scan(&m.Version, &m.Source, &m.Type, &m.BaseScore, &m.BaseSeverity,
			&vector, &exploitability, &impact); err != nil {
			return nil, fmt.Errorf("scan nvd_metric: %w", err)
		}
		m.VectorString = vector.String
		if exploitability.Valid {
			m.ExploitabilityScore = &exploitability.Float64
		}
		if impact.Valid {
			m.ImpactScore = &impact.Float64
		}
		metrics = append(metrics, m)
	}
	return metrics, rows.Err()
}

// fetchNVDWeaknesses retrieves CWE classifications for an NVD entry.
func (s *PostgresStore) fetchNVDWeaknesses(ctx context.Context, entryID int64) ([]model.NVDWeaknessDetail, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT source, type, cwe_id FROM nvd_weaknesses WHERE nvd_entry_id = $1`,
		entryID)
	if err != nil {
		return nil, fmt.Errorf("query nvd_weaknesses: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var weaknesses []model.NVDWeaknessDetail
	for rows.Next() {
		var w model.NVDWeaknessDetail
		if err := rows.Scan(&w.Source, &w.Type, &w.CWEID); err != nil {
			return nil, fmt.Errorf("scan nvd_weakness: %w", err)
		}
		weaknesses = append(weaknesses, w)
	}
	return weaknesses, rows.Err()
}

// fetchNVDReferences retrieves references for an NVD entry.
func (s *PostgresStore) fetchNVDReferences(ctx context.Context, entryID int64) ([]model.NVDReferenceDetail, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT url, source, tags FROM nvd_references WHERE nvd_entry_id = $1`,
		entryID)
	if err != nil {
		return nil, fmt.Errorf("query nvd_references: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var refs []model.NVDReferenceDetail
	for rows.Next() {
		var r model.NVDReferenceDetail
		var tags []byte
		if err := rows.Scan(&r.URL, &r.Source, &tags); err != nil {
			return nil, fmt.Errorf("scan nvd_reference: %w", err)
		}
		if tags != nil {
			// Parse PostgreSQL TEXT[] array
			r.Tags = parseTextArray(string(tags))
		}
		refs = append(refs, r)
	}
	return refs, rows.Err()
}

// fetchMITREDetail retrieves MITRE CVE Record enrichment data.
func (s *PostgresStore) fetchMITREDetail(ctx context.Context, vulnID string) (*model.MITREDetail, error) {
	// Get MITRE entry
	var entryID int64
	var state, assignerShortName sql.NullString
	var datePublished, dateUpdated sql.NullTime
	err := s.db.QueryRowContext(ctx,
		`SELECT id, state, assigner_short_name, date_published, date_updated
		 FROM mitre_entries WHERE vulnerability_id = $1`, vulnID).
		Scan(&entryID, &state, &assignerShortName, &datePublished, &dateUpdated)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query mitre_entries: %w", err)
	}

	mitre := &model.MITREDetail{
		State:             state.String,
		AssignerShortName: assignerShortName.String,
	}
	if datePublished.Valid {
		t := datePublished.Time
		mitre.DatePublished = &t
	}
	if dateUpdated.Valid {
		t := dateUpdated.Time
		mitre.DateUpdated = &t
	}

	// Get all container IDs for this entry
	containerIDs, err := s.fetchMITREContainerIDs(ctx, entryID)
	if err != nil {
		return nil, err
	}

	// Get metrics (CVSS + SSVC)
	mitre.Metrics, mitre.SSVC, err = s.fetchMITREMetrics(ctx, containerIDs)
	if err != nil {
		return nil, err
	}

	// Get problem types (CWE)
	mitre.ProblemTypes, err = s.fetchMITREProblemTypes(ctx, containerIDs)
	if err != nil {
		return nil, err
	}

	// Get credits
	mitre.Credits, err = s.fetchMITRECredits(ctx, containerIDs)
	if err != nil {
		return nil, err
	}

	// Get references
	mitre.References, err = s.fetchMITREReferences(ctx, containerIDs)
	if err != nil {
		return nil, err
	}

	return mitre, nil
}

// fetchMITREContainerIDs retrieves all container IDs for a MITRE entry.
func (s *PostgresStore) fetchMITREContainerIDs(ctx context.Context, entryID int64) ([]int64, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id FROM mitre_containers WHERE mitre_entry_id = $1`, entryID)
	if err != nil {
		return nil, fmt.Errorf("query mitre_containers: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan container id: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// fetchMITREMetrics retrieves CVSS and SSVC metrics from MITRE containers.
func (s *PostgresStore) fetchMITREMetrics(ctx context.Context, containerIDs []int64) ([]model.MITREMetricDetail, *model.SSVCDetail, error) {
	if len(containerIDs) == 0 {
		return nil, nil, nil
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT mm.format, mm.cvss_version, mm.base_score, mm.base_severity,
		        mm.vector_string, mm.cvss_data, mc.provider_short_name
		 FROM mitre_metrics mm
		 JOIN mitre_containers mc ON mc.id = mm.container_id
		 WHERE mm.container_id = ANY($1)
		 ORDER BY mm.base_score DESC NULLS LAST`, containerIDs)
	if err != nil {
		return nil, nil, fmt.Errorf("query mitre_metrics: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var metrics []model.MITREMetricDetail
	var ssvc *model.SSVCDetail

	for rows.Next() {
		var format, cvssVersion, severity, vectorString, providerShortName sql.NullString
		var baseScore sql.NullFloat64
		var cvssDataBytes []byte
		if err := rows.Scan(&format, &cvssVersion, &baseScore, &severity,
			&vectorString, &cvssDataBytes, &providerShortName); err != nil {
			return nil, nil, fmt.Errorf("scan mitre_metric: %w", err)
		}

		// Check if this is an SSVC assessment
		if format.String == "Other" && cvssDataBytes != nil {
			ssvcParsed := parseSSVC(cvssDataBytes)
			if ssvcParsed != nil {
				ssvc = ssvcParsed
			}
			continue
		}

		m := model.MITREMetricDetail{
			Format:       format.String,
			CvssVersion:  cvssVersion.String,
			Source:       providerShortName.String,
			BaseScore:    baseScore.Float64,
			BaseSeverity: severity.String,
			VectorString: vectorString.String,
		}
		metrics = append(metrics, m)
	}

	return metrics, ssvc, rows.Err()
}

// parseSSVC parses SSVC data from the mitre_metrics cvss_data JSONB field.
func parseSSVC(data []byte) *model.SSVCDetail {
	var raw struct {
		Type    string `json:"type"`
		Content struct {
			Version   string              `json:"version"`
			Role      string              `json:"role"`
			Timestamp string              `json:"timestamp"`
			Options   []map[string]string `json:"options"`
		} `json:"content"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}
	if raw.Type != "ssvc" {
		return nil
	}

	ssvc := &model.SSVCDetail{
		Version:   raw.Content.Version,
		Role:      raw.Content.Role,
		Timestamp: raw.Content.Timestamp,
	}
	for _, opt := range raw.Content.Options {
		for k, v := range opt {
			ssvc.Options = append(ssvc.Options, model.SSVCOption{Key: k, Value: v})
		}
	}
	return ssvc
}

// fetchMITREProblemTypes retrieves CWE classifications from MITRE containers.
func (s *PostgresStore) fetchMITREProblemTypes(ctx context.Context, containerIDs []int64) ([]model.MITREProblemTypeDetail, error) {
	if len(containerIDs) == 0 {
		return nil, nil
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT cwe_id, description, lang FROM mitre_problem_types
		 WHERE container_id = ANY($1)`, containerIDs)
	if err != nil {
		return nil, fmt.Errorf("query mitre_problem_types: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var pts []model.MITREProblemTypeDetail
	for rows.Next() {
		var pt model.MITREProblemTypeDetail
		var cweID sql.NullString
		if err := rows.Scan(&cweID, &pt.Description, &pt.Lang); err != nil {
			return nil, fmt.Errorf("scan mitre_problem_type: %w", err)
		}
		pt.CWEID = cweID.String
		pts = append(pts, pt)
	}
	return pts, rows.Err()
}

// fetchMITRECredits retrieves credits from MITRE containers.
func (s *PostgresStore) fetchMITRECredits(ctx context.Context, containerIDs []int64) ([]model.MITRECreditDetail, error) {
	if len(containerIDs) == 0 {
		return nil, nil
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT credit_type, value, lang FROM mitre_credits
		 WHERE container_id = ANY($1)`, containerIDs)
	if err != nil {
		return nil, fmt.Errorf("query mitre_credits: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var credits []model.MITRECreditDetail
	for rows.Next() {
		var c model.MITRECreditDetail
		var creditType sql.NullString
		if err := rows.Scan(&creditType, &c.Value, &c.Lang); err != nil {
			return nil, fmt.Errorf("scan mitre_credit: %w", err)
		}
		c.Type = creditType.String
		credits = append(credits, c)
	}
	return credits, rows.Err()
}

// fetchMITREReferences retrieves references from MITRE containers.
func (s *PostgresStore) fetchMITREReferences(ctx context.Context, containerIDs []int64) ([]model.MITREReferenceDetail, error) {
	if len(containerIDs) == 0 {
		return nil, nil
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT url, name, tags FROM mitre_references
		 WHERE container_id = ANY($1)`, containerIDs)
	if err != nil {
		return nil, fmt.Errorf("query mitre_references: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var refs []model.MITREReferenceDetail
	for rows.Next() {
		var r model.MITREReferenceDetail
		var name sql.NullString
		var tags []byte
		if err := rows.Scan(&r.URL, &name, &tags); err != nil {
			return nil, fmt.Errorf("scan mitre_reference: %w", err)
		}
		r.Name = name.String
		if tags != nil {
			r.Tags = parseTextArray(string(tags))
		}
		refs = append(refs, r)
	}
	return refs, rows.Err()
}

// fetchEPSSDetail retrieves the latest EPSS score for a vulnerability.
// Returns nil if no EPSS data exists.
func (s *PostgresStore) fetchEPSSDetail(ctx context.Context, vulnID string) (*model.EPSSDetail, error) {
	var epss, percentile float64
	var scoreDate string
	err := s.db.QueryRowContext(ctx, `
		SELECT epss, percentile, score_date::text
		FROM epss_scores
		WHERE vulnerability_id = $1
		ORDER BY score_date DESC
		LIMIT 1`,
		vulnID,
	).Scan(&epss, &percentile, &scoreDate)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query epss_scores for detail: %w", err)
	}

	return &model.EPSSDetail{
		EPSS:       epss,
		Percentile: percentile,
		ScoreDate:  scoreDate,
	}, nil
}

// fetchKEVDetail retrieves the KEV catalog entry for a vulnerability.
// Returns nil if the vulnerability is not in the KEV catalog.
func (s *PostgresStore) fetchKEVDetail(ctx context.Context, vulnID string) (*model.KEVDetail, error) {
	var vendorProject, product, vulnName, dateAdded, dueDate, requiredAction, ransomware string
	err := s.db.QueryRowContext(ctx, `
		SELECT vendor_project, product, vulnerability_name,
		       date_added::text, due_date::text, required_action,
		       known_ransomware_campaign_use
		FROM kev_entries
		WHERE vulnerability_id = $1`,
		vulnID,
	).Scan(&vendorProject, &product, &vulnName, &dateAdded, &dueDate, &requiredAction, &ransomware)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query kev_entries for detail: %w", err)
	}

	return &model.KEVDetail{
		VendorProject:              vendorProject,
		Product:                    product,
		VulnerabilityName:          vulnName,
		DateAdded:                  dateAdded,
		DueDate:                    dueDate,
		RequiredAction:             requiredAction,
		KnownRansomwareCampaignUse: ransomware,
	}, nil
}

// parseTextArray parses a PostgreSQL TEXT[] literal (e.g., "{foo,bar}") into a Go string slice.
func parseTextArray(s string) []string {
	if s == "" || s == "{}" {
		return nil
	}
	// Strip surrounding braces
	s = s[1 : len(s)-1]
	if s == "" {
		return nil
	}

	var result []string
	var current []byte
	inQuote := false
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '"' && !inQuote:
			inQuote = true
		case s[i] == '"' && inQuote:
			inQuote = false
		case s[i] == ',' && !inQuote:
			result = append(result, string(current))
			current = current[:0]
		case s[i] == '\\' && inQuote && i+1 < len(s):
			i++
			current = append(current, s[i])
		default:
			current = append(current, s[i])
		}
	}
	if len(current) > 0 {
		result = append(result, string(current))
	}
	return result
}
