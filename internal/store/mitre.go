package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/kato83/mayu/internal/model"
)

// UpsertMITREBatch stores multiple MITRE CVE entries in a single transaction.
// It retries automatically on deadlock (same pattern as UpsertNVDBatch).
func (s *PostgresStore) UpsertMITREBatch(ctx context.Context, entries []*model.MITRECVERecord) error {
	const maxRetries = 5
	for attempt := 0; attempt <= maxRetries; attempt++ {
		err := s.upsertMITREBatchOnce(ctx, entries)
		if err == nil {
			return nil
		}
		if isDeadlock(err) && attempt < maxRetries {
			backoff := time.Duration(10<<uint(attempt)) * time.Millisecond
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			continue
		}
		return err
	}
	return fmt.Errorf("upsert MITRE batch: exceeded max retries due to deadlock")
}

func (s *PostgresStore) upsertMITREBatchOnce(ctx context.Context, entries []*model.MITRECVERecord) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, entry := range entries {
		if err := s.upsertMITREEntry(ctx, tx, entry); err != nil {
			return fmt.Errorf("upsert %s: %w", entry.CVEMetadata.CVEID, err)
		}
	}

	return tx.Commit()
}

// upsertMITREEntry inserts or updates a single MITRE CVE entry within a transaction.
// It follows the same pattern as upsertNVDEntry:
//   - Upsert into unified vulnerabilities table
//   - DELETE existing mitre_entries row (CASCADE cleans child tables)
//   - INSERT fresh MITRE data into mitre_entries and all child tables
func (s *PostgresStore) upsertMITREEntry(ctx context.Context, tx *sql.Tx, entry *model.MITRECVERecord) error {
	// Step 1: Extract CVE ID
	cveID := entry.CVEMetadata.CVEID

	// Step 2: Extract English summary from CNA container descriptions
	var summary string
	if entry.Containers.CNA != nil {
		summary = extractMITREEnglishDescription(entry.Containers.CNA.Descriptions)
	}

	// Step 3: Determine raw_json
	rawJSON := entry.RawJSON
	if rawJSON == nil {
		var err error
		rawJSON, err = json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("marshal MITRE entry: %w", err)
		}
	}

	// Step 4: Determine published and modified times
	published := entry.CVEMetadata.DatePublished.Time
	modified := entry.CVEMetadata.DateUpdated.Time
	if modified.IsZero() {
		modified = published
	}

	// Handle zero published time (REJECTED CVEs may not have it)
	var publishedPtr interface{}
	if published.IsZero() {
		publishedPtr = nil
	} else {
		publishedPtr = published
	}

	var modifiedPtr interface{}
	if modified.IsZero() {
		modifiedPtr = nil
	} else {
		modifiedPtr = modified
	}

	// Step 5: Upsert into unified vulnerabilities table
	// COALESCE preserves existing NVD/OSV data; MITRE only fills gaps
	_, err := tx.ExecContext(ctx, `
		INSERT INTO vulnerabilities (id, source, summary, details, published, modified, withdrawn)
		VALUES ($1, 'mitre', $2, NULL, $3, $4, NULL)
		ON CONFLICT (id) DO UPDATE SET
			summary = COALESCE(NULLIF(vulnerabilities.summary, ''), EXCLUDED.summary),
			published = COALESCE(vulnerabilities.published, EXCLUDED.published),
			modified = GREATEST(EXCLUDED.modified, vulnerabilities.modified)`,
		cveID,
		nullIfEmpty(summary),
		publishedPtr,
		modifiedPtr,
	)
	if err != nil {
		return fmt.Errorf("upsert vulnerability: %w", err)
	}

	// Step 6: Delete existing mitre_entries row (CASCADE cleans child tables)
	_, err = tx.ExecContext(ctx, `DELETE FROM mitre_entries WHERE cve_id = $1`, cveID)
	if err != nil {
		return fmt.Errorf("delete existing mitre_entry: %w", err)
	}

	// Step 7: Insert into mitre_entries
	var dateReservedPtr, datePublishedPtr, dateUpdatedPtr interface{}
	if !entry.CVEMetadata.DateReserved.IsZero() {
		dateReservedPtr = entry.CVEMetadata.DateReserved.Time
	}
	if !entry.CVEMetadata.DatePublished.IsZero() {
		datePublishedPtr = entry.CVEMetadata.DatePublished.Time
	}
	if !entry.CVEMetadata.DateUpdated.IsZero() {
		dateUpdatedPtr = entry.CVEMetadata.DateUpdated.Time
	}

	var mitreEntryID int64
	err = tx.QueryRowContext(ctx, `
		INSERT INTO mitre_entries (cve_id, vulnerability_id, data_version, state, assigner_org_id, assigner_short_name, date_reserved, date_published, date_updated, raw_json)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id`,
		cveID,
		cveID,
		entry.DataVersion,
		entry.CVEMetadata.State,
		nullIfEmpty(entry.CVEMetadata.AssignerOrgID),
		nullIfEmpty(entry.CVEMetadata.AssignerShortName),
		dateReservedPtr,
		datePublishedPtr,
		dateUpdatedPtr,
		rawJSON,
	).Scan(&mitreEntryID)
	if err != nil {
		return fmt.Errorf("insert mitre_entry: %w", err)
	}

	// Step 8: Insert CNA container
	if entry.Containers.CNA != nil {
		cna := entry.Containers.CNA
		var cnaDateUpdated interface{}
		if !cna.ProviderMetadata.DateUpdated.IsZero() {
			cnaDateUpdated = cna.ProviderMetadata.DateUpdated.Time
		}
		cnaContainerID, err := insertMITREContainer(ctx, tx, mitreEntryID, "cna",
			nullIfEmpty(cna.Title),
			nullIfEmpty(cna.ProviderMetadata.OrgID),
			nullIfEmpty(cna.ProviderMetadata.ShortName),
			cnaDateUpdated,
		)
		if err != nil {
			return fmt.Errorf("insert CNA container: %w", err)
		}

		// Insert CNA child records
		if err := insertMITREAffected(ctx, tx, cnaContainerID, cna.Affected); err != nil {
			return fmt.Errorf("insert CNA affected: %w", err)
		}
		if err := insertMITREMetrics(ctx, tx, cnaContainerID, cna.Metrics); err != nil {
			return fmt.Errorf("insert CNA metrics: %w", err)
		}
		if err := insertMITREProblemTypes(ctx, tx, cnaContainerID, cna.ProblemTypes); err != nil {
			return fmt.Errorf("insert CNA problem types: %w", err)
		}
		if err := insertMITREReferences(ctx, tx, cnaContainerID, cna.References); err != nil {
			return fmt.Errorf("insert CNA references: %w", err)
		}
		if err := insertMITRECredits(ctx, tx, cnaContainerID, cna.Credits); err != nil {
			return fmt.Errorf("insert CNA credits: %w", err)
		}
	}

	// Step 9: Insert ADP containers
	for i, adp := range entry.Containers.ADP {
		var adpDateUpdated interface{}
		if !adp.ProviderMetadata.DateUpdated.IsZero() {
			adpDateUpdated = adp.ProviderMetadata.DateUpdated.Time
		}
		adpContainerID, err := insertMITREContainer(ctx, tx, mitreEntryID, "adp",
			nullIfEmpty(adp.Title),
			nullIfEmpty(adp.ProviderMetadata.OrgID),
			nullIfEmpty(adp.ProviderMetadata.ShortName),
			adpDateUpdated,
		)
		if err != nil {
			return fmt.Errorf("insert ADP container [%d]: %w", i, err)
		}

		// Insert ADP child records
		if err := insertMITREAffected(ctx, tx, adpContainerID, adp.Affected); err != nil {
			return fmt.Errorf("insert ADP affected [%d]: %w", i, err)
		}
		if err := insertMITREMetrics(ctx, tx, adpContainerID, adp.Metrics); err != nil {
			return fmt.Errorf("insert ADP metrics [%d]: %w", i, err)
		}
		if err := insertMITREProblemTypes(ctx, tx, adpContainerID, adp.ProblemTypes); err != nil {
			return fmt.Errorf("insert ADP problem types [%d]: %w", i, err)
		}
		if err := insertMITREReferences(ctx, tx, adpContainerID, adp.References); err != nil {
			return fmt.Errorf("insert ADP references [%d]: %w", i, err)
		}
		if err := insertMITRECredits(ctx, tx, adpContainerID, adp.Credits); err != nil {
			return fmt.Errorf("insert ADP credits [%d]: %w", i, err)
		}
	}

	return nil
}

// --- MITRE Helper functions ---

// extractMITREEnglishDescription returns the first English description value.
// Returns empty string if no English description is found.
func extractMITREEnglishDescription(descs []model.MITREDescription) string {
	for _, d := range descs {
		if d.Lang == "en" {
			return d.Value
		}
	}
	return ""
}

// insertMITREContainer inserts a container (CNA or ADP) and returns its generated ID.
func insertMITREContainer(ctx context.Context, tx *sql.Tx, mitreEntryID int64, containerType string, title, providerOrgID, providerShortName, dateUpdated interface{}) (int64, error) {
	var containerID int64
	err := tx.QueryRowContext(ctx, `
		INSERT INTO mitre_containers (mitre_entry_id, container_type, title, provider_org_id, provider_short_name, date_updated)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id`,
		mitreEntryID,
		containerType,
		title,
		providerOrgID,
		providerShortName,
		dateUpdated,
	).Scan(&containerID)
	if err != nil {
		return 0, err
	}
	return containerID, nil
}

// insertMITREAffected bulk inserts affected products and their nested version ranges.
func insertMITREAffected(ctx context.Context, tx *sql.Tx, containerID int64, affected []model.MITREAffected) error {
	if len(affected) == 0 {
		return nil
	}

	for _, aff := range affected {
		// Insert the affected row and get its ID for child versions
		var affectedID int64
		err := tx.QueryRowContext(ctx, `
			INSERT INTO mitre_affected (container_id, vendor, product, default_status, platforms, modules, package_url)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			RETURNING id`,
			containerID,
			nullIfEmpty(aff.Vendor),
			nullIfEmpty(aff.Product),
			nullIfEmpty(aff.DefaultStatus),
			pgTextArray(aff.Platforms),
			pgTextArray(aff.Modules),
			nullIfEmpty(aff.PackageURL),
		).Scan(&affectedID)
		if err != nil {
			return fmt.Errorf("insert mitre_affected: %w", err)
		}

		// Bulk insert versions for this affected product
		if len(aff.Versions) > 0 {
			verQuery := "INSERT INTO mitre_affected_versions (affected_id, version, version_type, status, less_than, less_than_or_equal, changes) VALUES "
			verArgs := make([]interface{}, 0, len(aff.Versions)*6+1)
			verArgs = append(verArgs, affectedID)
			for i, v := range aff.Versions {
				if i > 0 {
					verQuery += ", "
				}
				base := i*6 + 2
				verQuery += fmt.Sprintf("($1, $%d, $%d, $%d, $%d, $%d, $%d)",
					base, base+1, base+2, base+3, base+4, base+5)
				verArgs = append(verArgs,
					nullIfEmpty(v.Version),
					nullIfEmpty(v.VersionType),
					v.Status,
					nullIfEmpty(v.LessThan),
					nullIfEmpty(v.LessOrEqual),
					nullableRawJSON(v.Changes),
				)
			}
			if _, err := tx.ExecContext(ctx, verQuery, verArgs...); err != nil {
				return fmt.Errorf("insert mitre_affected_versions: %w", err)
			}
		}
	}

	return nil
}

// insertMITREMetrics bulk inserts CVSS/SSVC metrics for a container.
// It extracts base_score, base_severity, and vector_string from the CVSS JSON data.
func insertMITREMetrics(ctx context.Context, tx *sql.Tx, containerID int64, metrics []model.MITREMetric) error {
	if len(metrics) == 0 {
		return nil
	}

	type metricRow struct {
		format       string
		cvssVersion  string
		baseScore    *float64
		baseSeverity string
		vectorString string
		cvssData     json.RawMessage
		scenarios    []byte
	}

	var rows []metricRow
	for _, m := range metrics {
		row := metricRow{
			format: m.Format,
		}

		// Marshal scenarios to JSON
		if len(m.Scenarios) > 0 {
			scenJSON, err := json.Marshal(m.Scenarios)
			if err != nil {
				return fmt.Errorf("marshal scenarios: %w", err)
			}
			row.scenarios = scenJSON
		}

		// Determine CVSS version and extract data
		switch {
		case len(m.CvssV4_0) > 0:
			row.cvssVersion = "4.0"
			row.cvssData = m.CvssV4_0
			row.baseScore = extractBaseScore(m.CvssV4_0)
			row.baseSeverity = extractBaseSeverity(m.CvssV4_0)
			row.vectorString = extractVectorString(m.CvssV4_0)
		case len(m.CvssV3_1) > 0:
			row.cvssVersion = "3.1"
			row.cvssData = m.CvssV3_1
			row.baseScore = extractBaseScore(m.CvssV3_1)
			row.baseSeverity = extractBaseSeverity(m.CvssV3_1)
			row.vectorString = extractVectorString(m.CvssV3_1)
		case len(m.CvssV3_0) > 0:
			row.cvssVersion = "3.0"
			row.cvssData = m.CvssV3_0
			row.baseScore = extractBaseScore(m.CvssV3_0)
			row.baseSeverity = extractBaseSeverity(m.CvssV3_0)
			row.vectorString = extractVectorString(m.CvssV3_0)
		case len(m.CvssV2_0) > 0:
			row.cvssVersion = "2.0"
			row.cvssData = m.CvssV2_0
			row.baseScore = extractBaseScore(m.CvssV2_0)
			row.baseSeverity = extractBaseSeverity(m.CvssV2_0)
			row.vectorString = extractVectorString(m.CvssV2_0)
		case len(m.Other) > 0:
			// SSVC or other non-CVSS metrics
			if m.Format != "" {
				row.format = m.Format
			} else {
				row.format = "Other"
			}
			row.cvssData = m.Other
			// No base_score for SSVC/Other
		default:
			// Metric with no CVSS data — skip or store format only
			if m.Format == "" {
				continue
			}
		}

		// Default format to "CVSS" if not set and we have CVSS data
		if row.format == "" && row.cvssVersion != "" {
			row.format = "CVSS"
		}

		rows = append(rows, row)
	}

	if len(rows) == 0 {
		return nil
	}

	query := "INSERT INTO mitre_metrics (container_id, format, cvss_version, base_score, base_severity, vector_string, cvss_data, scenarios) VALUES "
	args := make([]interface{}, 0, len(rows)*7+1)
	args = append(args, containerID)
	for i, r := range rows {
		if i > 0 {
			query += ", "
		}
		base := i*7 + 2
		query += fmt.Sprintf("($1, $%d, $%d, $%d, $%d, $%d, $%d, $%d)",
			base, base+1, base+2, base+3, base+4, base+5, base+6)
		args = append(args,
			r.format,
			nullIfEmpty(r.cvssVersion),
			nullableFloat64(r.baseScore),
			nullIfEmpty(r.baseSeverity),
			nullIfEmpty(r.vectorString),
			nullableRawJSON(r.cvssData),
			nullableRawJSON(json.RawMessage(r.scenarios)),
		)
	}
	if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("insert mitre_metrics: %w", err)
	}
	return nil
}

// insertMITREProblemTypes bulk inserts problem type descriptions for a container.
// Each MITREProblemType may have multiple descriptions; these are expanded into individual rows.
func insertMITREProblemTypes(ctx context.Context, tx *sql.Tx, containerID int64, problemTypes []model.MITREProblemType) error {
	type ptRow struct {
		cweID       string
		description string
		lang        string
	}

	var rows []ptRow
	for _, pt := range problemTypes {
		for _, desc := range pt.Descriptions {
			rows = append(rows, ptRow{
				cweID:       desc.CWEID,
				description: desc.Description,
				lang:        desc.Lang,
			})
		}
	}

	if len(rows) == 0 {
		return nil
	}

	query := "INSERT INTO mitre_problem_types (container_id, cwe_id, description, lang) VALUES "
	args := make([]interface{}, 0, len(rows)*3+1)
	args = append(args, containerID)
	for i, r := range rows {
		if i > 0 {
			query += ", "
		}
		base := i*3 + 2
		query += fmt.Sprintf("($1, $%d, $%d, $%d)", base, base+1, base+2)
		args = append(args, nullIfEmpty(r.cweID), r.description, r.lang)
	}
	if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("insert mitre_problem_types: %w", err)
	}
	return nil
}

// insertMITREReferences bulk inserts references for a container.
func insertMITREReferences(ctx context.Context, tx *sql.Tx, containerID int64, refs []model.MITREReference) error {
	if len(refs) == 0 {
		return nil
	}

	query := "INSERT INTO mitre_references (container_id, url, name, tags) VALUES "
	args := make([]interface{}, 0, len(refs)*3+1)
	args = append(args, containerID)
	for i, ref := range refs {
		if i > 0 {
			query += ", "
		}
		base := i*3 + 2
		query += fmt.Sprintf("($1, $%d, $%d, $%d)", base, base+1, base+2)
		args = append(args, ref.URL, nullIfEmpty(ref.Name), pgTextArray(ref.Tags))
	}
	if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("insert mitre_references: %w", err)
	}
	return nil
}

// insertMITRECredits bulk inserts credits for a container.
func insertMITRECredits(ctx context.Context, tx *sql.Tx, containerID int64, credits []model.MITRECredit) error {
	if len(credits) == 0 {
		return nil
	}

	query := "INSERT INTO mitre_credits (container_id, credit_type, value, lang) VALUES "
	args := make([]interface{}, 0, len(credits)*3+1)
	args = append(args, containerID)
	for i, c := range credits {
		if i > 0 {
			query += ", "
		}
		base := i*3 + 2
		query += fmt.Sprintf("($1, $%d, $%d, $%d)", base, base+1, base+2)
		args = append(args, nullIfEmpty(c.Type), c.Value, c.Lang)
	}
	if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("insert mitre_credits: %w", err)
	}
	return nil
}

// extractVectorString extracts the vectorString field from a CVSS JSON data blob.
// Returns empty string if the field is missing or cannot be parsed.
func extractVectorString(cvssData json.RawMessage) string {
	if len(cvssData) == 0 {
		return ""
	}
	var data map[string]interface{}
	if err := json.Unmarshal(cvssData, &data); err != nil {
		return ""
	}
	if vec, ok := data["vectorString"]; ok {
		if s, ok := vec.(string); ok {
			return s
		}
	}
	return ""
}
