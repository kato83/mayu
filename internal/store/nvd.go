package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/kato83/mayu/internal/model"
)

// UpsertNVDBatch stores multiple NVD CVE entries in a single transaction.
// It retries automatically on deadlock (same pattern as OSV UpsertBatch).
func (s *PostgresStore) UpsertNVDBatch(ctx context.Context, entries []*model.NVDCVE) error {
	const maxRetries = 5
	for attempt := 0; attempt <= maxRetries; attempt++ {
		err := s.upsertNVDBatchOnce(ctx, entries)
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
	return fmt.Errorf("upsert NVD batch: exceeded max retries due to deadlock")
}

func (s *PostgresStore) upsertNVDBatchOnce(ctx context.Context, entries []*model.NVDCVE) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, entry := range entries {
		if err := s.upsertNVDEntry(ctx, tx, entry); err != nil {
			return fmt.Errorf("upsert %s: %w", entry.ID, err)
		}
	}

	return tx.Commit()
}

// upsertNVDEntry inserts or updates a single NVD CVE entry within a transaction.
// It follows the same pattern as upsertVulnerability:
//   - Upsert into unified vulnerabilities table
//   - DELETE existing nvd_entries row (CASCADE cleans child tables)
//   - INSERT fresh NVD data into nvd_entries and all child tables
func (s *PostgresStore) upsertNVDEntry(ctx context.Context, tx *sql.Tx, entry *model.NVDCVE) error {
	cveID := entry.ID
	summary := extractEnglishDescription(entry.Descriptions)

	// Determine raw_json: use RawJSON if available, otherwise marshal the struct
	rawJSON := entry.RawJSON
	if rawJSON == nil {
		var err error
		rawJSON, err = json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("marshal NVD entry: %w", err)
		}
	}

	// --- Step 1: Upsert into unified vulnerabilities table (no source column) ---
	// ON CONFLICT: preserve existing summary (OSV priority) via COALESCE, use GREATEST for modified
	_, err := tx.ExecContext(ctx, `
		INSERT INTO vulnerabilities (id, summary, details, published, modified, withdrawn)
		VALUES ($1, $2, NULL, $3, $4, NULL)
		ON CONFLICT (id) DO UPDATE SET
			summary = COALESCE(NULLIF(vulnerabilities.summary, ''), EXCLUDED.summary),
			published = COALESCE(EXCLUDED.published, vulnerabilities.published),
			modified = GREATEST(EXCLUDED.modified, vulnerabilities.modified)`,
		cveID,
		nullIfEmpty(summary),
		entry.Published.Time,
		entry.LastModified.Time,
	)
	if err != nil {
		return fmt.Errorf("upsert vulnerability: %w", err)
	}

	// --- Step 2: Delete existing nvd_entries row (CASCADE cleans child tables) ---
	_, err = tx.ExecContext(ctx, `DELETE FROM nvd_entries WHERE cve_id = $1`, cveID)
	if err != nil {
		return fmt.Errorf("delete existing nvd_entry: %w", err)
	}

	// --- Step 3: Insert into nvd_entries ---
	var nvdEntryID int64
	err = tx.QueryRowContext(ctx, `
		INSERT INTO nvd_entries (cve_id, vulnerability_id, source_identifier, vuln_status, published, last_modified, raw_json)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id`,
		cveID,
		cveID,
		nullIfEmpty(entry.SourceIdentifier),
		nullIfEmpty(entry.VulnStatus),
		entry.Published.Time,
		entry.LastModified.Time,
		rawJSON,
	).Scan(&nvdEntryID)
	if err != nil {
		return fmt.Errorf("insert nvd_entry: %w", err)
	}

	// --- Step 4: Insert descriptions (bulk) ---
	if len(entry.Descriptions) > 0 {
		descQuery := "INSERT INTO nvd_descriptions (nvd_entry_id, lang, value) VALUES "
		descArgs := make([]interface{}, 0, len(entry.Descriptions)*2+1)
		descArgs = append(descArgs, nvdEntryID)
		for i, desc := range entry.Descriptions {
			if i > 0 {
				descQuery += ", "
			}
			base := i*2 + 2
			descQuery += fmt.Sprintf("($1, $%d, $%d)", base, base+1)
			descArgs = append(descArgs, desc.Lang, desc.Value)
		}
		if _, err := tx.ExecContext(ctx, descQuery, descArgs...); err != nil {
			return fmt.Errorf("insert nvd_descriptions: %w", err)
		}
	}

	// --- Step 5: Insert metrics (bulk) ---
	if err := s.insertNVDMetrics(ctx, tx, nvdEntryID, entry.Metrics); err != nil {
		return err
	}

	// --- Step 6: Insert weaknesses (bulk) ---
	if err := s.insertNVDWeaknesses(ctx, tx, nvdEntryID, entry.Weaknesses); err != nil {
		return err
	}

	// --- Step 7: Insert configurations and CPE matches ---
	if err := s.insertNVDConfigurations(ctx, tx, nvdEntryID, entry.Configurations); err != nil {
		return err
	}

	// --- Step 7b: Insert product_identifiers from CPE matches (decomposed) ---
	if _, err := tx.ExecContext(ctx, `DELETE FROM product_identifiers WHERE vulnerability_id = $1 AND source = 'nvd'`, cveID); err != nil {
		return fmt.Errorf("delete nvd product_identifiers: %w", err)
	}
	for _, cfg := range entry.Configurations {
		matches := flattenCPEMatches(cfg.Nodes)
		for _, m := range matches {
			if !m.Vulnerable {
				continue
			}
			cpeFields := model.ParseCPE23(m.Criteria)
			if cpeFields == nil {
				continue
			}
			pi := &model.ProductIdentifier{
				VulnerabilityID: cveID,
				Source:          "nvd",
				CPEPart:         cpeFields.Part,
				CPEVendor:       cpeFields.Vendor,
				CPEProduct:      cpeFields.Product,
				CPEVersion:      cpeFields.Version,
				CPEUpdate:       cpeFields.Update,
				CPEEdition:      cpeFields.Edition,
				CPELanguage:     cpeFields.Language,
				CPESWEdition:    cpeFields.SWEdition,
				CPETargetSW:     cpeFields.TargetSW,
				CPETargetHW:     cpeFields.TargetHW,
				CPEOther:        cpeFields.Other,
				Vendor:          cpeFields.Vendor,
				Product:         cpeFields.Product,
			}
			// Build version_constraint from CPE version range fields
			if m.VersionStartIncluding != "" || m.VersionStartExcluding != "" ||
				m.VersionEndIncluding != "" || m.VersionEndExcluding != "" {
				vc := map[string]string{}
				if m.VersionStartIncluding != "" {
					vc["vsi"] = m.VersionStartIncluding
				}
				if m.VersionStartExcluding != "" {
					vc["vse"] = m.VersionStartExcluding
				}
				if m.VersionEndIncluding != "" {
					vc["vei"] = m.VersionEndIncluding
				}
				if m.VersionEndExcluding != "" {
					vc["vee"] = m.VersionEndExcluding
				}
				vcJSON, _ := json.Marshal(vc)
				pi.VersionConstraint = vcJSON
			}
			if err := insertSingleProductIdentifierNVD(ctx, tx, pi); err != nil {
				return fmt.Errorf("insert nvd product_identifier: %w", err)
			}
		}
	}

	// --- Step 8: Insert references (bulk) ---
	if len(entry.References) > 0 {
		refQuery := "INSERT INTO nvd_references (nvd_entry_id, url, source, tags) VALUES "
		refArgs := make([]interface{}, 0, len(entry.References)*3+1)
		refArgs = append(refArgs, nvdEntryID)
		for i, ref := range entry.References {
			if i > 0 {
				refQuery += ", "
			}
			base := i*3 + 2
			refQuery += fmt.Sprintf("($1, $%d, $%d, $%d)", base, base+1, base+2)
			refArgs = append(refArgs, ref.URL, nullIfEmpty(ref.Source), pgTextArray(ref.Tags))
		}
		if _, err := tx.ExecContext(ctx, refQuery, refArgs...); err != nil {
			return fmt.Errorf("insert nvd_references: %w", err)
		}
	}

	return nil
}

// insertNVDMetrics inserts all CVSS metrics for an NVD entry.
func (s *PostgresStore) insertNVDMetrics(ctx context.Context, tx *sql.Tx, nvdEntryID int64, metrics model.NVDMetrics) error {
	type metricRow struct {
		version             string
		source              string
		metricType          string
		cvssData            json.RawMessage
		baseScore           *float64
		baseSeverity        string
		exploitabilityScore *float64
		impactScore         *float64
	}

	var rows []metricRow

	// CVSS v4.0
	for _, m := range metrics.CvssMetricV40 {
		rows = append(rows, metricRow{
			version:      "v40",
			source:       m.Source,
			metricType:   m.Type,
			cvssData:     m.CvssData,
			baseScore:    extractBaseScore(m.CvssData),
			baseSeverity: extractBaseSeverity(m.CvssData),
		})
	}

	// CVSS v3.1
	for _, m := range metrics.CvssMetricV31 {
		rows = append(rows, metricRow{
			version:             "v31",
			source:              m.Source,
			metricType:          m.Type,
			cvssData:            m.CvssData,
			baseScore:           extractBaseScore(m.CvssData),
			baseSeverity:        extractBaseSeverity(m.CvssData),
			exploitabilityScore: m.ExploitabilityScore,
			impactScore:         m.ImpactScore,
		})
	}

	// CVSS v3.0
	for _, m := range metrics.CvssMetricV30 {
		rows = append(rows, metricRow{
			version:             "v30",
			source:              m.Source,
			metricType:          m.Type,
			cvssData:            m.CvssData,
			baseScore:           extractBaseScore(m.CvssData),
			baseSeverity:        extractBaseSeverity(m.CvssData),
			exploitabilityScore: m.ExploitabilityScore,
			impactScore:         m.ImpactScore,
		})
	}

	// CVSS v2.0
	for _, m := range metrics.CvssMetricV2 {
		rows = append(rows, metricRow{
			version:             "v2",
			source:              m.Source,
			metricType:          m.Type,
			cvssData:            m.CvssData,
			baseScore:           extractBaseScore(m.CvssData),
			baseSeverity:        m.BaseSeverity,
			exploitabilityScore: m.ExploitabilityScore,
			impactScore:         m.ImpactScore,
		})
	}

	if len(rows) == 0 {
		return nil
	}

	query := "INSERT INTO nvd_metrics (nvd_entry_id, version, source, type, cvss_data, base_score, base_severity, exploitability_score, impact_score) VALUES "
	args := make([]interface{}, 0, len(rows)*8+1)
	args = append(args, nvdEntryID)
	for i, r := range rows {
		if i > 0 {
			query += ", "
		}
		base := i*8 + 2
		query += fmt.Sprintf("($1, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d)",
			base, base+1, base+2, base+3, base+4, base+5, base+6, base+7)
		args = append(args, r.version, r.source, r.metricType, []byte(r.cvssData),
			nullableFloat64(r.baseScore), nullIfEmpty(r.baseSeverity),
			nullableFloat64(r.exploitabilityScore), nullableFloat64(r.impactScore))
	}
	if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("insert nvd_metrics: %w", err)
	}
	return nil
}

// insertNVDWeaknesses inserts CWE weakness entries for an NVD entry.
// Each weakness description item becomes a separate row (expanded).
func (s *PostgresStore) insertNVDWeaknesses(ctx context.Context, tx *sql.Tx, nvdEntryID int64, weaknesses []model.NVDWeakness) error {
	type weaknessRow struct {
		source   string
		weakType string
		cweID    string
	}

	var rows []weaknessRow
	for _, w := range weaknesses {
		for _, desc := range w.Description {
			if desc.Lang == "en" && desc.Value != "" {
				rows = append(rows, weaknessRow{
					source:   w.Source,
					weakType: w.Type,
					cweID:    desc.Value,
				})
			}
		}
	}

	if len(rows) == 0 {
		return nil
	}

	query := "INSERT INTO nvd_weaknesses (nvd_entry_id, source, type, cwe_id) VALUES "
	args := make([]interface{}, 0, len(rows)*3+1)
	args = append(args, nvdEntryID)
	for i, r := range rows {
		if i > 0 {
			query += ", "
		}
		base := i*3 + 2
		query += fmt.Sprintf("($1, $%d, $%d, $%d)", base, base+1, base+2)
		args = append(args, r.source, r.weakType, r.cweID)
	}
	if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("insert nvd_weaknesses: %w", err)
	}
	return nil
}

// insertNVDConfigurations inserts CPE configurations and their flattened CPE matches.
func (s *PostgresStore) insertNVDConfigurations(ctx context.Context, tx *sql.Tx, nvdEntryID int64, configs []model.NVDConfiguration) error {
	for _, cfg := range configs {
		// Marshal nodes to JSON for raw_nodes
		nodesJSON, err := json.Marshal(cfg.Nodes)
		if err != nil {
			return fmt.Errorf("marshal nodes: %w", err)
		}

		negate := false
		if cfg.Negate != nil {
			negate = *cfg.Negate
		}

		var configID int64
		err = tx.QueryRowContext(ctx, `
			INSERT INTO nvd_configurations (nvd_entry_id, operator, negate, raw_nodes)
			VALUES ($1, $2, $3, $4)
			RETURNING id`,
			nvdEntryID,
			nullIfEmpty(cfg.Operator),
			negate,
			nodesJSON,
		).Scan(&configID)
		if err != nil {
			return fmt.Errorf("insert nvd_configuration: %w", err)
		}

		// Flatten CPE matches from all nodes and insert
		matches := flattenCPEMatches(cfg.Nodes)
		if len(matches) == 0 {
			continue
		}

		matchQuery := "INSERT INTO nvd_cpe_matches (configuration_id, vulnerable, criteria, match_criteria_id, version_start_including, version_start_excluding, version_end_including, version_end_excluding, cpe_part, cpe_vendor, cpe_product, cpe_version, cpe_update, cpe_edition, cpe_language, cpe_sw_edition, cpe_target_sw, cpe_target_hw, cpe_other) VALUES "
		matchArgs := make([]interface{}, 0, len(matches)*18+1)
		matchArgs = append(matchArgs, configID)
		for i, m := range matches {
			if i > 0 {
				matchQuery += ", "
			}
			base := i*18 + 2
			matchQuery += fmt.Sprintf("($1, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d)",
				base, base+1, base+2, base+3, base+4, base+5, base+6,
				base+7, base+8, base+9, base+10, base+11, base+12, base+13, base+14, base+15, base+16, base+17)

			// Decompose CPE 2.3 URI into fields
			cpeFields := model.ParseCPE23(m.Criteria)
			var cpePart, cpeVendor, cpeProduct, cpeVersion, cpeUpdate, cpeEdition, cpeLang, cpeSWEd, cpeTgtSW, cpeTgtHW, cpeOther interface{}
			if cpeFields != nil {
				cpePart = nullIfEmpty(cpeFields.Part)
				cpeVendor = nullIfEmpty(cpeFields.Vendor)
				cpeProduct = nullIfEmpty(cpeFields.Product)
				cpeVersion = nullIfEmpty(cpeFields.Version)
				cpeUpdate = nullIfEmpty(cpeFields.Update)
				cpeEdition = nullIfEmpty(cpeFields.Edition)
				cpeLang = nullIfEmpty(cpeFields.Language)
				cpeSWEd = nullIfEmpty(cpeFields.SWEdition)
				cpeTgtSW = nullIfEmpty(cpeFields.TargetSW)
				cpeTgtHW = nullIfEmpty(cpeFields.TargetHW)
				cpeOther = nullIfEmpty(cpeFields.Other)
			}

			matchArgs = append(matchArgs, m.Vulnerable, m.Criteria, m.MatchCriteriaId,
				nullIfEmpty(m.VersionStartIncluding), nullIfEmpty(m.VersionStartExcluding),
				nullIfEmpty(m.VersionEndIncluding), nullIfEmpty(m.VersionEndExcluding),
				cpePart, cpeVendor, cpeProduct, cpeVersion, cpeUpdate, cpeEdition, cpeLang, cpeSWEd, cpeTgtSW, cpeTgtHW, cpeOther)
		}
		if _, err := tx.ExecContext(ctx, matchQuery, matchArgs...); err != nil {
			return fmt.Errorf("insert nvd_cpe_matches: %w", err)
		}
	}
	return nil
}

// --- NVD Helper functions ---

// extractEnglishDescription returns the first English description value.
// Returns empty string if no English description is found.
func extractEnglishDescription(descs []model.NVDLangString) string {
	for _, d := range descs {
		if d.Lang == "en" {
			return d.Value
		}
	}
	return ""
}

// extractBaseScore extracts the baseScore field from a CVSS JSON data blob.
// Returns nil if the field is missing or cannot be parsed.
func extractBaseScore(cvssData json.RawMessage) *float64 {
	if len(cvssData) == 0 {
		return nil
	}
	var data map[string]interface{}
	if err := json.Unmarshal(cvssData, &data); err != nil {
		return nil
	}
	if score, ok := data["baseScore"]; ok {
		if f, ok := score.(float64); ok {
			return &f
		}
	}
	return nil
}

// extractBaseSeverity extracts the baseSeverity field from a CVSS JSON data blob.
// Returns empty string if the field is missing or cannot be parsed.
func extractBaseSeverity(cvssData json.RawMessage) string {
	if len(cvssData) == 0 {
		return ""
	}
	var data map[string]interface{}
	if err := json.Unmarshal(cvssData, &data); err != nil {
		return ""
	}
	if sev, ok := data["baseSeverity"]; ok {
		if s, ok := sev.(string); ok {
			return s
		}
	}
	return ""
}

// flattenCPEMatches recursively collects all CPE match entries from a node tree.
func flattenCPEMatches(nodes []model.NVDNode) []model.NVDCPEMatch {
	var matches []model.NVDCPEMatch
	for _, node := range nodes {
		matches = append(matches, node.CpeMatch...)
	}
	return matches
}

// nullableFloat64 returns nil if the pointer is nil, otherwise returns the float value.
func nullableFloat64(f *float64) interface{} {
	if f == nil {
		return nil
	}
	return *f
}

// insertSingleProductIdentifierNVD inserts a single NVD product_identifiers row.
func insertSingleProductIdentifierNVD(ctx context.Context, tx *sql.Tx, pi *model.ProductIdentifier) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO product_identifiers (
			vulnerability_id, source,
			purl_type, purl_namespace, purl_name, purl_version, purl_qualifiers, purl_subpath,
			cpe_part, cpe_vendor, cpe_product, cpe_version, cpe_update, cpe_edition,
			cpe_language, cpe_sw_edition, cpe_target_sw, cpe_target_hw, cpe_other,
			ecosystem, name, vendor, product, version_constraint
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)`,
		pi.VulnerabilityID, pi.Source,
		nullIfEmpty(pi.PurlType), nullIfEmpty(pi.PurlNamespace), nullIfEmpty(pi.PurlName),
		nullIfEmpty(pi.PurlVersion), nullIfEmpty(pi.PurlQualifiers), nullIfEmpty(pi.PurlSubpath),
		nullIfEmpty(pi.CPEPart), nullIfEmpty(pi.CPEVendor), nullIfEmpty(pi.CPEProduct),
		nullIfEmpty(pi.CPEVersion), nullIfEmpty(pi.CPEUpdate), nullIfEmpty(pi.CPEEdition),
		nullIfEmpty(pi.CPELanguage), nullIfEmpty(pi.CPESWEdition), nullIfEmpty(pi.CPETargetSW),
		nullIfEmpty(pi.CPETargetHW), nullIfEmpty(pi.CPEOther),
		nullIfEmpty(pi.Ecosystem), nullIfEmpty(pi.Name),
		nullIfEmpty(pi.Vendor), nullIfEmpty(pi.Product),
		nullableRawJSON(pi.VersionConstraint),
	)
	return err
}
