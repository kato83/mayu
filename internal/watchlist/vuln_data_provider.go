package watchlist

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// Compile-time interface compliance check.
var _ VulnDataProvider = (*PostgresVulnDataProvider)(nil)

// PostgresVulnDataProvider implements VulnDataProvider using direct SQL queries
// against the vulnerability_summary and product_identifiers tables.
type PostgresVulnDataProvider struct {
	db *sql.DB
}

// NewPostgresVulnDataProvider creates a new PostgresVulnDataProvider.
func NewPostgresVulnDataProvider(db *sql.DB) *PostgresVulnDataProvider {
	return &PostgresVulnDataProvider{db: db}
}

// GetVulnDataForMatching retrieves vulnerability metadata needed for watchlist matching.
func (p *PostgresVulnDataProvider) GetVulnDataForMatching(ctx context.Context, vulnIDs []string) ([]VulnData, error) {
	if len(vulnIDs) == 0 {
		return nil, nil
	}

	// Build a map for results
	dataMap := make(map[string]*VulnData, len(vulnIDs))
	for _, id := range vulnIDs {
		dataMap[id] = &VulnData{ID: id}
	}

	// Fetch summary data (severity, EPSS, ecosystems)
	if err := p.fetchSummaryData(ctx, vulnIDs, dataMap); err != nil {
		return nil, err
	}

	// Fetch product identifiers
	if err := p.fetchIdentifiers(ctx, vulnIDs, dataMap); err != nil {
		return nil, err
	}

	// Convert map to slice
	result := make([]VulnData, 0, len(dataMap))
	for _, vd := range dataMap {
		result = append(result, *vd)
	}
	return result, nil
}

// fetchSummaryData loads vulnerability_summary rows for the given IDs.
func (p *PostgresVulnDataProvider) fetchSummaryData(ctx context.Context, vulnIDs []string, dataMap map[string]*VulnData) error {
	if len(vulnIDs) == 0 {
		return nil
	}

	placeholders := make([]string, len(vulnIDs))
	args := make([]interface{}, len(vulnIDs))
	for i, id := range vulnIDs {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}

	query := fmt.Sprintf(`
		SELECT vulnerability_id, severity_worst, epss_score, ecosystem_list
		FROM vulnerability_summary
		WHERE vulnerability_id IN (%s)`,
		strings.Join(placeholders, ","))

	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("fetch summary data: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var vulnID string
		var severityWorst int
		var epssScore sql.NullFloat64
		var ecosystemList sql.NullString

		if err := rows.Scan(&vulnID, &severityWorst, &epssScore, &ecosystemList); err != nil {
			return fmt.Errorf("scan summary row: %w", err)
		}

		vd, ok := dataMap[vulnID]
		if !ok {
			continue
		}

		vd.SeverityWorst = severityWorst
		if epssScore.Valid {
			vd.EPSSScore = &epssScore.Float64
		}
		if ecosystemList.Valid && ecosystemList.String != "" {
			vd.Ecosystems = splitEcosystems(ecosystemList.String)
		}
	}

	return rows.Err()
}

// fetchIdentifiers loads product_identifiers rows for the given vulnerability IDs.
func (p *PostgresVulnDataProvider) fetchIdentifiers(ctx context.Context, vulnIDs []string, dataMap map[string]*VulnData) error {
	if len(vulnIDs) == 0 {
		return nil
	}

	placeholders := make([]string, len(vulnIDs))
	args := make([]interface{}, len(vulnIDs))
	for i, id := range vulnIDs {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}

	query := fmt.Sprintf(`
		SELECT vulnerability_id, ecosystem, name,
		       purl_type, purl_namespace, purl_name, purl_version,
		       cpe_part, cpe_vendor, cpe_product, cpe_version,
		       cpe_update, cpe_edition, cpe_language,
		       cpe_sw_edition, cpe_target_sw, cpe_target_hw, cpe_other
		FROM product_identifiers
		WHERE vulnerability_id IN (%s)`,
		strings.Join(placeholders, ","))

	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("fetch identifiers: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var vulnID string
		var ecosystem, name sql.NullString
		var purlType, purlNamespace, purlName, purlVersion sql.NullString
		var cpePart, cpeVendor, cpeProduct, cpeVersion sql.NullString
		var cpeUpdate, cpeEdition, cpeLanguage sql.NullString
		var cpeSWEdition, cpeTargetSW, cpeTargetHW, cpeOther sql.NullString

		if err := rows.Scan(
			&vulnID, &ecosystem, &name,
			&purlType, &purlNamespace, &purlName, &purlVersion,
			&cpePart, &cpeVendor, &cpeProduct, &cpeVersion,
			&cpeUpdate, &cpeEdition, &cpeLanguage,
			&cpeSWEdition, &cpeTargetSW, &cpeTargetHW, &cpeOther,
		); err != nil {
			return fmt.Errorf("scan identifier row: %w", err)
		}

		vd, ok := dataMap[vulnID]
		if !ok {
			continue
		}

		ident := VulnIdentifier{
			Ecosystem: nullStr(ecosystem),
			Name:      nullStr(name),
		}

		// Reconstruct purl if purl_type is present
		if purlType.Valid && purlType.String != "" {
			ident.Purl = reconstructPurl(nullStr(purlType), nullStr(purlNamespace), nullStr(purlName), nullStr(purlVersion))
		}

		// Reconstruct CPE if cpe_part is present
		if cpePart.Valid && cpePart.String != "" {
			ident.CPE = reconstructCPE(
				nullStr(cpePart), nullStr(cpeVendor), nullStr(cpeProduct), nullStr(cpeVersion),
				nullStr(cpeUpdate), nullStr(cpeEdition), nullStr(cpeLanguage),
				nullStr(cpeSWEdition), nullStr(cpeTargetSW), nullStr(cpeTargetHW), nullStr(cpeOther),
			)
		}

		vd.Identifiers = append(vd.Identifiers, ident)
	}

	return rows.Err()
}

// nullStr extracts the string value from a sql.NullString, returning empty string if null.
func nullStr(ns sql.NullString) string {
	if ns.Valid {
		return ns.String
	}
	return ""
}

// splitEcosystems splits the comma-separated ecosystem_list string from vulnerability_summary.
func splitEcosystems(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// reconstructPurl builds a purl string from decomposed fields.
func reconstructPurl(purlType, namespace, name, version string) string {
	if purlType == "" || name == "" {
		return ""
	}
	var b strings.Builder
	b.WriteString("pkg:")
	b.WriteString(purlType)
	b.WriteString("/")
	if namespace != "" {
		b.WriteString(namespace)
		b.WriteString("/")
	}
	b.WriteString(name)
	if version != "" {
		b.WriteString("@")
		b.WriteString(version)
	}
	return b.String()
}

// reconstructCPE builds a CPE 2.3 URI from decomposed fields.
func reconstructCPE(part, vendor, product, version, update, edition, language, swEdition, targetSW, targetHW, other string) string {
	cpeField := func(s string) string {
		if s == "" {
			return "*"
		}
		return s
	}
	return "cpe:2.3:" + cpeField(part) + ":" + cpeField(vendor) + ":" + cpeField(product) + ":" +
		cpeField(version) + ":" + cpeField(update) + ":" + cpeField(edition) + ":" +
		cpeField(language) + ":" + cpeField(swEdition) + ":" + cpeField(targetSW) + ":" +
		cpeField(targetHW) + ":" + cpeField(other)
}
