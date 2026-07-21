package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/kato83/mayu/internal/model"
)

// SearchByPackages queries vulnerabilities for multiple packages in a single batch.
// It returns a map keyed by "ecosystem/name" containing matching vulnerabilities
// with full affected data (needed for version range checking in audit).
//
// The query uses product_identifiers to find vulnerability IDs, then fetches
// the full OSV JSON (which includes affected ranges and versions).
func (s *PostgresStore) SearchByPackages(ctx context.Context, packages []PackageQuery) (map[string][]*model.Vulnerability, error) {
	if len(packages) == 0 {
		return make(map[string][]*model.Vulnerability), nil
	}

	// Build the query with OR conditions for each (ecosystem, name) pair.
	// We use a VALUES clause joined against product_identifiers for efficiency.
	//
	// Query structure:
	// SELECT raw_json, vuln_id, severity_worst, pi_ecosystem, pi_name
	// FROM product_identifiers pi
	// JOIN osv_entries oe ON oe.vulnerability_id = pi.vulnerability_id
	// JOIN vulnerability_summary vs ON vs.vulnerability_id = pi.vulnerability_id
	// WHERE (pi.ecosystem, pi.name) IN (VALUES (...))

	var valueClauses []string
	var args []interface{}
	argIdx := 0

	for _, pkg := range packages {
		argIdx++
		ecoArg := argIdx
		argIdx++
		nameArg := argIdx
		valueClauses = append(valueClauses, fmt.Sprintf("($%d, $%d)", ecoArg, nameArg))
		args = append(args, pkg.Ecosystem, pkg.Name)
	}

	query := fmt.Sprintf(`
		SELECT DISTINCT ON (oe.vulnerability_id, oe.osv_id)
			oe.raw_json,
			v.id AS vuln_id,
			vs.severity_worst,
			pi.ecosystem AS pi_ecosystem,
			pi.name AS pi_name
		FROM product_identifiers pi
		JOIN vulnerabilities v ON v.id = pi.vulnerability_id
		LEFT JOIN vulnerability_summary vs ON vs.vulnerability_id = v.id
		LEFT JOIN LATERAL (
			SELECT e.raw_json, e.osv_id, e.vulnerability_id
			FROM osv_entries e
			WHERE e.vulnerability_id = pi.vulnerability_id
			ORDER BY e.osv_id
			LIMIT 1
		) oe ON true
		WHERE (pi.ecosystem, pi.name) IN (VALUES %s)
		ORDER BY oe.vulnerability_id, oe.osv_id`,
		strings.Join(valueClauses, ", "))

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("search by packages: %w", err)
	}
	defer func() { _ = rows.Close() }()

	result := make(map[string][]*model.Vulnerability)

	for rows.Next() {
		var rawJSON []byte
		var vulnID string
		var severityWorst sql.NullInt32
		var piEcosystem, piName string

		if err := rows.Scan(&rawJSON, &vulnID, &severityWorst, &piEcosystem, &piName); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}

		key := piEcosystem + "/" + piName

		if rawJSON != nil {
			vuln, err := model.ParseVulnerability(rawJSON)
			if err != nil {
				// Skip unparseable entries
				continue
			}
			// Override ID with canonical vulnerability_id
			if vulnID != "" && vuln.ID != vulnID {
				vuln.ID = vulnID
			}
			if severityWorst.Valid {
				vuln.SeverityLevel = int(severityWorst.Int32)
			}
			result[key] = append(result[key], vuln)
		} else {
			// No OSV entry — build minimal vulnerability from vulnerabilities table
			vuln := &model.Vulnerability{
				ID: vulnID,
			}
			if severityWorst.Valid {
				vuln.SeverityLevel = int(severityWorst.Int32)
			}
			result[key] = append(result[key], vuln)
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rows: %w", err)
	}

	return result, nil
}
