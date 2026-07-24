package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kato83/mayu/internal/model"

	_ "github.com/jackc/pgx/v5/stdlib" // PostgreSQL driver
)

// PostgresStore implements Store using database/sql with the pgx stdlib driver.
type PostgresStore struct {
	db *sql.DB
}

// NewPostgresStore creates a new PostgresStore connected to the given database URL.
func NewPostgresStore(ctx context.Context, databaseURL string) (*PostgresStore, error) {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return &PostgresStore{db: db}, nil
}

// Close releases the database connection pool.
func (s *PostgresStore) Close() error {
	return s.db.Close()
}

// CleanAll removes all data from all tables. Used for testing only.
func (s *PostgresStore) CleanAll(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM sync_state;
		DELETE FROM alias_sources;
		DELETE FROM vulnerability_aliases;
		DELETE FROM vulnerability_summary;
		DELETE FROM product_identifiers;
		DELETE FROM purl_cpe_mapping;
		DELETE FROM osv_credits;
		DELETE FROM osv_references;
		DELETE FROM osv_severity;
		DELETE FROM osv_affected_ranges;
		DELETE FROM osv_affected_packages;
		DELETE FROM osv_entries;
		DELETE FROM nvd_cpe_matches;
		DELETE FROM nvd_configurations;
		DELETE FROM nvd_references;
		DELETE FROM nvd_weaknesses;
		DELETE FROM nvd_metrics;
		DELETE FROM nvd_descriptions;
		DELETE FROM nvd_entries;
		DELETE FROM vulnerabilities;
	`)
	return err
}

// Insert stores a single vulnerability and all its related data.
func (s *PostgresStore) Insert(ctx context.Context, vuln *model.Vulnerability) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := s.upsertVulnerability(ctx, tx, vuln); err != nil {
		return err
	}

	return tx.Commit()
}

// UpsertBatch stores multiple vulnerabilities in a single transaction.
// It retries automatically on deadlock (PostgreSQL error code 40P01).
func (s *PostgresStore) UpsertBatch(ctx context.Context, vulns []*model.Vulnerability) error {
	const maxRetries = 5

	for attempt := 0; attempt <= maxRetries; attempt++ {
		err := s.upsertBatchOnce(ctx, vulns)
		if err == nil {
			return nil
		}

		// Check if the error is a deadlock (SQLSTATE 40P01)
		if isDeadlock(err) && attempt < maxRetries {
			// Exponential backoff: 10ms, 20ms, 40ms, 80ms, 160ms
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
	return fmt.Errorf("upsert batch: exceeded max retries due to deadlock")
}

// upsertBatchOnce performs a single attempt of UpsertBatch.
func (s *PostgresStore) upsertBatchOnce(ctx context.Context, vulns []*model.Vulnerability) error {
	// Sort entries by canonical vulnerability ID to ensure consistent lock
	// ordering across parallel store workers. This prevents deadlocks where
	// two workers lock the same vulnerabilities rows in different order.
	sort.Slice(vulns, func(i, j int) bool {
		return canonicalID(vulns[i].ID, vulns[i].Aliases) < canonicalID(vulns[j].ID, vulns[j].Aliases)
	})

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, vuln := range vulns {
		if err := s.upsertVulnerability(ctx, tx, vuln); err != nil {
			return fmt.Errorf("upsert %s: %w", vuln.ID, err)
		}
	}

	return tx.Commit()
}

// isDeadlock checks if an error is a PostgreSQL deadlock (SQLSTATE 40P01).
func isDeadlock(err error) bool {
	return err != nil && strings.Contains(err.Error(), "40P01")
}

// extractCVE returns the first CVE alias from the list, or empty string if none found.
func extractCVE(aliases []string) string {
	for _, alias := range aliases {
		if len(alias) > 4 && alias[:4] == "CVE-" {
			return alias
		}
	}
	return ""
}

// canonicalID determines the canonical vulnerability ID for an OSV entry.
// If a CVE alias exists, the CVE is used; otherwise the OSV ID is used as-is.
func canonicalID(osvID string, aliases []string) string {
	if cve := extractCVE(aliases); cve != "" {
		return cve
	}
	return osvID
}

// upsertVulnerability inserts or updates a vulnerability within a transaction.
// It resolves the canonical vulnerability ID (CVE if available) and handles:
//   - Multiple OSV entries pointing to the same CVE (shared vulnerabilities row)
//   - Late CVE assignment (migrating from OSV ID to CVE)
//   - Cleanup of orphaned vulnerabilities rows
//   - osv_id normalization (Debian prefix for bare CVE-* IDs)
//   - alias_sources junction table management
//   - product_identifiers population
//
// This writes to:
//   - vulnerabilities (unified master, keyed by CVE or OSV ID, no source column)
//   - vulnerability_aliases + alias_sources (cross-references with provenance)
//   - osv_entries (OSV-specific data, keyed by normalized osv_id)
//   - osv_affected_packages, osv_affected_ranges, osv_severity, osv_references, osv_credits
//   - product_identifiers (unified package search, source="osv")
func (s *PostgresStore) upsertVulnerability(ctx context.Context, tx *sql.Tx, vuln *model.Vulnerability) error {
	// Determine raw_json: use RawJSON if available, otherwise marshal the struct
	rawJSON := vuln.RawJSON
	if rawJSON == nil {
		var err error
		rawJSON, err = json.Marshal(vuln)
		if err != nil {
			return fmt.Errorf("marshal vulnerability: %w", err)
		}
	}

	// --- osv_id normalization ---
	ecosystem := model.ExtractEcosystemFromAffected(vuln)
	osvID := model.NormalizeOSVID(vuln.ID, ecosystem)
	canID := canonicalID(vuln.ID, vuln.Aliases)

	// --- Step 1: Check if this OSV entry already exists and get its current vulnerability_id ---
	var oldVulnID sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT vulnerability_id FROM osv_entries WHERE osv_id = $1`, osvID).Scan(&oldVulnID)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("lookup existing osv_entry: %w", err)
	}

	// --- Step 2: Handle migration when canonical ID changes (e.g., late CVE assignment) ---
	if oldVulnID.Valid && oldVulnID.String != canID {
		oldID := oldVulnID.String

		// Delete the osv_entry and its children (will be re-created below)
		if _, err := tx.ExecContext(ctx, `DELETE FROM osv_entries WHERE osv_id = $1`, osvID); err != nil {
			return fmt.Errorf("delete old osv_entry for migration: %w", err)
		}

		// Remove alias_sources entries for this osv_id
		if _, err := tx.ExecContext(ctx, `DELETE FROM alias_sources WHERE osv_id = $1`, osvID); err != nil {
			return fmt.Errorf("delete old alias_sources: %w", err)
		}

		// Garbage-collect vulnerability_aliases with no remaining alias_sources
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM vulnerability_aliases va
			WHERE va.vulnerability_id = $1
			AND NOT EXISTS (SELECT 1 FROM alias_sources asrc WHERE asrc.alias_id = va.id)`,
			oldID); err != nil {
			return fmt.Errorf("gc orphaned aliases: %w", err)
		}

		// Check if the old vulnerability has any remaining osv_entries
		var remainingCount int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM osv_entries WHERE vulnerability_id = $1`, oldID).Scan(&remainingCount); err != nil {
			return fmt.Errorf("count remaining osv_entries: %w", err)
		}

		if remainingCount == 0 {
			// CASCADE will clean up vulnerability_aliases, vulnerability_summary, product_identifiers
			if _, err := tx.ExecContext(ctx, `DELETE FROM vulnerabilities WHERE id = $1`, oldID); err != nil {
				return fmt.Errorf("delete orphaned vulnerability: %w", err)
			}
		}
	}
	// When oldVulnID.Valid && oldVulnID.String == canID (same canonical ID),
	// no action is needed here — Step 5 handles it via ON CONFLICT DO UPDATE.

	// --- Step 3: Upsert into unified vulnerabilities table (no source column) ---
	_, err = tx.ExecContext(ctx, `
		INSERT INTO vulnerabilities (id, summary, details, published, modified, withdrawn)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (id) DO UPDATE SET
			summary = COALESCE(NULLIF(EXCLUDED.summary, ''), vulnerabilities.summary),
			details = COALESCE(NULLIF(EXCLUDED.details, ''), vulnerabilities.details),
			published = COALESCE(EXCLUDED.published, vulnerabilities.published),
			modified = GREATEST(EXCLUDED.modified, vulnerabilities.modified),
			withdrawn = EXCLUDED.withdrawn`,
		canID,
		nullIfEmpty(vuln.Summary),
		nullIfEmpty(vuln.Details),
		vuln.Published,
		vuln.Modified,
		vuln.Withdrawn,
	)
	if err != nil {
		return fmt.Errorf("upsert vulnerability: %w", err)
	}

	// --- Step 4: Upsert osv_entry (must be before alias_sources due to FK) ---
	// Delete child tables first (they will be re-created below).
	for _, childTable := range []string{"osv_severity", "osv_affected_packages", "osv_references", "osv_credits"} {
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+childTable+` WHERE osv_entry_id = $1`, osvID); err != nil {
			return fmt.Errorf("delete %s before upsert: %w", childTable, err)
		}
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO osv_entries (osv_id, vulnerability_id, schema_version, raw_json, database_specific)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (osv_id) DO UPDATE SET
			vulnerability_id = EXCLUDED.vulnerability_id,
			schema_version = EXCLUDED.schema_version,
			raw_json = EXCLUDED.raw_json,
			database_specific = EXCLUDED.database_specific`,
		osvID,
		canID,
		nullIfEmpty(vuln.SchemaVersion),
		rawJSON,
		nullableRawJSON(vuln.DatabaseSpecific),
	)
	if err != nil {
		return fmt.Errorf("upsert osv_entry: %w", err)
	}

	// --- Step 5: Upsert aliases using alias_sources junction table ---
	allAliases := make([]string, 0, len(vuln.Aliases)+2)
	if canID != osvID {
		allAliases = append(allAliases, osvID)
	}
	if vuln.ID != osvID && vuln.ID != canID {
		allAliases = append(allAliases, vuln.ID)
	}
	allAliases = append(allAliases, vuln.Aliases...)

	// Remove old alias_sources for this osv_id
	if _, err := tx.ExecContext(ctx, `DELETE FROM alias_sources WHERE osv_id = $1`, osvID); err != nil {
		return fmt.Errorf("delete alias_sources for osv_id: %w", err)
	}

	// Upsert each alias and link via alias_sources
	for _, alias := range allAliases {
		var aliasID int64
		err := tx.QueryRowContext(ctx, `
			INSERT INTO vulnerability_aliases (vulnerability_id, alias)
			VALUES ($1, $2)
			ON CONFLICT (vulnerability_id, alias) DO UPDATE SET alias = EXCLUDED.alias
			RETURNING id`,
			canID, alias).Scan(&aliasID)
		if err != nil {
			return fmt.Errorf("upsert alias %q: %w", alias, err)
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO alias_sources (alias_id, osv_id)
			VALUES ($1, $2)
			ON CONFLICT (alias_id, osv_id) DO NOTHING`,
			aliasID, osvID)
		if err != nil {
			return fmt.Errorf("insert alias_source for %q: %w", alias, err)
		}
	}

	// Garbage-collect vulnerability_aliases with no remaining alias_sources
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM vulnerability_aliases va
		WHERE va.vulnerability_id = $1
		AND NOT EXISTS (SELECT 1 FROM alias_sources asrc WHERE asrc.alias_id = va.id)`,
		canID); err != nil {
		return fmt.Errorf("gc orphaned aliases for %s: %w", canID, err)
	}

	// --- Step 6: Insert top-level severity (bulk) ---
	if len(vuln.Severity) > 0 {
		sevQuery := "INSERT INTO osv_severity (osv_entry_id, affected_package_id, severity_type, score, source) VALUES "
		sevArgs := make([]interface{}, 0, len(vuln.Severity)*3+1)
		sevArgs = append(sevArgs, osvID)
		for i, sev := range vuln.Severity {
			if i > 0 {
				sevQuery += ", "
			}
			base := i*3 + 2 // $1 is osvID, then groups of 3
			sevQuery += fmt.Sprintf("($1, NULL, $%d, $%d, $%d)", base, base+1, base+2)
			sevArgs = append(sevArgs, string(sev.Type), sev.Score, nullIfEmpty(sev.Source))
		}
		if _, err := tx.ExecContext(ctx, sevQuery, sevArgs...); err != nil {
			return fmt.Errorf("insert severity: %w", err)
		}
	}

	// --- Step 7: Insert affected packages + product_identifiers ---
	// Delete existing product_identifiers for this specific OSV entry only (not all entries for the CVE).
	// This prevents data loss when multiple OSV entries share the same canonical vulnerability ID.
	if _, err := tx.ExecContext(ctx, `DELETE FROM product_identifiers WHERE vulnerability_id = $1 AND source = 'osv' AND osv_entry_id = $2`, canID, osvID); err != nil {
		return fmt.Errorf("delete product_identifiers: %w", err)
	}

	for _, affected := range vuln.Affected {
		var affectedPkgID int64
		err := tx.QueryRowContext(ctx, `
			INSERT INTO osv_affected_packages (osv_entry_id, ecosystem, name, purl, versions, ecosystem_specific, database_specific)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			RETURNING id`,
			osvID,
			affected.Package.Ecosystem,
			affected.Package.Name,
			nullIfEmpty(affected.Package.Purl),
			pgTextArray(affected.Versions),
			nullableRawJSON(affected.EcosystemSpecific),
			nullableRawJSON(affected.DatabaseSpecific),
		).Scan(&affectedPkgID)
		if err != nil {
			return fmt.Errorf("insert osv_affected_package: %w", err)
		}

		// Insert into product_identifiers (purl decomposed)
		if err := s.insertOSVProductIdentifier(ctx, tx, canID, osvID, &affected); err != nil {
			return fmt.Errorf("insert product_identifier: %w", err)
		}

		// Insert ranges (bulk)
		if len(affected.Ranges) > 0 {
			rangeQuery := "INSERT INTO osv_affected_ranges (affected_package_id, range_type, repo, events, database_specific) VALUES "
			rangeArgs := make([]interface{}, 0, len(affected.Ranges)*4+1)
			rangeArgs = append(rangeArgs, affectedPkgID)
			for i, r := range affected.Ranges {
				if i > 0 {
					rangeQuery += ", "
				}
				eventsJSON, err := json.Marshal(r.Events)
				if err != nil {
					return fmt.Errorf("marshal events: %w", err)
				}
				base := i*4 + 2
				rangeQuery += fmt.Sprintf("($1, $%d, $%d, $%d, $%d)", base, base+1, base+2, base+3)
				rangeArgs = append(rangeArgs, string(r.Type), nullIfEmpty(r.Repo), eventsJSON, nullableRawJSON(r.DatabaseSpecific))
			}
			if _, err := tx.ExecContext(ctx, rangeQuery, rangeArgs...); err != nil {
				return fmt.Errorf("insert osv_affected_range: %w", err)
			}
		}

		// Insert per-affected severity (bulk)
		if len(affected.Severity) > 0 {
			sevQuery := "INSERT INTO osv_severity (osv_entry_id, affected_package_id, severity_type, score, source) VALUES "
			sevArgs := make([]interface{}, 0, len(affected.Severity)*3+2)
			sevArgs = append(sevArgs, osvID, affectedPkgID)
			for i, sev := range affected.Severity {
				if i > 0 {
					sevQuery += ", "
				}
				base := i*3 + 3
				sevQuery += fmt.Sprintf("($1, $2, $%d, $%d, $%d)", base, base+1, base+2)
				sevArgs = append(sevArgs, string(sev.Type), sev.Score, nullIfEmpty(sev.Source))
			}
			if _, err := tx.ExecContext(ctx, sevQuery, sevArgs...); err != nil {
				return fmt.Errorf("insert affected severity: %w", err)
			}
		}
	}

	// --- Step 8: Insert references (bulk) ---
	if len(vuln.References) > 0 {
		refQuery := "INSERT INTO osv_references (osv_entry_id, reference_type, url) VALUES "
		refArgs := make([]interface{}, 0, len(vuln.References)*2+1)
		refArgs = append(refArgs, osvID)
		for i, ref := range vuln.References {
			if i > 0 {
				refQuery += ", "
			}
			base := i*2 + 2
			refQuery += fmt.Sprintf("($1, $%d, $%d)", base, base+1)
			refArgs = append(refArgs, string(ref.Type), ref.URL)
		}
		if _, err := tx.ExecContext(ctx, refQuery, refArgs...); err != nil {
			return fmt.Errorf("insert osv_reference: %w", err)
		}
	}

	// --- Step 9: Insert credits (bulk) ---
	if len(vuln.Credits) > 0 {
		credQuery := "INSERT INTO osv_credits (osv_entry_id, name, contact, credit_type) VALUES "
		credArgs := make([]interface{}, 0, len(vuln.Credits)*3+1)
		credArgs = append(credArgs, osvID)
		for i, credit := range vuln.Credits {
			if i > 0 {
				credQuery += ", "
			}
			base := i*3 + 2
			credQuery += fmt.Sprintf("($1, $%d, $%d, $%d)", base, base+1, base+2)
			credArgs = append(credArgs, credit.Name, pgTextArray(credit.Contact), nullIfEmpty(string(credit.Type)))
		}
		if _, err := tx.ExecContext(ctx, credQuery, credArgs...); err != nil {
			return fmt.Errorf("insert osv_credit: %w", err)
		}
	}

	return nil
}

// GetByID retrieves a single vulnerability by its OSV ID.
func (s *PostgresStore) GetByID(ctx context.Context, id string) (*model.Vulnerability, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT oe.raw_json FROM osv_entries oe WHERE oe.osv_id = $1`, id)

	var rawJSON []byte
	if err := row.Scan(&rawJSON); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("query vulnerability: %w", err)
	}

	vuln, err := model.ParseVulnerability(rawJSON)
	if err != nil {
		return nil, fmt.Errorf("parse vulnerability: %w", err)
	}
	return vuln, nil
}

// buildSearchConditions constructs the WHERE clause and arguments for a SearchQuery.
// Uses vulnerability_summary for severity/KEV filtering and product_identifiers for
// package/ecosystem/purl/cpe filtering. No more correlated subqueries.
func (s *PostgresStore) buildSearchConditions(query SearchQuery) (baseQuery string, args []interface{}, argIdx int) {
	switch {
	case query.ID != "":
		// Match by vulnerabilities.id OR vulnerability_aliases.alias
		argIdx++
		baseQuery = `SELECT oe.raw_json, v.id, v.summary, v.details, v.published, v.modified, oe.osv_id,
		       vs.severity_worst
		FROM vulnerabilities v
		LEFT JOIN vulnerability_summary vs ON vs.vulnerability_id = v.id
		LEFT JOIN LATERAL (
			SELECT e.raw_json, e.osv_id FROM osv_entries e WHERE e.vulnerability_id = v.id ORDER BY e.osv_id LIMIT 1
		) oe ON true
		WHERE (v.id = $` + fmt.Sprint(argIdx) + `
			OR v.id IN (SELECT va.vulnerability_id FROM vulnerability_aliases va WHERE va.alias = $` + fmt.Sprint(argIdx) + `)
		) AND 1=1`
		args = append(args, query.ID)

	case query.Purl != "":
		// Search by purl (decompose and match on product_identifiers)
		argIdx++
		baseQuery = `SELECT oe.raw_json, v.id, v.summary, v.details, v.published, v.modified, oe.osv_id,
		       vs.severity_worst
		FROM vulnerabilities v
		LEFT JOIN vulnerability_summary vs ON vs.vulnerability_id = v.id
		LEFT JOIN LATERAL (
			SELECT e.raw_json, e.osv_id FROM osv_entries e WHERE e.vulnerability_id = v.id ORDER BY e.osv_id LIMIT 1
		) oe ON true
		WHERE v.id IN (
			SELECT pi.vulnerability_id FROM product_identifiers pi
			WHERE pi.purl_type || '/' || COALESCE(pi.purl_namespace || '/', '') || pi.purl_name = $` + fmt.Sprint(argIdx) + `
		) AND 1=1`
		// Extract type/namespace/name from the purl for matching
		// The caller provides just "pkg:type/ns/name" or "type/ns/name" - we match the reconstructed form
		purlMatch := strings.TrimPrefix(query.Purl, "pkg:")
		// Remove version/qualifiers/subpath if present
		if idx := strings.IndexByte(purlMatch, '@'); idx >= 0 {
			purlMatch = purlMatch[:idx]
		}
		if idx := strings.IndexByte(purlMatch, '?'); idx >= 0 {
			purlMatch = purlMatch[:idx]
		}
		args = append(args, purlMatch)

	case query.CPE != "":
		// Search by CPE vendor+product (decompose from cpe:2.3:part:vendor:product:...)
		cpeFields := model.ParseCPE23(query.CPE)
		if cpeFields != nil && cpeFields.Vendor != "*" && cpeFields.Product != "*" {
			argIdx++
			vendorArg := argIdx
			argIdx++
			productArg := argIdx
			baseQuery = `SELECT oe.raw_json, v.id, v.summary, v.details, v.published, v.modified, oe.osv_id,
			       vs.severity_worst
			FROM vulnerabilities v
			LEFT JOIN vulnerability_summary vs ON vs.vulnerability_id = v.id
			LEFT JOIN LATERAL (
				SELECT e.raw_json, e.osv_id FROM osv_entries e WHERE e.vulnerability_id = v.id ORDER BY e.osv_id LIMIT 1
			) oe ON true
			WHERE v.id IN (
				SELECT pi.vulnerability_id FROM product_identifiers pi
				WHERE pi.cpe_vendor = $` + fmt.Sprint(vendorArg) + ` AND pi.cpe_product = $` + fmt.Sprint(productArg) + `
			) AND 1=1`
			args = append(args, cpeFields.Vendor, cpeFields.Product)
		} else {
			// Fallback: treat as text prefix match on reconstructed CPE
			argIdx++
			baseQuery = `SELECT oe.raw_json, v.id, v.summary, v.details, v.published, v.modified, oe.osv_id,
			       vs.severity_worst
			FROM vulnerabilities v
			LEFT JOIN vulnerability_summary vs ON vs.vulnerability_id = v.id
			LEFT JOIN LATERAL (
				SELECT e.raw_json, e.osv_id FROM osv_entries e WHERE e.vulnerability_id = v.id ORDER BY e.osv_id LIMIT 1
			) oe ON true
			WHERE v.id IN (
				SELECT pi.vulnerability_id FROM product_identifiers pi
				WHERE pi.cpe_vendor IS NOT NULL
			) AND 1=1`
			args = append(args, query.CPE)
		}

	case query.PackageName != "" || query.Ecosystem != "":
		// Use product_identifiers for cross-source package search
		innerWhere := `1=1`
		if query.Ecosystem != "" {
			argIdx++
			innerWhere += fmt.Sprintf(` AND pi.ecosystem = $%d`, argIdx)
			args = append(args, query.Ecosystem)
		}
		if query.PackageName != "" {
			argIdx++
			innerWhere += fmt.Sprintf(` AND pi.name = $%d`, argIdx)
			args = append(args, query.PackageName)
		}
		baseQuery = fmt.Sprintf(`SELECT oe.raw_json, v.id, v.summary, v.details, v.published, v.modified, oe.osv_id,
		       vs.severity_worst
		FROM vulnerabilities v
		LEFT JOIN vulnerability_summary vs ON vs.vulnerability_id = v.id
		LEFT JOIN LATERAL (
			SELECT e.raw_json, e.osv_id FROM osv_entries e WHERE e.vulnerability_id = v.id ORDER BY e.osv_id LIMIT 1
		) oe ON true
		WHERE v.id IN (
			SELECT DISTINCT pi.vulnerability_id FROM product_identifiers pi WHERE %s
		) AND 1=1`, innerWhere)

	default:
		baseQuery = `SELECT oe.raw_json, v.id, v.summary, v.details, v.published, v.modified, oe.osv_id,
		       vs.severity_worst
		FROM vulnerabilities v
		LEFT JOIN vulnerability_summary vs ON vs.vulnerability_id = v.id
		LEFT JOIN LATERAL (
			SELECT e.raw_json, e.osv_id FROM osv_entries e WHERE e.vulnerability_id = v.id ORDER BY e.osv_id LIMIT 1
		) oe ON true
		WHERE 1=1`
	}

	// --- Additional filters using vulnerability_summary ---

	// Severity filter: uses normalized 5-level scale range overlap
	// A vulnerability matches if its severity range [severity_best, severity_worst]
	// includes the requested level. This means:
	// severity_worst >= level AND severity_best <= level
	// Special case: "unknown" matches vulnerabilities with no severity data (NULL).
	if query.Severity != "" {
		if strings.EqualFold(query.Severity, "unknown") {
			baseQuery += ` AND vs.severity_worst IS NULL`
		} else {
			sevLevel := severityToLevel(query.Severity)
			if sevLevel > 0 {
				argIdx++
				baseQuery += fmt.Sprintf(` AND severity_worst >= $%d`, argIdx)
				args = append(args, sevLevel)
				argIdx++
				baseQuery += fmt.Sprintf(` AND COALESCE(severity_best, severity_worst) <= $%d`, argIdx)
				args = append(args, sevLevel)
			}
		}
	}

	// KEV filter
	if query.InKEV != nil && *query.InKEV {
		baseQuery += ` AND vs.in_kev = true`
	}

	// Since filter (modified date)
	if query.Since != "" {
		argIdx++
		baseQuery += fmt.Sprintf(` AND modified >= $%d`, argIdx)
		args = append(args, query.Since)
	}

	// Version filter (check if version appears in affected versions list)
	if query.Version != "" {
		argIdx++
		baseQuery += fmt.Sprintf(` AND osv_id IN (
			SELECT ap2.osv_entry_id FROM osv_affected_packages ap2
			WHERE $%d = ANY(ap2.versions))`, argIdx)
		args = append(args, query.Version)
	}

	return baseQuery, args, argIdx
}

// severityToLevel maps a severity label to the normalized 5-level value.
func severityToLevel(level string) int {
	switch strings.ToLower(level) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "none":
		return 1
	default:
		return -1
	}
}

// Search finds vulnerabilities matching the given query parameters.
func (s *PostgresStore) Search(ctx context.Context, query SearchQuery) ([]*model.Vulnerability, error) {
	// Use lightweight query path when fields are specified (avoids raw_json fetch)
	if len(query.Fields) > 0 {
		return s.searchLight(ctx, query)
	}

	limit := query.Limit
	if limit <= 0 {
		limit = 100
	}
	offset := query.Offset
	if offset < 0 {
		offset = 0
	}

	baseQuery, args, argIdx := s.buildSearchConditions(query)

	// Apply cursor-based or offset-based pagination
	if query.Cursor != "" {
		cursor, err := DecodeCursor(query.Cursor)
		if err != nil {
			return nil, fmt.Errorf("invalid cursor: %w", err)
		}
		// Keyset condition: (published, id) < (cursor.published, cursor.id)
		// For DESC order: find rows that sort AFTER the cursor position
		if cursor.Published != nil {
			argIdx++
			pubArg := argIdx
			argIdx++
			idArg := argIdx
			baseQuery += fmt.Sprintf(` AND (published < $%d OR (published = $%d AND v.id < $%d) OR (published IS NULL))`,
				pubArg, pubArg, idArg)
			args = append(args, cursor.Published.UTC(), cursor.ID)
		} else {
			// Cursor item had NULL published; only items with NULL published AND id < cursor.id come after
			argIdx++
			baseQuery += fmt.Sprintf(` AND (published IS NULL AND v.id < $%d)`, argIdx)
			args = append(args, cursor.ID)
		}
	}

	argIdx++
	baseQuery += fmt.Sprintf(` ORDER BY published DESC NULLS LAST, v.id DESC LIMIT $%d`, argIdx)
	args = append(args, limit)

	// Apply offset only when no cursor is set (backward compatibility)
	if query.Cursor == "" && offset > 0 {
		argIdx++
		baseQuery += fmt.Sprintf(` OFFSET $%d`, argIdx)
		args = append(args, offset)
	}

	rows, err := s.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("query vulnerabilities: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var results []*model.Vulnerability
	for rows.Next() {
		var rawJSON []byte
		var vulnID string
		var summary, details sql.NullString
		var published, modified sql.NullTime
		var osvID sql.NullString
		var severityWorst sql.NullInt32
		if err := rows.Scan(&rawJSON, &vulnID, &summary, &details, &published, &modified, &osvID, &severityWorst); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		if rawJSON != nil {
			vuln, err := model.ParseVulnerability(rawJSON)
			if err != nil {
				return nil, fmt.Errorf("parse vulnerability: %w", err)
			}
			// Override ID with the canonical vulnerability ID (e.g., CVE-xxx)
			if vulnID != "" && vuln.ID != vulnID {
				vuln.ID = vulnID
				if vuln.RawJSON != nil {
					vuln.RawJSON = replaceJSONField(vuln.RawJSON, "id", vulnID)
				}
			}
			if severityWorst.Valid {
				vuln.SeverityLevel = int(severityWorst.Int32)
			}
			results = append(results, vuln)
		} else {
			// Fallback: build minimal Vulnerability from vulnerabilities table
			vuln := &model.Vulnerability{
				ID:      vulnID,
				Summary: summary.String,
				Details: details.String,
			}
			if modified.Valid {
				vuln.Modified = modified.Time
			}
			if published.Valid {
				vuln.Published = &published.Time
			}
			if severityWorst.Valid {
				vuln.SeverityLevel = int(severityWorst.Int32)
			}
			results = append(results, vuln)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}

	return results, nil
}

// Count returns the number of vulnerabilities matching the given query parameters.
// It uses buildCountConditions which avoids the expensive LATERAL JOIN on osv_entries
// that is only needed for fetching display data (raw_json), not for counting rows.
func (s *PostgresStore) Count(ctx context.Context, query SearchQuery) (int64, error) {
	countQuery, args := s.buildCountConditions(query)

	var count int64
	if err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("count vulnerabilities: %w", err)
	}
	return count, nil
}

// buildCountConditions builds a COUNT query without the expensive LATERAL JOIN on osv_entries.
// It mirrors the WHERE conditions from buildSearchConditions but uses a lightweight SELECT.
func (s *PostgresStore) buildCountConditions(query SearchQuery) (string, []interface{}) {
	var args []interface{}
	var argIdx int

	baseFrom := `FROM vulnerabilities v
		LEFT JOIN vulnerability_summary vs ON vs.vulnerability_id = v.id`
	where := `WHERE 1=1`

	switch {
	case query.ID != "":
		argIdx++
		where = fmt.Sprintf(`WHERE (v.id = $%d
			OR v.id IN (SELECT va.vulnerability_id FROM vulnerability_aliases va WHERE va.alias = $%d)
		)`, argIdx, argIdx)
		args = append(args, query.ID)

	case query.Purl != "":
		argIdx++
		purlMatch := strings.TrimPrefix(query.Purl, "pkg:")
		if idx := strings.IndexByte(purlMatch, '@'); idx >= 0 {
			purlMatch = purlMatch[:idx]
		}
		if idx := strings.IndexByte(purlMatch, '?'); idx >= 0 {
			purlMatch = purlMatch[:idx]
		}
		where = fmt.Sprintf(`WHERE v.id IN (
			SELECT pi.vulnerability_id FROM product_identifiers pi
			WHERE pi.purl_type || '/' || COALESCE(pi.purl_namespace || '/', '') || pi.purl_name = $%d
		)`, argIdx)
		args = append(args, purlMatch)

	case query.CPE != "":
		cpeFields := model.ParseCPE23(query.CPE)
		if cpeFields != nil && cpeFields.Vendor != "*" && cpeFields.Product != "*" {
			argIdx++
			vendorArg := argIdx
			argIdx++
			productArg := argIdx
			where = fmt.Sprintf(`WHERE v.id IN (
				SELECT pi.vulnerability_id FROM product_identifiers pi
				WHERE pi.cpe_vendor = $%d AND pi.cpe_product = $%d
			)`, vendorArg, productArg)
			args = append(args, cpeFields.Vendor, cpeFields.Product)
		}

	case query.PackageName != "" || query.Ecosystem != "":
		innerWhere := `1=1`
		if query.Ecosystem != "" {
			argIdx++
			innerWhere += fmt.Sprintf(` AND pi.ecosystem = $%d`, argIdx)
			args = append(args, query.Ecosystem)
		}
		if query.PackageName != "" {
			argIdx++
			innerWhere += fmt.Sprintf(` AND pi.name = $%d`, argIdx)
			args = append(args, query.PackageName)
		}
		where = fmt.Sprintf(`WHERE v.id IN (
			SELECT DISTINCT pi.vulnerability_id FROM product_identifiers pi WHERE %s
		)`, innerWhere)
	}

	// Severity filter
	if query.Severity != "" {
		if strings.EqualFold(query.Severity, "unknown") {
			where += ` AND vs.severity_worst IS NULL`
		} else {
			sevLevel := severityToLevel(query.Severity)
			if sevLevel > 0 {
				argIdx++
				where += fmt.Sprintf(` AND vs.severity_worst >= $%d`, argIdx)
				args = append(args, sevLevel)
				argIdx++
				where += fmt.Sprintf(` AND COALESCE(vs.severity_best, vs.severity_worst) <= $%d`, argIdx)
				args = append(args, sevLevel)
			}
		}
	}

	// KEV filter
	if query.InKEV != nil && *query.InKEV {
		where += ` AND vs.in_kev = true`
	}

	// Since filter
	if query.Since != "" {
		argIdx++
		where += fmt.Sprintf(` AND v.modified >= $%d`, argIdx)
		args = append(args, query.Since)
	}

	// Version filter
	if query.Version != "" {
		argIdx++
		where += fmt.Sprintf(` AND v.id IN (
			SELECT oe.vulnerability_id FROM osv_entries oe
			JOIN osv_affected_packages ap ON ap.osv_entry_id = oe.osv_id
			WHERE $%d = ANY(ap.versions))`, argIdx)
		args = append(args, query.Version)
	}

	return fmt.Sprintf(`SELECT COUNT(*) %s %s`, baseFrom, where), args
}

// GetSyncState retrieves the sync state for a given source.
func (s *PostgresStore) GetSyncState(ctx context.Context, source string) (*SyncState, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT source, source_type, last_modified_at, last_synced_at, record_count FROM sync_state WHERE source = $1`,
		source,
	)

	var state SyncState
	var lastModified time.Time
	var lastSynced time.Time
	if err := row.Scan(&state.Source, &state.SourceType, &lastModified, &lastSynced, &state.RecordCount); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("query sync_state: %w", err)
	}
	state.LastModifiedAt = lastModified.Format(time.RFC3339Nano)
	state.LastSyncedAt = lastSynced.Format(time.RFC3339Nano)
	return &state, nil
}

// UpdateSyncState creates or updates the sync state for a source.
func (s *PostgresStore) UpdateSyncState(ctx context.Context, state *SyncState) error {
	lastModified, err := time.Parse(time.RFC3339Nano, state.LastModifiedAt)
	if err != nil {
		// Fall back to RFC3339 for backward compatibility with existing data
		lastModified, err = time.Parse(time.RFC3339, state.LastModifiedAt)
		if err != nil {
			return fmt.Errorf("parse last_modified_at: %w", err)
		}
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO sync_state (source, source_type, last_modified_at, record_count)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (source) DO UPDATE SET
			source_type = EXCLUDED.source_type,
			last_modified_at = EXCLUDED.last_modified_at,
			last_synced_at = NOW(),
			record_count = EXCLUDED.record_count`,
		state.Source, state.SourceType, lastModified, state.RecordCount,
	)
	if err != nil {
		return fmt.Errorf("upsert sync_state: %w", err)
	}
	return nil
}

// ListSyncStates returns all sync state records ordered by source_type and source.
func (s *PostgresStore) ListSyncStates(ctx context.Context) ([]SyncState, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT source, source_type, last_modified_at, last_synced_at, record_count
		FROM sync_state ORDER BY source_type, source`)
	if err != nil {
		return nil, fmt.Errorf("query sync_states: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var states []SyncState
	for rows.Next() {
		var state SyncState
		var lastModified, lastSynced time.Time
		if err := rows.Scan(&state.Source, &state.SourceType, &lastModified, &lastSynced, &state.RecordCount); err != nil {
			return nil, fmt.Errorf("scan sync_state: %w", err)
		}
		state.LastModifiedAt = lastModified.Format(time.RFC3339Nano)
		state.LastSyncedAt = lastSynced.Format(time.RFC3339Nano)
		states = append(states, state)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sync_states: %w", err)
	}
	return states, nil
}

// --- Helper functions ---

// nullIfEmpty returns nil if the string is empty, otherwise returns the string.
func nullIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// nullableRawJSON returns nil if the json.RawMessage is nil or empty.
func nullableRawJSON(data json.RawMessage) interface{} {
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	return []byte(data)
}

// pgTextArray converts a Go string slice for use as a PostgreSQL TEXT[] parameter.
// pgx stdlib natively supports []string → TEXT[] conversion, so we pass it directly.
// Returns nil for empty/nil slices (stored as NULL in PostgreSQL).
func pgTextArray(ss []string) interface{} {
	if len(ss) == 0 {
		return nil
	}
	return ss
}

// replaceJSONField replaces a top-level string field in a JSON object.
// If the field is not found or the JSON is malformed, returns the original data unchanged.
func replaceJSONField(data json.RawMessage, field, newValue string) json.RawMessage {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil {
		return data
	}
	quotedValue, err := json.Marshal(newValue)
	if err != nil {
		return data
	}
	obj[field] = quotedValue
	result, err := json.Marshal(obj)
	if err != nil {
		return data
	}
	return result
}

// insertOSVProductIdentifier inserts a product_identifiers row for an OSV affected package.
// It decomposes the purl string into individual fields for efficient querying.
func (s *PostgresStore) insertOSVProductIdentifier(ctx context.Context, tx *sql.Tx, vulnID string, osvEntryID string, affected *model.Affected) error {
	pi := &model.ProductIdentifier{
		VulnerabilityID: vulnID,
		Source:          "osv",
		Ecosystem:       affected.Package.Ecosystem,
		Name:            affected.Package.Name,
	}

	// Decompose purl if available
	if affected.Package.Purl != "" {
		parsePurlIntoPI(affected.Package.Purl, pi)
	}

	// Build version_constraint from ranges
	if len(affected.Ranges) > 0 {
		vc, _ := json.Marshal(affected.Ranges)
		pi.VersionConstraint = vc
	}

	_, err := tx.ExecContext(ctx, `
		INSERT INTO product_identifiers (
			vulnerability_id, source, osv_entry_id,
			purl_type, purl_namespace, purl_name, purl_version, purl_qualifiers, purl_subpath,
			cpe_part, cpe_vendor, cpe_product, cpe_version, cpe_update, cpe_edition,
			cpe_language, cpe_sw_edition, cpe_target_sw, cpe_target_hw, cpe_other,
			ecosystem, name, vendor, product, version_constraint
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25)`,
		pi.VulnerabilityID, pi.Source, osvEntryID,
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

// parsePurlIntoPI parses a purl string and populates ProductIdentifier fields.
// Lightweight parser: pkg:type/namespace/name@version?qualifiers#subpath
func parsePurlIntoPI(purlStr string, pi *model.ProductIdentifier) {
	if !strings.HasPrefix(purlStr, "pkg:") {
		return
	}
	remainder := purlStr[4:]

	// Extract subpath
	if idx := strings.IndexByte(remainder, '#'); idx >= 0 {
		pi.PurlSubpath = remainder[idx+1:]
		remainder = remainder[:idx]
	}
	// Extract qualifiers
	if idx := strings.IndexByte(remainder, '?'); idx >= 0 {
		pi.PurlQualifiers = remainder[idx+1:]
		remainder = remainder[:idx]
	}
	// Extract version
	if idx := strings.IndexByte(remainder, '@'); idx >= 0 {
		pi.PurlVersion = remainder[idx+1:]
		remainder = remainder[:idx]
	}
	// Extract type
	if idx := strings.IndexByte(remainder, '/'); idx >= 0 {
		pi.PurlType = remainder[:idx]
		remainder = remainder[idx+1:]
	} else {
		pi.PurlType = remainder
		return
	}
	// Remaining is namespace/name or just name
	if idx := strings.LastIndexByte(remainder, '/'); idx >= 0 {
		pi.PurlNamespace = remainder[:idx]
		pi.PurlName = remainder[idx+1:]
	} else {
		pi.PurlName = remainder
	}
}

// searchLight performs a lightweight search that avoids fetching raw_json from osv_entries.
// It uses vulnerability_summary for severity/scores and product_identifiers for ecosystem.
// This is significantly faster for list views where only a subset of fields is needed.
func (s *PostgresStore) searchLight(ctx context.Context, query SearchQuery) ([]*model.Vulnerability, error) {
	limit := query.Limit
	if limit <= 0 {
		limit = 100
	}
	offset := query.Offset
	if offset < 0 {
		offset = 0
	}

	// Determine which fields are requested
	fieldSet := make(map[string]bool, len(query.Fields))
	for _, f := range query.Fields {
		fieldSet[strings.ToLower(f)] = true
	}

	needSeverity := fieldSet["severity"]
	needEcosystem := fieldSet["ecosystem"]

	// Build query using vulnerability_summary
	var baseQuery string
	var args []interface{}
	var argIdx int

	switch {
	case query.ID != "":
		argIdx++
		baseQuery = fmt.Sprintf(`SELECT v.id, v.summary, v.modified, v.published,
			vs.severity_worst, vs.severity_best, vs.scores_detail, vs.ecosystem_list
		FROM vulnerabilities v
		LEFT JOIN vulnerability_summary vs ON vs.vulnerability_id = v.id
		WHERE (v.id = $%d OR v.id IN (
			SELECT va.vulnerability_id FROM vulnerability_aliases va WHERE va.alias = $%d
		))`, argIdx, argIdx)
		args = append(args, query.ID)

	case query.Purl != "":
		argIdx++
		purlMatch := strings.TrimPrefix(query.Purl, "pkg:")
		if idx := strings.IndexByte(purlMatch, '@'); idx >= 0 {
			purlMatch = purlMatch[:idx]
		}
		baseQuery = fmt.Sprintf(`SELECT v.id, v.summary, v.modified, v.published,
			vs.severity_worst, vs.severity_best, vs.scores_detail, vs.ecosystem_list
		FROM vulnerabilities v
		LEFT JOIN vulnerability_summary vs ON vs.vulnerability_id = v.id
		WHERE v.id IN (
			SELECT pi.vulnerability_id FROM product_identifiers pi
			WHERE pi.purl_type || '/' || COALESCE(pi.purl_namespace || '/', '') || pi.purl_name = $%d
		)`, argIdx)
		args = append(args, purlMatch)

	case query.CPE != "":
		cpeFields := model.ParseCPE23(query.CPE)
		if cpeFields != nil && cpeFields.Vendor != "*" && cpeFields.Product != "*" {
			argIdx++
			vendorArg := argIdx
			argIdx++
			productArg := argIdx
			baseQuery = fmt.Sprintf(`SELECT v.id, v.summary, v.modified, v.published,
				vs.severity_worst, vs.severity_best, vs.scores_detail, vs.ecosystem_list
			FROM vulnerabilities v
			LEFT JOIN vulnerability_summary vs ON vs.vulnerability_id = v.id
			WHERE v.id IN (
				SELECT pi.vulnerability_id FROM product_identifiers pi
				WHERE pi.cpe_vendor = $%d AND pi.cpe_product = $%d
			)`, vendorArg, productArg)
			args = append(args, cpeFields.Vendor, cpeFields.Product)
		} else {
			baseQuery = `SELECT v.id, v.summary, v.modified, v.published,
				vs.severity_worst, vs.severity_best, vs.scores_detail, vs.ecosystem_list
			FROM vulnerabilities v
			LEFT JOIN vulnerability_summary vs ON vs.vulnerability_id = v.id
			WHERE 1=1`
		}

	case query.PackageName != "" || query.Ecosystem != "":
		innerWhere := `1=1`
		if query.Ecosystem != "" {
			argIdx++
			innerWhere += fmt.Sprintf(` AND pi.ecosystem = $%d`, argIdx)
			args = append(args, query.Ecosystem)
		}
		if query.PackageName != "" {
			argIdx++
			innerWhere += fmt.Sprintf(` AND pi.name = $%d`, argIdx)
			args = append(args, query.PackageName)
		}
		baseQuery = fmt.Sprintf(`SELECT v.id, v.summary, v.modified, v.published,
			vs.severity_worst, vs.severity_best, vs.scores_detail, vs.ecosystem_list
		FROM vulnerabilities v
		LEFT JOIN vulnerability_summary vs ON vs.vulnerability_id = v.id
		WHERE v.id IN (
			SELECT DISTINCT pi.vulnerability_id FROM product_identifiers pi WHERE %s
		)`, innerWhere)

	default:
		baseQuery = `SELECT v.id, v.summary, v.modified, v.published,
			vs.severity_worst, vs.severity_best, vs.scores_detail, vs.ecosystem_list
		FROM vulnerabilities v
		LEFT JOIN vulnerability_summary vs ON vs.vulnerability_id = v.id
		WHERE 1=1`
	}

	// Severity filter
	if query.Severity != "" {
		if strings.EqualFold(query.Severity, "unknown") {
			baseQuery += ` AND vs.severity_worst IS NULL`
		} else {
			sevLevel := severityToLevel(query.Severity)
			if sevLevel > 0 {
				argIdx++
				baseQuery += fmt.Sprintf(` AND vs.severity_worst >= $%d`, argIdx)
				args = append(args, sevLevel)
				argIdx++
				baseQuery += fmt.Sprintf(` AND COALESCE(vs.severity_best, vs.severity_worst) <= $%d`, argIdx)
				args = append(args, sevLevel)
			}
		}
	}

	// KEV filter
	if query.InKEV != nil && *query.InKEV {
		baseQuery += ` AND vs.in_kev = true`
	}

	// Since filter
	if query.Since != "" {
		argIdx++
		baseQuery += fmt.Sprintf(` AND v.modified >= $%d`, argIdx)
		args = append(args, query.Since)
	}

	// Version filter
	if query.Version != "" {
		argIdx++
		baseQuery += fmt.Sprintf(` AND v.id IN (
			SELECT oe.vulnerability_id FROM osv_entries oe
			JOIN osv_affected_packages ap ON ap.osv_entry_id = oe.osv_id
			WHERE $%d = ANY(ap.versions))`, argIdx)
		args = append(args, query.Version)
	}

	// ORDER BY and pagination (cursor-based or offset-based)
	if query.Cursor != "" {
		cursor, err := DecodeCursor(query.Cursor)
		if err != nil {
			return nil, fmt.Errorf("invalid cursor: %w", err)
		}
		if cursor.Published != nil {
			argIdx++
			pubArg := argIdx
			argIdx++
			idArg := argIdx
			baseQuery += fmt.Sprintf(` AND (v.published < $%d OR (v.published = $%d AND v.id < $%d) OR (v.published IS NULL))`,
				pubArg, pubArg, idArg)
			args = append(args, cursor.Published.UTC(), cursor.ID)
		} else {
			argIdx++
			baseQuery += fmt.Sprintf(` AND (v.published IS NULL AND v.id < $%d)`, argIdx)
			args = append(args, cursor.ID)
		}
	}

	argIdx++
	baseQuery += fmt.Sprintf(` ORDER BY v.published DESC NULLS LAST, v.id DESC LIMIT $%d`, argIdx)
	args = append(args, limit)

	if query.Cursor == "" && offset > 0 {
		argIdx++
		baseQuery += fmt.Sprintf(` OFFSET $%d`, argIdx)
		args = append(args, offset)
	}

	rows, err := s.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("searchLight query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var results []*model.Vulnerability
	for rows.Next() {
		var id string
		var summary sql.NullString
		var modified, published sql.NullTime
		var severityWorst, severityBest sql.NullInt32
		var scoresDetail []byte
		var ecosystemList []byte
		if err := rows.Scan(&id, &summary, &modified, &published, &severityWorst, &severityBest, &scoresDetail, &ecosystemList); err != nil {
			return nil, fmt.Errorf("searchLight scan: %w", err)
		}

		vuln := &model.Vulnerability{
			ID:      id,
			Summary: summary.String,
		}
		if modified.Valid {
			vuln.Modified = modified.Time
		}
		if published.Valid {
			t := published.Time
			vuln.Published = &t
		}

		// Add severity from vulnerability_summary severity_worst / severity_best
		if needSeverity && severityWorst.Valid && severityWorst.Int32 > 0 {
			worst := model.SeverityLevelName(int(severityWorst.Int32))
			best := worst
			if severityBest.Valid && severityBest.Int32 > 0 {
				best = model.SeverityLevelName(int(severityBest.Int32))
			}
			if worst == best {
				vuln.Severity = []model.Severity{{
					Type:  model.SeverityTypeCVSSV3,
					Score: worst,
				}}
			} else {
				vuln.Severity = []model.Severity{
					{Type: model.SeverityTypeCVSSV3, Score: worst},
					{Type: model.SeverityTypeCVSSV3, Score: best},
				}
			}
		}

		// Add ecosystem from vulnerability_summary ecosystem_list
		if needEcosystem && ecosystemList != nil {
			ecos := parseTextArray(string(ecosystemList))
			if len(ecos) > 0 {
				vuln.Affected = []model.Affected{{
					Package: model.Package{
						Ecosystem: ecos[0],
					},
				}}
			}
		}

		results = append(results, vuln)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("searchLight rows: %w", err)
	}

	return results, nil
}
