package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
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
		DELETE FROM vulnerability_aliases;
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
//
// This writes to:
//   - vulnerabilities (unified master, keyed by CVE or OSV ID)
//   - vulnerability_aliases (cross-references including OSV ID itself)
//   - osv_entries (OSV-specific data, keyed by osv_id)
//   - osv_affected_packages, osv_affected_ranges, osv_severity, osv_references, osv_credits
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

	osvID := vuln.ID
	canID := canonicalID(osvID, vuln.Aliases)

	// --- Step 1: Check if this OSV entry already exists and get its current vulnerability_id ---
	var oldVulnID sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT vulnerability_id FROM osv_entries WHERE osv_id = $1`, osvID).Scan(&oldVulnID)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("lookup existing osv_entry: %w", err)
	}

	// --- Step 2: Handle migration when canonical ID changes (e.g., late CVE assignment) ---
	if oldVulnID.Valid && oldVulnID.String != canID {
		// The osv_entry previously pointed to a different vulnerability.
		// We need to re-point it and potentially clean up the old vulnerability row.
		oldID := oldVulnID.String

		// Delete the osv_entry and its children (will be re-created below)
		if _, err := tx.ExecContext(ctx, `DELETE FROM osv_entries WHERE osv_id = $1`, osvID); err != nil {
			return fmt.Errorf("delete old osv_entry for migration: %w", err)
		}

		// Remove all aliases that this OSV entry contributed under the old vulnerability
		if _, err := tx.ExecContext(ctx, `DELETE FROM vulnerability_aliases WHERE vulnerability_id = $1 AND source_osv_id = $2`, oldID, osvID); err != nil {
			return fmt.Errorf("delete old osv aliases: %w", err)
		}

		// Check if the old vulnerability has any remaining osv_entries
		var remainingCount int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM osv_entries WHERE vulnerability_id = $1`, oldID).Scan(&remainingCount); err != nil {
			return fmt.Errorf("count remaining osv_entries: %w", err)
		}

		if remainingCount == 0 {
			// No other OSV entries reference the old vulnerability — safe to delete
			// CASCADE will clean up vulnerability_aliases
			if _, err := tx.ExecContext(ctx, `DELETE FROM vulnerabilities WHERE id = $1`, oldID); err != nil {
				return fmt.Errorf("delete orphaned vulnerability: %w", err)
			}
		}
	} else if oldVulnID.Valid && oldVulnID.String == canID {
		// Same canonical ID — delete old osv_entry data (will be re-created below)
		if _, err := tx.ExecContext(ctx, `DELETE FROM osv_entries WHERE osv_id = $1`, osvID); err != nil {
			return fmt.Errorf("delete existing osv_entry: %w", err)
		}
	}

	// --- Step 3: Upsert into unified vulnerabilities table ---
	_, err = tx.ExecContext(ctx, `
		INSERT INTO vulnerabilities (id, source, summary, details, published, modified, withdrawn)
		VALUES ($1, 'osv', $2, $3, $4, $5, $6)
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

	// --- Step 4: Upsert aliases ---
	// Build alias set: original aliases + OSV ID itself (if canonical is different)
	allAliases := make([]string, 0, len(vuln.Aliases)+1)
	if canID != osvID {
		allAliases = append(allAliases, osvID)
	}
	allAliases = append(allAliases, vuln.Aliases...)

	// Insert aliases with ON CONFLICT to handle multiple OSV entries contributing aliases.
	// Each alias is tagged with source_osv_id to track which OSV entry contributed it.
	if len(allAliases) > 0 {
		aliasQuery := "INSERT INTO vulnerability_aliases (vulnerability_id, alias, ordering, source_osv_id) VALUES "
		aliasArgs := make([]interface{}, 0, len(allAliases)*2+2)
		aliasArgs = append(aliasArgs, canID, osvID)
		for i, alias := range allAliases {
			if i > 0 {
				aliasQuery += ", "
			}
			base := i*2 + 3
			aliasQuery += fmt.Sprintf("($1, $%d, $%d, $2)", base, base+1)
			aliasArgs = append(aliasArgs, alias, i)
		}
		aliasQuery += " ON CONFLICT (vulnerability_id, alias, source_osv_id) DO UPDATE SET ordering = EXCLUDED.ordering"
		if _, err := tx.ExecContext(ctx, aliasQuery, aliasArgs...); err != nil {
			return fmt.Errorf("insert aliases: %w", err)
		}
	}

	// Delete aliases that this OSV entry previously contributed but are no longer in the list.
	// This handles the case where an OSV entry's aliases field shrinks over time.
	if len(allAliases) > 0 {
		// Build placeholder list for NOT IN clause
		placeholders := make([]string, len(allAliases))
		args := make([]interface{}, 0, len(allAliases)+2)
		args = append(args, canID, osvID)
		for i, alias := range allAliases {
			placeholders[i] = fmt.Sprintf("$%d", i+3)
			args = append(args, alias)
		}
		query := fmt.Sprintf(`
			DELETE FROM vulnerability_aliases
			WHERE vulnerability_id = $1 AND source_osv_id = $2
			AND alias NOT IN (%s)`, strings.Join(placeholders, ", "))
		if _, err := tx.ExecContext(ctx, query, args...); err != nil {
			return fmt.Errorf("delete stale aliases: %w", err)
		}
	} else {
		// No aliases at all — delete all aliases contributed by this OSV entry
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM vulnerability_aliases
			WHERE vulnerability_id = $1 AND source_osv_id = $2`,
			canID, osvID,
		); err != nil {
			return fmt.Errorf("delete all aliases for osv entry: %w", err)
		}
	}

	// --- Step 5: Insert osv_entry ---
	_, err = tx.ExecContext(ctx, `
		INSERT INTO osv_entries (osv_id, vulnerability_id, schema_version, raw_json, database_specific)
		VALUES ($1, $2, $3, $4, $5)`,
		osvID,
		canID,
		nullIfEmpty(vuln.SchemaVersion),
		rawJSON,
		nullableRawJSON(vuln.DatabaseSpecific),
	)
	if err != nil {
		return fmt.Errorf("insert osv_entry: %w", err)
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

	// --- Step 7: Insert affected packages ---
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
// It returns the base SELECT query with conditions, the arguments, and the current argIdx.
func (s *PostgresStore) buildSearchConditions(query SearchQuery) (baseQuery string, args []interface{}, argIdx int) {
	switch {
	case query.ID != "":
		// Use UNION ALL to avoid OR across joined tables which causes full table scans.
		// Branch 1: match by vulnerabilities.id (PK lookup), join osv_entries via vulnerability_id FK
		// Branch 2: match by osv_entries.osv_id (PK lookup), resolve the parent vulnerability
		// The NOT EXISTS clause prevents duplicates when query.ID matches both v.id and oe.osv_id.
		argIdx++
		baseQuery = `SELECT raw_json, id, summary, details, published, modified, osv_id FROM (
			SELECT oe.raw_json, v.id, v.summary, v.details, v.published, v.modified, oe.osv_id FROM vulnerabilities v
			LEFT JOIN osv_entries oe ON oe.vulnerability_id = v.id
			WHERE v.id = $` + fmt.Sprint(argIdx) + `
			UNION ALL
			SELECT oe.raw_json, v.id, v.summary, v.details, v.published, v.modified, oe.osv_id FROM osv_entries oe
			JOIN vulnerabilities v ON v.id = oe.vulnerability_id
			WHERE oe.osv_id = $` + fmt.Sprint(argIdx) + `
			AND NOT EXISTS (SELECT 1 FROM vulnerabilities WHERE id = $` + fmt.Sprint(argIdx) + ` AND id = oe.osv_id)
		) sub WHERE 1=1`
		args = append(args, query.ID)

	case query.Alias != "":
		// Use UNION ALL: branch 1 matches by vulnerabilities.id directly (user passed a CVE as alias),
		// branch 2 resolves via vulnerability_aliases table, excluding any already found in branch 1.
		argIdx++
		baseQuery = `SELECT raw_json, id, summary, details, published, modified, osv_id FROM (
			SELECT oe.raw_json, v.id, v.summary, v.details, v.published, v.modified, oe.osv_id FROM vulnerabilities v
			LEFT JOIN osv_entries oe ON oe.vulnerability_id = v.id
			WHERE v.id = $` + fmt.Sprint(argIdx) + `
			UNION ALL
			SELECT oe.raw_json, v.id, v.summary, v.details, v.published, v.modified, oe.osv_id FROM vulnerabilities v
			LEFT JOIN osv_entries oe ON oe.vulnerability_id = v.id
			WHERE v.id IN (
				SELECT va.vulnerability_id FROM vulnerability_aliases va WHERE va.alias = $` + fmt.Sprint(argIdx) + `
			) AND v.id != $` + fmt.Sprint(argIdx) + `
		) sub WHERE 1=1`
		args = append(args, query.Alias)

	case query.PackageName != "" || query.Ecosystem != "":
		baseQuery = `SELECT oe.raw_json, v.id, v.summary, v.details, v.published, v.modified, oe.osv_id FROM vulnerabilities v
			LEFT JOIN osv_entries oe ON oe.vulnerability_id = v.id
			WHERE oe.osv_id IN (
				SELECT ap.osv_entry_id FROM osv_affected_packages ap WHERE 1=1`
		if query.Ecosystem != "" {
			argIdx++
			baseQuery += fmt.Sprintf(` AND ap.ecosystem = $%d`, argIdx)
			args = append(args, query.Ecosystem)
		}
		if query.PackageName != "" {
			argIdx++
			baseQuery += fmt.Sprintf(` AND ap.name = $%d`, argIdx)
			args = append(args, query.PackageName)
		}
		baseQuery += `)`

	default:
		baseQuery = `SELECT oe.raw_json, v.id, v.summary, v.details, v.published, v.modified, oe.osv_id FROM vulnerabilities v
			LEFT JOIN osv_entries oe ON oe.vulnerability_id = v.id
			WHERE 1=1`
	}

	// Additional filter: --severity (filter by CVSS score range)
	if query.Severity != "" {
		minScore, maxScore := severityToScoreRange(query.Severity)
		if minScore >= 0 {
			argIdx++
			baseQuery += fmt.Sprintf(` AND osv_id IN (
				SELECT s.osv_entry_id FROM osv_severity s
				WHERE s.severity_type IN ('CVSS_V3', 'CVSS_V4', 'CVSS_V2')
				AND cvss_base_score(s.score) >= $%d`, argIdx)
			args = append(args, minScore)
			argIdx++
			baseQuery += fmt.Sprintf(` AND cvss_base_score(s.score) < $%d)`, argIdx)
			args = append(args, maxScore)
		}
	}

	// Additional filter: --since (modified date)
	if query.Since != "" {
		argIdx++
		baseQuery += fmt.Sprintf(` AND modified >= $%d`, argIdx)
		args = append(args, query.Since)
	}

	// Additional filter: --version (check if version appears in affected versions list)
	if query.Version != "" {
		argIdx++
		baseQuery += fmt.Sprintf(` AND osv_id IN (
			SELECT ap2.osv_entry_id FROM osv_affected_packages ap2
			WHERE $%d = ANY(ap2.versions))`, argIdx)
		args = append(args, query.Version)
	}

	return baseQuery, args, argIdx
}

// severityToScoreRange maps a severity level string to CVSS v3 score ranges.
// Returns (minScore, maxScore). Returns (-1, -1) for unknown levels.
func severityToScoreRange(level string) (float64, float64) {
	switch strings.ToLower(level) {
	case "critical":
		return 9.0, 10.1
	case "high":
		return 7.0, 9.0
	case "medium":
		return 4.0, 7.0
	case "low":
		return 0.1, 4.0
	case "none":
		return 0.0, 0.1
	default:
		return -1, -1
	}
}

// Search finds vulnerabilities matching the given query parameters.
func (s *PostgresStore) Search(ctx context.Context, query SearchQuery) ([]*model.Vulnerability, error) {
	limit := query.Limit
	if limit <= 0 {
		limit = 100
	}
	offset := query.Offset
	if offset < 0 {
		offset = 0
	}

	baseQuery, args, argIdx := s.buildSearchConditions(query)

	argIdx++
	baseQuery += fmt.Sprintf(` ORDER BY modified DESC LIMIT $%d`, argIdx)
	args = append(args, limit)
	argIdx++
	baseQuery += fmt.Sprintf(` OFFSET $%d`, argIdx)
	args = append(args, offset)

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
		var osvID sql.NullString // unused but required for consistent column count
		if err := rows.Scan(&rawJSON, &vulnID, &summary, &details, &published, &modified, &osvID); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		if rawJSON != nil {
			vuln, err := model.ParseVulnerability(rawJSON)
			if err != nil {
				return nil, fmt.Errorf("parse vulnerability: %w", err)
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
			results = append(results, vuln)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}

	return results, nil
}

// Count returns the number of vulnerabilities matching the given query parameters.
func (s *PostgresStore) Count(ctx context.Context, query SearchQuery) (int64, error) {
	baseQuery, args, _ := s.buildSearchConditions(query)

	// Wrap the base query as a subquery to count results universally
	// (works for both simple queries and UNION ALL queries).
	countQuery := `SELECT COUNT(*) FROM (` + baseQuery + `) count_sub`

	var count int64
	if err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("count vulnerabilities: %w", err)
	}
	return count, nil
}

// GetSyncState retrieves the sync state for a given source.
func (s *PostgresStore) GetSyncState(ctx context.Context, source string) (*SyncState, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT source, last_modified_at, record_count FROM sync_state WHERE source = $1`,
		source,
	)

	var state SyncState
	var lastModified time.Time
	if err := row.Scan(&state.Source, &lastModified, &state.RecordCount); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("query sync_state: %w", err)
	}
	state.LastModifiedAt = lastModified.Format(time.RFC3339)
	return &state, nil
}

// UpdateSyncState creates or updates the sync state for a source.
func (s *PostgresStore) UpdateSyncState(ctx context.Context, state *SyncState) error {
	lastModified, err := time.Parse(time.RFC3339, state.LastModifiedAt)
	if err != nil {
		return fmt.Errorf("parse last_modified_at: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO sync_state (source, last_modified_at, record_count)
		VALUES ($1, $2, $3)
		ON CONFLICT (source) DO UPDATE SET
			last_modified_at = EXCLUDED.last_modified_at,
			last_synced_at = NOW(),
			record_count = EXCLUDED.record_count`,
		state.Source, lastModified, state.RecordCount,
	)
	if err != nil {
		return fmt.Errorf("upsert sync_state: %w", err)
	}
	return nil
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
