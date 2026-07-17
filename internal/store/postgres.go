package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
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
func (s *PostgresStore) UpsertBatch(ctx context.Context, vulns []*model.Vulnerability) error {
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

// upsertVulnerability inserts or updates a vulnerability within a transaction.
// This writes to:
//   - vulnerabilities (unified master)
//   - vulnerability_aliases (cross-references)
//   - osv_entries (OSV-specific data)
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

	// --- Step 1: Upsert into unified vulnerabilities table ---
	var published, withdrawn *time.Time
	published = vuln.Published
	withdrawn = vuln.Withdrawn

	_, err := tx.ExecContext(ctx, `
		INSERT INTO vulnerabilities (id, source, summary, details, published, modified, withdrawn)
		VALUES ($1, 'osv', $2, $3, $4, $5, $6)
		ON CONFLICT (id) DO UPDATE SET
			summary = EXCLUDED.summary,
			details = EXCLUDED.details,
			published = EXCLUDED.published,
			modified = EXCLUDED.modified,
			withdrawn = EXCLUDED.withdrawn`,
		vuln.ID,
		nullIfEmpty(vuln.Summary),
		nullIfEmpty(vuln.Details),
		published,
		vuln.Modified,
		withdrawn,
	)
	if err != nil {
		return fmt.Errorf("upsert vulnerability: %w", err)
	}

	// --- Step 2: Upsert aliases ---
	// Delete existing aliases for this vulnerability and re-insert
	if _, err := tx.ExecContext(ctx, `DELETE FROM vulnerability_aliases WHERE vulnerability_id = $1`, vuln.ID); err != nil {
		return fmt.Errorf("delete aliases: %w", err)
	}
	for i, alias := range vuln.Aliases {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO vulnerability_aliases (vulnerability_id, alias, ordering)
			VALUES ($1, $2, $3)`,
			vuln.ID, alias, i,
		)
		if err != nil {
			return fmt.Errorf("insert alias: %w", err)
		}
	}

	// --- Step 3: Upsert osv_entries ---
	// Delete existing osv_entry (cascade deletes child rows)
	if _, err := tx.ExecContext(ctx, `DELETE FROM osv_entries WHERE vulnerability_id = $1`, vuln.ID); err != nil {
		return fmt.Errorf("delete existing osv_entry: %w", err)
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO osv_entries (osv_id, vulnerability_id, schema_version, raw_json, database_specific)
		VALUES ($1, $2, $3, $4, $5)`,
		vuln.ID,
		vuln.ID,
		nullIfEmpty(vuln.SchemaVersion),
		rawJSON,
		nullableRawJSON(vuln.DatabaseSpecific),
	)
	if err != nil {
		return fmt.Errorf("insert osv_entry: %w", err)
	}

	// --- Step 4: Insert top-level severity ---
	for _, sev := range vuln.Severity {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO osv_severity (osv_entry_id, affected_package_id, severity_type, score, source)
			VALUES ($1, NULL, $2, $3, $4)`,
			vuln.ID, string(sev.Type), sev.Score, nullIfEmpty(sev.Source),
		)
		if err != nil {
			return fmt.Errorf("insert severity: %w", err)
		}
	}

	// --- Step 5: Insert affected packages ---
	for _, affected := range vuln.Affected {
		var affectedPkgID int64
		err := tx.QueryRowContext(ctx, `
			INSERT INTO osv_affected_packages (osv_entry_id, ecosystem, name, purl, versions, ecosystem_specific, database_specific)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			RETURNING id`,
			vuln.ID,
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

		// Insert ranges
		for _, r := range affected.Ranges {
			eventsJSON, err := json.Marshal(r.Events)
			if err != nil {
				return fmt.Errorf("marshal events: %w", err)
			}
			_, err = tx.ExecContext(ctx, `
				INSERT INTO osv_affected_ranges (affected_package_id, range_type, repo, events, database_specific)
				VALUES ($1, $2, $3, $4, $5)`,
				affectedPkgID,
				string(r.Type),
				nullIfEmpty(r.Repo),
				eventsJSON,
				nullableRawJSON(r.DatabaseSpecific),
			)
			if err != nil {
				return fmt.Errorf("insert osv_affected_range: %w", err)
			}
		}

		// Insert per-affected severity
		for _, sev := range affected.Severity {
			_, err := tx.ExecContext(ctx, `
				INSERT INTO osv_severity (osv_entry_id, affected_package_id, severity_type, score, source)
				VALUES ($1, $2, $3, $4, $5)`,
				vuln.ID, affectedPkgID, string(sev.Type), sev.Score, nullIfEmpty(sev.Source),
			)
			if err != nil {
				return fmt.Errorf("insert affected severity: %w", err)
			}
		}
	}

	// --- Step 6: Insert references ---
	for _, ref := range vuln.References {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO osv_references (osv_entry_id, reference_type, url)
			VALUES ($1, $2, $3)`,
			vuln.ID, string(ref.Type), ref.URL,
		)
		if err != nil {
			return fmt.Errorf("insert osv_reference: %w", err)
		}
	}

	// --- Step 7: Insert credits ---
	for _, credit := range vuln.Credits {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO osv_credits (osv_entry_id, name, contact, credit_type)
			VALUES ($1, $2, $3, $4)`,
			vuln.ID, credit.Name, pgTextArray(credit.Contact), nullIfEmpty(string(credit.Type)),
		)
		if err != nil {
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

	var (
		baseQuery string
		args      []interface{}
		argIdx    int
	)

	switch {
	case query.ID != "":
		argIdx++
		baseQuery = `SELECT oe.raw_json FROM osv_entries oe
			JOIN vulnerabilities v ON v.id = oe.vulnerability_id
			WHERE oe.osv_id = $` + fmt.Sprint(argIdx)
		args = append(args, query.ID)

	case query.Alias != "":
		argIdx++
		baseQuery = `SELECT oe.raw_json FROM osv_entries oe
			JOIN vulnerabilities v ON v.id = oe.vulnerability_id
			WHERE oe.vulnerability_id IN (
				SELECT va.vulnerability_id FROM vulnerability_aliases va WHERE va.alias = $` + fmt.Sprint(argIdx) + `
			)`
		args = append(args, query.Alias)

	case query.PackageName != "" || query.Ecosystem != "":
		baseQuery = `SELECT oe.raw_json FROM osv_entries oe
			JOIN vulnerabilities v ON v.id = oe.vulnerability_id
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
		baseQuery = `SELECT oe.raw_json FROM osv_entries oe
			JOIN vulnerabilities v ON v.id = oe.vulnerability_id
			WHERE 1=1`
	}

	argIdx++
	baseQuery += fmt.Sprintf(` ORDER BY v.modified DESC LIMIT $%d`, argIdx)
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
		if err := rows.Scan(&rawJSON); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		vuln, err := model.ParseVulnerability(rawJSON)
		if err != nil {
			return nil, fmt.Errorf("parse vulnerability: %w", err)
		}
		results = append(results, vuln)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}

	return results, nil
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
