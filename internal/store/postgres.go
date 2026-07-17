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
		db.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return &PostgresStore{db: db}, nil
}

// Close releases the database connection pool.
func (s *PostgresStore) Close() error {
	return s.db.Close()
}

// Insert stores a single vulnerability and all its related data.
func (s *PostgresStore) Insert(ctx context.Context, vuln *model.Vulnerability) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

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
	defer tx.Rollback()

	for _, vuln := range vulns {
		if err := s.upsertVulnerability(ctx, tx, vuln); err != nil {
			return fmt.Errorf("upsert %s: %w", vuln.ID, err)
		}
	}

	return tx.Commit()
}

// upsertVulnerability inserts or updates a vulnerability within a transaction.
func (s *PostgresStore) upsertVulnerability(ctx context.Context, tx *sql.Tx, vuln *model.Vulnerability) error {
	// Delete existing related data (cascade will handle child tables, but we
	// delete explicitly for clarity and to avoid relying on cascade for upsert)
	if _, err := tx.ExecContext(ctx, `DELETE FROM vulnerabilities WHERE id = $1`, vuln.ID); err != nil {
		return fmt.Errorf("delete existing vulnerability: %w", err)
	}

	// Determine raw_json: use RawJSON if available, otherwise marshal the struct
	rawJSON := vuln.RawJSON
	if rawJSON == nil {
		var err error
		rawJSON, err = json.Marshal(vuln)
		if err != nil {
			return fmt.Errorf("marshal vulnerability: %w", err)
		}
	}

	// Insert vulnerability
	var published, withdrawn *time.Time
	published = vuln.Published
	withdrawn = vuln.Withdrawn

	_, err := tx.ExecContext(ctx, `
		INSERT INTO vulnerabilities (id, schema_version, modified, published, withdrawn, aliases, related, upstream, summary, details, raw_json, database_specific)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		vuln.ID,
		nullIfEmpty(vuln.SchemaVersion),
		vuln.Modified,
		published,
		withdrawn,
		pgTextArray(vuln.Aliases),
		pgTextArray(vuln.Related),
		pgTextArray(vuln.Upstream),
		nullIfEmpty(vuln.Summary),
		nullIfEmpty(vuln.Details),
		rawJSON,
		nullableRawJSON(vuln.DatabaseSpecific),
	)
	if err != nil {
		return fmt.Errorf("insert vulnerability: %w", err)
	}

	// Insert severity (top-level)
	for _, sev := range vuln.Severity {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO severity (vulnerability_id, affected_package_id, severity_type, score, source)
			VALUES ($1, NULL, $2, $3, $4)`,
			vuln.ID, string(sev.Type), sev.Score, nullIfEmpty(sev.Source),
		)
		if err != nil {
			return fmt.Errorf("insert severity: %w", err)
		}
	}

	// Insert affected packages
	for _, affected := range vuln.Affected {
		var affectedPkgID int64
		err := tx.QueryRowContext(ctx, `
			INSERT INTO affected_packages (vulnerability_id, ecosystem, name, purl, versions, ecosystem_specific, database_specific)
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
			return fmt.Errorf("insert affected_package: %w", err)
		}

		// Insert ranges
		for _, r := range affected.Ranges {
			eventsJSON, err := json.Marshal(r.Events)
			if err != nil {
				return fmt.Errorf("marshal events: %w", err)
			}
			_, err = tx.ExecContext(ctx, `
				INSERT INTO affected_ranges (affected_package_id, range_type, repo, events, database_specific)
				VALUES ($1, $2, $3, $4, $5)`,
				affectedPkgID,
				string(r.Type),
				nullIfEmpty(r.Repo),
				eventsJSON,
				nullableRawJSON(r.DatabaseSpecific),
			)
			if err != nil {
				return fmt.Errorf("insert affected_range: %w", err)
			}
		}

		// Insert per-affected severity
		for _, sev := range affected.Severity {
			_, err := tx.ExecContext(ctx, `
				INSERT INTO severity (vulnerability_id, affected_package_id, severity_type, score, source)
				VALUES ($1, $2, $3, $4, $5)`,
				vuln.ID, affectedPkgID, string(sev.Type), sev.Score, nullIfEmpty(sev.Source),
			)
			if err != nil {
				return fmt.Errorf("insert affected severity: %w", err)
			}
		}
	}

	// Insert references
	for _, ref := range vuln.References {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO references_ (vulnerability_id, reference_type, url)
			VALUES ($1, $2, $3)`,
			vuln.ID, string(ref.Type), ref.URL,
		)
		if err != nil {
			return fmt.Errorf("insert reference: %w", err)
		}
	}

	// Insert credits
	for _, credit := range vuln.Credits {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO credits (vulnerability_id, name, contact, credit_type)
			VALUES ($1, $2, $3, $4)`,
			vuln.ID, credit.Name, pgTextArray(credit.Contact), nullIfEmpty(string(credit.Type)),
		)
		if err != nil {
			return fmt.Errorf("insert credit: %w", err)
		}
	}

	return nil
}

// GetByID retrieves a single vulnerability by its OSV ID.
func (s *PostgresStore) GetByID(ctx context.Context, id string) (*model.Vulnerability, error) {
	row := s.db.QueryRowContext(ctx, `SELECT raw_json FROM vulnerabilities WHERE id = $1`, id)

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
		baseQuery = `SELECT v.raw_json FROM vulnerabilities v WHERE v.id = $` + fmt.Sprint(argIdx)
		args = append(args, query.ID)

	case query.Alias != "":
		argIdx++
		baseQuery = `SELECT v.raw_json FROM vulnerabilities v WHERE $` + fmt.Sprint(argIdx) + ` = ANY(v.aliases)`
		args = append(args, query.Alias)

	case query.PackageName != "" || query.Ecosystem != "":
		baseQuery = `SELECT v.raw_json FROM vulnerabilities v WHERE v.id IN (SELECT ap.vulnerability_id FROM affected_packages ap WHERE 1=1`
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
		baseQuery = `SELECT v.raw_json FROM vulnerabilities v WHERE 1=1`
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
	defer rows.Close()

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

// GetSyncState retrieves the sync state for a given ecosystem.
func (s *PostgresStore) GetSyncState(ctx context.Context, ecosystem string) (*SyncState, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT ecosystem, last_modified_at, record_count FROM sync_state WHERE ecosystem = $1`,
		ecosystem,
	)

	var state SyncState
	var lastModified time.Time
	if err := row.Scan(&state.Ecosystem, &lastModified, &state.RecordCount); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("query sync_state: %w", err)
	}
	state.LastModifiedAt = lastModified.Format(time.RFC3339)
	return &state, nil
}

// UpdateSyncState creates or updates the sync state for an ecosystem.
func (s *PostgresStore) UpdateSyncState(ctx context.Context, state *SyncState) error {
	lastModified, err := time.Parse(time.RFC3339, state.LastModifiedAt)
	if err != nil {
		return fmt.Errorf("parse last_modified_at: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO sync_state (ecosystem, last_modified_at, record_count)
		VALUES ($1, $2, $3)
		ON CONFLICT (ecosystem) DO UPDATE SET
			last_modified_at = EXCLUDED.last_modified_at,
			last_synced_at = NOW(),
			record_count = EXCLUDED.record_count`,
		state.Ecosystem, lastModified, state.RecordCount,
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
