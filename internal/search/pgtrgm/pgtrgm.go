// Package pgtrgm provides a full-text search engine backed by PostgreSQL's
// pg_trgm extension. It uses GIN indexes on trigrams to accelerate ILIKE queries,
// supporting any language including Japanese without additional configuration.
package pgtrgm

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/kato83/mayu/internal/search"
)

// indexes defines the GIN trigram indexes to create during initialization.
// Each entry is {indexName, tableName, columnName}.
var indexes = []struct {
	name   string
	table  string
	column string
}{
	{"idx_vuln_summary_trgm", "vulnerabilities", "summary"},
	{"idx_vuln_details_trgm", "vulnerabilities", "details"},
	{"idx_vuln_trans_summary_trgm", "vulnerabilities_translation", "summary"},
	{"idx_vuln_trans_details_trgm", "vulnerabilities_translation", "details"},
	{"idx_nvd_desc_value_trgm", "nvd_descriptions", "value"},
	{"idx_nvd_desc_trans_value_trgm", "nvd_descriptions_translation", "value"},
	{"idx_kev_short_desc_trgm", "kev_entries", "short_description"},
	{"idx_kev_vuln_name_trgm", "kev_entries", "vulnerability_name"},
}

// Engine implements search.Engine using PostgreSQL pg_trgm extension.
type Engine struct {
	db *sql.DB
}

// New creates a new pg_trgm search engine with the given database connection.
func New(db *sql.DB) *Engine {
	return &Engine{db: db}
}

// Available checks whether the pg_trgm extension is enabled and indexes exist.
func (e *Engine) Available(ctx context.Context) error {
	// Check if pg_trgm extension is installed
	var hasExtension bool
	err := e.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm')`,
	).Scan(&hasExtension)
	if err != nil {
		return fmt.Errorf("check pg_trgm extension: %w", err)
	}
	if !hasExtension {
		return search.ErrNotInitialized
	}

	// Check if at least the primary index exists
	var hasIndex bool
	err = e.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM pg_indexes WHERE indexname = $1)`,
		indexes[0].name,
	).Scan(&hasIndex)
	if err != nil {
		return fmt.Errorf("check search indexes: %w", err)
	}
	if !hasIndex {
		return search.ErrNotInitialized
	}

	return nil
}

// Init creates the pg_trgm extension and GIN indexes.
// This may take significant time depending on data volume.
func (e *Engine) Init(ctx context.Context, progress search.InitProgress) error {
	total := len(indexes) + 1 // +1 for CREATE EXTENSION

	// Step 1: Create extension
	if progress != nil {
		progress("Creating pg_trgm extension", 0, total)
	}
	_, err := e.db.ExecContext(ctx, `CREATE EXTENSION IF NOT EXISTS pg_trgm`)
	if err != nil {
		return fmt.Errorf("create pg_trgm extension: %w (ensure the PostgreSQL user has CREATE privilege on the database)", err)
	}

	// Step 2: Create GIN indexes
	for i, idx := range indexes {
		if progress != nil {
			progress(fmt.Sprintf("Creating index %s on %s.%s", idx.name, idx.table, idx.column), i+1, total)
		}

		// Check if the target table exists before creating the index
		var tableExists bool
		err := e.db.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name = $1)`,
			idx.table,
		).Scan(&tableExists)
		if err != nil {
			return fmt.Errorf("check table %s: %w", idx.table, err)
		}
		if !tableExists {
			// Skip indexes for tables that don't exist yet
			continue
		}

		query := fmt.Sprintf(
			`CREATE INDEX IF NOT EXISTS %s ON %s USING GIN (%s gin_trgm_ops)`,
			idx.name, idx.table, idx.column,
		)
		_, err = e.db.ExecContext(ctx, query)
		if err != nil {
			return fmt.Errorf("create index %s: %w", idx.name, err)
		}
	}

	if progress != nil {
		progress("Initialization complete", total, total)
	}
	return nil
}

// Search executes a full-text search using ILIKE with pg_trgm GIN indexes.
func (e *Engine) Search(ctx context.Context, q search.Query) ([]search.Result, int64, error) {
	if err := e.Available(ctx); err != nil {
		return nil, 0, err
	}

	if q.Text == "" {
		return nil, 0, nil
	}

	limit := q.Limit
	if limit <= 0 {
		limit = 20
	}
	offset := q.Offset
	if offset < 0 {
		offset = 0
	}

	// Escape special characters for LIKE pattern
	pattern := "%" + escapeLike(q.Text) + "%"

	// Build ecosystem filter clause
	ecosystemFilter := ""
	var baseArgs []interface{}
	baseArgs = append(baseArgs, pattern)
	argPattern := "$1" // pattern is always $1

	if q.Ecosystem != "" {
		baseArgs = append(baseArgs, q.Ecosystem)
		ecosystemFilter = `AND v.id IN (
			SELECT DISTINCT vulnerability_id FROM product_identifiers WHERE ecosystem = $2
		)`
	}

	// Search query: find matching vulnerabilities across multiple text columns
	searchQuery := fmt.Sprintf(`
		WITH matched AS (
			SELECT v.id, v.summary,
				CASE
					WHEN v.summary ILIKE %s THEN 1.0
					ELSE 0.8
				END AS score
			FROM vulnerabilities v
			WHERE (v.summary ILIKE %s OR v.details ILIKE %s)
			%s

			UNION ALL

			SELECT v.id, v.summary, 0.7 AS score
			FROM vulnerabilities v
			JOIN nvd_entries ne ON ne.vulnerability_id = v.id
			JOIN nvd_descriptions nd ON nd.nvd_entry_id = ne.id
			WHERE nd.value ILIKE %s
			%s

			UNION ALL

			SELECT v.id, v.summary, 0.9 AS score
			FROM vulnerabilities v
			JOIN vulnerabilities_translation vt ON vt.vulnerability_id = v.id
			WHERE (vt.summary ILIKE %s OR vt.details ILIKE %s)
			%s
		),
		ranked AS (
			SELECT id, summary, MAX(score) AS score
			FROM matched
			GROUP BY id, summary
		)
		SELECT id, COALESCE(summary, ''), score
		FROM ranked
		ORDER BY score DESC, id
	`, argPattern, argPattern, argPattern, ecosystemFilter,
		argPattern, ecosystemFilter,
		argPattern, argPattern, ecosystemFilter)

	// Add LIMIT and OFFSET
	limitArgIdx := len(baseArgs) + 1
	offsetArgIdx := len(baseArgs) + 2
	searchQuery += fmt.Sprintf(" LIMIT $%d OFFSET $%d", limitArgIdx, offsetArgIdx)

	queryArgs := append(baseArgs, limit, offset)

	rows, err := e.db.QueryContext(ctx, searchQuery, queryArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("search query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var results []search.Result
	for rows.Next() {
		var r search.Result
		if err := rows.Scan(&r.VulnerabilityID, &r.Summary, &r.Score); err != nil {
			return nil, 0, fmt.Errorf("scan result: %w", err)
		}
		results = append(results, r)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate results: %w", err)
	}

	// Count total matches
	countQuery := fmt.Sprintf(`
		SELECT COUNT(DISTINCT id) FROM (
			SELECT v.id
			FROM vulnerabilities v
			WHERE (v.summary ILIKE %s OR v.details ILIKE %s)
			%s

			UNION ALL

			SELECT v.id
			FROM vulnerabilities v
			JOIN nvd_entries ne ON ne.vulnerability_id = v.id
			JOIN nvd_descriptions nd ON nd.nvd_entry_id = ne.id
			WHERE nd.value ILIKE %s
			%s

			UNION ALL

			SELECT v.id
			FROM vulnerabilities v
			JOIN vulnerabilities_translation vt ON vt.vulnerability_id = v.id
			WHERE (vt.summary ILIKE %s OR vt.details ILIKE %s)
			%s
		) AS all_matches`, argPattern, argPattern, ecosystemFilter,
		argPattern, ecosystemFilter,
		argPattern, argPattern, ecosystemFilter)

	var total int64
	err = e.db.QueryRowContext(ctx, countQuery, baseArgs...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count query: %w", err)
	}

	return results, total, nil
}

// escapeLike escapes special characters in a LIKE/ILIKE pattern.
func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}
