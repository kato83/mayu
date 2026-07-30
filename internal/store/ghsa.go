package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kato83/mayu/internal/model"
)

// UpsertGHSABatch stores multiple GHSA entries in a single transaction.
// It retries automatically on deadlock (same pattern as NVD/MITRE UpsertBatch).
func (s *PostgresStore) UpsertGHSABatch(ctx context.Context, entries []*model.GHSAEntry) error {
	const maxRetries = 5
	for attempt := 0; attempt <= maxRetries; attempt++ {
		err := s.upsertGHSABatchOnce(ctx, entries)
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
	return fmt.Errorf("upsert GHSA batch: exceeded max retries due to deadlock")
}

func (s *PostgresStore) upsertGHSABatchOnce(ctx context.Context, entries []*model.GHSAEntry) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, entry := range entries {
		if err := s.upsertGHSAEntry(ctx, tx, entry); err != nil {
			return fmt.Errorf("upsert %s: %w", entry.GHSAID, err)
		}
	}

	return tx.Commit()
}

// UpsertGHSA stores a single GHSA entry (convenience wrapper).
func (s *PostgresStore) UpsertGHSA(ctx context.Context, entry *model.GHSAEntry) error {
	return s.UpsertGHSABatch(ctx, []*model.GHSAEntry{entry})
}

// upsertGHSAEntry inserts or updates a single GHSA entry within a transaction.
// Strategy:
//  1. Determine canonical vulnerability ID (CVE if available, else GHSA ID).
//  2. Ensure vulnerability row exists (DO UPDATE for modified time).
//  3. DELETE existing ghsa_entries row for this ghsa_id (CASCADE cleans children).
//  4. INSERT fresh GHSA data into ghsa_entries and child tables.
//  5. Upsert vulnerability_aliases for GHSA↔CVE cross-reference.
//  6. Upsert product_identifiers for package search.
func (s *PostgresStore) upsertGHSAEntry(ctx context.Context, tx *sql.Tx, entry *model.GHSAEntry) error {
	// Determine canonical vulnerability ID
	vulnID := entry.GHSAID
	if entry.CVEID != "" {
		vulnID = entry.CVEID
	}
	entry.VulnerabilityID = vulnID

	// --- Step 1: Upsert into unified vulnerabilities table ---
	_, err := tx.ExecContext(ctx, `
		INSERT INTO vulnerabilities (id, summary, details, published, modified, withdrawn)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (id) DO UPDATE SET
			summary = COALESCE(NULLIF(vulnerabilities.summary, ''), EXCLUDED.summary),
			details = COALESCE(NULLIF(vulnerabilities.details, ''), EXCLUDED.details),
			published = LEAST(EXCLUDED.published, vulnerabilities.published),
			modified = GREATEST(EXCLUDED.modified, vulnerabilities.modified)`,
		vulnID,
		nullIfEmpty(entry.Summary),
		nullIfEmpty(entry.Description),
		entry.PublishedAt,
		entry.UpdatedAt,
		entry.WithdrawnAt,
	)
	if err != nil {
		return fmt.Errorf("ensure vulnerability exists: %w", err)
	}

	// --- Step 2: DELETE existing ghsa_entries row (CASCADE cleans children) ---
	_, err = tx.ExecContext(ctx, `DELETE FROM ghsa_entries WHERE ghsa_id = $1`, entry.GHSAID)
	if err != nil {
		return fmt.Errorf("delete existing ghsa_entry: %w", err)
	}

	// --- Step 3: INSERT ghsa_entries ---
	var entryID int64
	err = tx.QueryRowContext(ctx, `
		INSERT INTO ghsa_entries (
			ghsa_id, vulnerability_id, cve_id, summary, description,
			severity, state, html_url, published_at, updated_at, withdrawn_at, raw_json
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING id`,
		entry.GHSAID,
		vulnID,
		nullIfEmpty(entry.CVEID),
		nullIfEmpty(entry.Summary),
		nullIfEmpty(entry.Description),
		nullIfEmpty(entry.Severity),
		entry.State,
		nullIfEmpty(entry.HTMLURL),
		entry.PublishedAt,
		entry.UpdatedAt,
		entry.WithdrawnAt,
		sanitizeJSONB(entry.RawJSON),
	).Scan(&entryID)
	if err != nil {
		return fmt.Errorf("insert ghsa_entry: %w", err)
	}

	// --- Step 4: INSERT child records ---

	// Vulnerabilities (affected packages)
	for _, v := range entry.Vulnerabilities {
		_, err = tx.ExecContext(ctx, `
			INSERT INTO ghsa_vulnerabilities (
				ghsa_entry_id, ecosystem, package_name,
				vulnerable_version_range, patched_versions, vulnerable_functions
			)
			VALUES ($1, $2, $3, $4, $5, $6)`,
			entryID,
			v.Ecosystem,
			v.PackageName,
			nullIfEmpty(v.VulnerableVersionRange),
			nullIfEmpty(v.PatchedVersions),
			pgTextArray(v.VulnerableFunctions),
		)
		if err != nil {
			return fmt.Errorf("insert ghsa_vulnerability: %w", err)
		}
	}

	// Credits
	for _, c := range entry.Credits {
		_, err = tx.ExecContext(ctx, `
			INSERT INTO ghsa_credits (ghsa_entry_id, login, credit_type)
			VALUES ($1, $2, $3)`,
			entryID,
			c.Login,
			nullIfEmpty(c.CreditType),
		)
		if err != nil {
			return fmt.Errorf("insert ghsa_credit: %w", err)
		}
	}

	// CWEs
	for _, cwe := range entry.CWEs {
		_, err = tx.ExecContext(ctx, `
			INSERT INTO ghsa_cwes (ghsa_entry_id, cwe_id, name)
			VALUES ($1, $2, $3)`,
			entryID,
			cwe.CWEID,
			nullIfEmpty(cwe.Name),
		)
		if err != nil {
			return fmt.Errorf("insert ghsa_cwe: %w", err)
		}
	}

	// --- Step 5: Upsert vulnerability_aliases ---
	// Add GHSA ID as alias if canonical is CVE
	if entry.CVEID != "" {
		_, err = tx.ExecContext(ctx, `
			INSERT INTO vulnerability_aliases (vulnerability_id, alias)
			VALUES ($1, $2)
			ON CONFLICT (vulnerability_id, alias) DO NOTHING`,
			vulnID, entry.GHSAID,
		)
		if err != nil {
			return fmt.Errorf("insert GHSA alias: %w", err)
		}
	}
	// Add CVE as alias if canonical is GHSA ID
	if entry.CVEID != "" && vulnID == entry.CVEID {
		// CVE is canonical, GHSA is alias — already handled above
	} else if entry.CVEID != "" && vulnID == entry.GHSAID {
		_, err = tx.ExecContext(ctx, `
			INSERT INTO vulnerability_aliases (vulnerability_id, alias)
			VALUES ($1, $2)
			ON CONFLICT (vulnerability_id, alias) DO NOTHING`,
			vulnID, entry.CVEID,
		)
		if err != nil {
			return fmt.Errorf("insert CVE alias: %w", err)
		}
	}

	// --- Step 6: Upsert product_identifiers ---
	for _, v := range entry.Vulnerabilities {
		_, err = tx.ExecContext(ctx, `
			INSERT INTO product_identifiers (
				vulnerability_id, source, ecosystem, name
			)
			VALUES ($1, 'ghsa', $2, $3)
			ON CONFLICT DO NOTHING`,
			vulnID,
			v.Ecosystem,
			v.PackageName,
		)
		if err != nil {
			return fmt.Errorf("insert product_identifier: %w", err)
		}
	}

	return nil
}

// GetGHSAByVulnerabilityID retrieves the GHSA entry for a vulnerability.
// Returns nil, nil if no GHSA entry exists for the given vulnerability.
func (s *PostgresStore) GetGHSAByVulnerabilityID(ctx context.Context, vulnID string) (*model.GHSAEntry, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, ghsa_id, vulnerability_id, cve_id, summary, description,
		       severity, state, html_url, published_at, updated_at, withdrawn_at, raw_json
		FROM ghsa_entries
		WHERE vulnerability_id = $1`, vulnID)

	entry, err := scanGHSAEntry(row)
	if err == pgx.ErrNoRows || err == sql.ErrNoRows {
		return nil, nil
	}
	return entry, err
}

// GetGHSAByGHSAID retrieves a GHSA entry by its GHSA ID.
func (s *PostgresStore) GetGHSAByGHSAID(ctx context.Context, ghsaID string) (*model.GHSAEntry, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, ghsa_id, vulnerability_id, cve_id, summary, description,
		       severity, state, html_url, published_at, updated_at, withdrawn_at, raw_json
		FROM ghsa_entries
		WHERE ghsa_id = $1`, ghsaID)

	entry, err := scanGHSAEntry(row)
	if err == pgx.ErrNoRows || err == sql.ErrNoRows {
		return nil, nil
	}
	return entry, err
}

// CountGHSAEntries returns the total number of GHSA entries.
func (s *PostgresStore) CountGHSAEntries(ctx context.Context) (int64, error) {
	var count int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM ghsa_entries`).Scan(&count)
	return count, err
}

// scanGHSAEntry scans a single ghsa_entries row.
func scanGHSAEntry(row *sql.Row) (*model.GHSAEntry, error) {
	var entry model.GHSAEntry
	var cveID, summary, description, severity, htmlURL sql.NullString
	var publishedAt, updatedAt, withdrawnAt sql.NullTime

	err := row.Scan(
		&entry.ID,
		&entry.GHSAID,
		&entry.VulnerabilityID,
		&cveID,
		&summary,
		&description,
		&severity,
		&entry.State,
		&htmlURL,
		&publishedAt,
		&updatedAt,
		&withdrawnAt,
		&entry.RawJSON,
	)
	if err != nil {
		return nil, err
	}

	entry.CVEID = cveID.String
	entry.Summary = summary.String
	entry.Description = description.String
	entry.Severity = severity.String
	entry.HTMLURL = htmlURL.String
	if publishedAt.Valid {
		entry.PublishedAt = &publishedAt.Time
	}
	if updatedAt.Valid {
		entry.UpdatedAt = &updatedAt.Time
	}
	if withdrawnAt.Valid {
		entry.WithdrawnAt = &withdrawnAt.Time
	}

	return &entry, nil
}
