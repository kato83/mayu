package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/kato83/mayu/internal/model"
)

// UpsertKEVBatch stores multiple KEV entries in a single transaction.
// It retries automatically on deadlock (same pattern as NVD/MITRE/EPSS UpsertBatch).
//
// The upsert strategy:
//   - Ensure a corresponding vulnerabilities row exists (INSERT ... ON CONFLICT DO NOTHING).
//   - For each KEV entry, INSERT or UPDATE on cve_id conflict.
//
// KEV entries are unique per CVE (one entry per CVE in the catalog).
// On reimport, existing entries are updated in-place with the latest data.
func (s *PostgresStore) UpsertKEVBatch(ctx context.Context, records []*model.KEVRecord) error {
	const maxRetries = 5
	for attempt := 0; attempt <= maxRetries; attempt++ {
		err := s.upsertKEVBatchOnce(ctx, records)
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
	return fmt.Errorf("upsert KEV batch: exceeded max retries due to deadlock")
}

func (s *PostgresStore) upsertKEVBatchOnce(ctx context.Context, records []*model.KEVRecord) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, record := range records {
		if err := s.upsertKEVEntry(ctx, tx, record); err != nil {
			return fmt.Errorf("upsert KEV %s: %w", record.CVEID, err)
		}
	}

	return tx.Commit()
}

// upsertKEVEntry inserts or updates a single KEV entry within a transaction.
// Strategy:
//  1. Ensure the CVE exists in the vulnerabilities table (source='kev').
//     Uses ON CONFLICT DO NOTHING to avoid overwriting existing vulnerability data
//     contributed by other sources (OSV, NVD, MITRE).
//  2. Upsert into kev_entries using cve_id unique constraint.
//     On conflict, updates all fields (newer catalog data wins).
func (s *PostgresStore) upsertKEVEntry(ctx context.Context, tx *sql.Tx, record *model.KEVRecord) error {
	cveID := record.CVEID

	// --- Step 1: Ensure vulnerability row exists ---
	// KEV contributes the CVE ID and short description; it doesn't provide
	// detailed summary/published/modified dates.
	// Use DO NOTHING to preserve data from richer sources (OSV, NVD, MITRE).
	// modified uses NOW() because the column has a NOT NULL constraint.
	_, err := tx.ExecContext(ctx, `
		INSERT INTO vulnerabilities (id, summary, details, published, modified, withdrawn)
		VALUES ($1, $2, NULL, NULL, NOW(), NULL)
		ON CONFLICT (id) DO NOTHING`,
		cveID,
		record.ShortDescription,
	)
	if err != nil {
		return fmt.Errorf("ensure vulnerability exists: %w", err)
	}

	// --- Step 2: Upsert KEV entry ---
	_, err = tx.ExecContext(ctx, `
		INSERT INTO kev_entries (
			cve_id, vulnerability_id, vendor_project, product,
			vulnerability_name, date_added, short_description,
			required_action, due_date, known_ransomware_campaign_use,
			notes, cwes, raw_json
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT (cve_id) DO UPDATE SET
			vendor_project = EXCLUDED.vendor_project,
			product = EXCLUDED.product,
			vulnerability_name = EXCLUDED.vulnerability_name,
			date_added = EXCLUDED.date_added,
			short_description = EXCLUDED.short_description,
			required_action = EXCLUDED.required_action,
			due_date = EXCLUDED.due_date,
			known_ransomware_campaign_use = EXCLUDED.known_ransomware_campaign_use,
			notes = EXCLUDED.notes,
			cwes = EXCLUDED.cwes,
			raw_json = EXCLUDED.raw_json`,
		cveID,
		cveID,
		record.VendorProject,
		record.Product,
		record.VulnerabilityName,
		record.DateAdded,
		record.ShortDescription,
		record.RequiredAction,
		record.DueDate,
		record.KnownRansomwareCampaignUse,
		nullIfEmpty(record.Notes),
		pgTextArray(record.CWEs),
		[]byte(record.RawJSON),
	)
	if err != nil {
		return fmt.Errorf("upsert kev_entry: %w", err)
	}

	return nil
}

// GetKEVByVulnerabilityID retrieves the KEV entry for a vulnerability.
// Returns nil, nil if no KEV entry exists for the given vulnerability.
func (s *PostgresStore) GetKEVByVulnerabilityID(ctx context.Context, vulnID string) (*model.KEVRecord, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT cve_id, vendor_project, product, vulnerability_name,
			   date_added, short_description, required_action, due_date,
			   known_ransomware_campaign_use, notes, cwes, raw_json
		FROM kev_entries
		WHERE vulnerability_id = $1`,
		vulnID,
	)

	return scanKEVRecord(row)
}

// GetKEVByCVEID retrieves the KEV entry for a specific CVE ID.
// Returns nil, nil if no KEV entry exists.
func (s *PostgresStore) GetKEVByCVEID(ctx context.Context, cveID string) (*model.KEVRecord, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT cve_id, vendor_project, product, vulnerability_name,
			   date_added, short_description, required_action, due_date,
			   known_ransomware_campaign_use, notes, cwes, raw_json
		FROM kev_entries
		WHERE cve_id = $1`,
		cveID,
	)

	return scanKEVRecord(row)
}

// CountKEVEntries returns the total number of KEV entries in the database.
func (s *PostgresStore) CountKEVEntries(ctx context.Context) (int64, error) {
	var count int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM kev_entries`).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count KEV entries: %w", err)
	}
	return count, nil
}

// scanKEVRecord scans a single row into a KEVRecord.
func scanKEVRecord(row *sql.Row) (*model.KEVRecord, error) {
	var record model.KEVRecord
	var notes sql.NullString
	var cwes []byte
	var rawJSON []byte

	if err := row.Scan(
		&record.CVEID,
		&record.VendorProject,
		&record.Product,
		&record.VulnerabilityName,
		&record.DateAdded,
		&record.ShortDescription,
		&record.RequiredAction,
		&record.DueDate,
		&record.KnownRansomwareCampaignUse,
		&notes,
		&cwes,
		&rawJSON,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("query KEV entry: %w", err)
	}

	if notes.Valid {
		record.Notes = notes.String
	}
	if cwes != nil {
		record.CWEs = parseTextArray(string(cwes))
	}
	record.RawJSON = rawJSON

	return &record, nil
}
