package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// SaveVulnerabilityTranslation upserts a translation for a vulnerability's summary/details.
func (s *PostgresStore) SaveVulnerabilityTranslation(ctx context.Context, vulnID, locale, summary, details string, translatedAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO vulnerabilities_translation (vulnerability_id, locale, summary, details, translated_at)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (vulnerability_id, locale) DO UPDATE SET
		   summary = EXCLUDED.summary,
		   details = EXCLUDED.details,
		   translated_at = EXCLUDED.translated_at`,
		vulnID, locale, nullIfEmpty(summary), nullIfEmpty(details), translatedAt)
	if err != nil {
		return fmt.Errorf("upsert vulnerabilities_translation: %w", err)
	}
	return nil
}

// SaveKEVTranslation upserts a translation for KEV entry text fields.
func (s *PostgresStore) SaveKEVTranslation(ctx context.Context, kevEntryID int64, locale, vulnName, shortDesc, reqAction, notes string, translatedAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO kev_entries_translation (kev_entry_id, locale, vulnerability_name, short_description, required_action, notes, translated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 ON CONFLICT (kev_entry_id, locale) DO UPDATE SET
		   vulnerability_name = EXCLUDED.vulnerability_name,
		   short_description = EXCLUDED.short_description,
		   required_action = EXCLUDED.required_action,
		   notes = EXCLUDED.notes,
		   translated_at = EXCLUDED.translated_at`,
		kevEntryID, locale, nullIfEmpty(vulnName), nullIfEmpty(shortDesc), nullIfEmpty(reqAction), nullIfEmpty(notes), translatedAt)
	if err != nil {
		return fmt.Errorf("upsert kev_entries_translation: %w", err)
	}
	return nil
}

// SaveNVDDescriptionTranslation upserts a translation for an NVD description.
func (s *PostgresStore) SaveNVDDescriptionTranslation(ctx context.Context, nvdDescID int64, locale, value string, translatedAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO nvd_descriptions_translation (nvd_description_id, locale, value, translated_at)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (nvd_description_id, locale) DO UPDATE SET
		   value = EXCLUDED.value,
		   translated_at = EXCLUDED.translated_at`,
		nvdDescID, locale, value, translatedAt)
	if err != nil {
		return fmt.Errorf("upsert nvd_descriptions_translation: %w", err)
	}
	return nil
}

// GetTranslatableTexts fetches all translatable text fields for a vulnerability.
// Returns the texts along with the DB IDs needed for storing translations.
func (s *PostgresStore) GetTranslatableTexts(ctx context.Context, vulnID string) (*TranslatableTexts, error) {
	result := &TranslatableTexts{VulnerabilityID: vulnID}

	// Get vulnerability summary and details
	err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(summary, ''), COALESCE(details, '') FROM vulnerabilities WHERE id = $1`,
		vulnID).Scan(&result.Summary, &result.Details)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query vulnerability texts: %w", err)
	}

	// Get NVD English description and its ID
	err = s.db.QueryRowContext(ctx,
		`SELECT nd.id, nd.value FROM nvd_descriptions nd
		 JOIN nvd_entries ne ON ne.id = nd.nvd_entry_id
		 WHERE ne.vulnerability_id = $1 AND nd.lang = 'en'
		 LIMIT 1`,
		vulnID).Scan(&result.NVDDescriptionID, &result.NVDDescription)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("query NVD description: %w", err)
	}

	// Get KEV entry and its fields
	err = s.db.QueryRowContext(ctx,
		`SELECT id, COALESCE(vulnerability_name, ''), COALESCE(short_description, ''),
		        COALESCE(required_action, ''), COALESCE(notes, '')
		 FROM kev_entries WHERE vulnerability_id = $1`,
		vulnID).Scan(&result.KEVEntryID, &result.KEVVulnerabilityName, &result.KEVShortDescription, &result.KEVRequiredAction, &result.KEVNotes)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("query KEV entry: %w", err)
	}

	// Get OSV entries with their summary/details
	osvRows, err := s.db.QueryContext(ctx,
		`SELECT osv_id, COALESCE(summary, ''), COALESCE(details, '')
		 FROM osv_entries WHERE vulnerability_id = $1 ORDER BY osv_id`,
		vulnID)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("query OSV entries: %w", err)
	}
	if err == nil {
		defer func() { _ = osvRows.Close() }()
		for osvRows.Next() {
			var entry OSVEntryTexts
			if err := osvRows.Scan(&entry.OsvID, &entry.Summary, &entry.Details); err != nil {
				return nil, fmt.Errorf("scan OSV entry: %w", err)
			}
			// Only include entries that have translatable text
			if entry.Summary != "" || entry.Details != "" {
				result.OSVEntries = append(result.OSVEntries, entry)
			}
		}
		if err := osvRows.Err(); err != nil {
			return nil, fmt.Errorf("iterate OSV entries: %w", err)
		}
	}

	return result, nil
}

// TranslatableTexts holds all translatable text fields with their DB IDs.
type TranslatableTexts struct {
	VulnerabilityID      string
	Summary              string
	Details              string
	NVDDescriptionID     int64
	NVDDescription       string
	KEVEntryID           int64
	KEVVulnerabilityName string
	KEVShortDescription  string
	KEVRequiredAction    string
	KEVNotes             string
	OSVEntries           []OSVEntryTexts
}

// OSVEntryTexts holds translatable texts for a single OSV entry.
type OSVEntryTexts struct {
	OsvID   string
	Summary string
	Details string
}

// SaveOSVEntryTranslation upserts a translation for an OSV entry's summary/details.
func (s *PostgresStore) SaveOSVEntryTranslation(ctx context.Context, osvEntryID, locale, summary, details string, translatedAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO osv_entries_translation (osv_entry_id, locale, summary, details, translated_at)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (osv_entry_id, locale) DO UPDATE SET
		   summary = EXCLUDED.summary,
		   details = EXCLUDED.details,
		   translated_at = EXCLUDED.translated_at`,
		osvEntryID, locale, nullIfEmpty(summary), nullIfEmpty(details), translatedAt)
	if err != nil {
		return fmt.Errorf("upsert osv_entries_translation: %w", err)
	}
	return nil
}
