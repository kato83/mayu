package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/kato83/mayu/internal/model"
)

// TranslationQuery specifies which translations to fetch.
type TranslationQuery struct {
	// VulnerabilityID is the vulnerability to fetch translations for.
	VulnerabilityID string

	// Locales is the list of preferred locales (BCP 47 tags), ordered by preference.
	Locales []string
}

// TranslationResult holds all translation data for a vulnerability detail response.
type TranslationResult struct {
	// Vulnerability translations (summary, details)
	Vulnerability []model.VulnerabilityTranslation

	// KEV translations (vulnerability_name, short_description, required_action, notes)
	KEV []model.KEVTranslation

	// NVD description translations
	NVDDescriptions []model.NVDDescriptionTranslation

	// MITREProblemTypes is a flat list of translations for all MITRE problem types,
	// ordered to match the problem types returned by fetchMITREProblemTypes.
	MITREProblemTypes [][]model.MITREProblemTypeTranslation

	// MITRECredits is a flat list of translations for all MITRE credits,
	// ordered to match the credits returned by fetchMITRECredits.
	MITRECredits [][]model.MITRECreditTranslation
}

// GetTranslations retrieves all available translations for a vulnerability detail.
// It queries translation tables for the specified locales and returns results
// grouped by source type.
func (s *PostgresStore) GetTranslations(ctx context.Context, q TranslationQuery) (*TranslationResult, error) {
	if len(q.Locales) == 0 || q.VulnerabilityID == "" {
		return nil, nil
	}

	result := &TranslationResult{}

	// 1. Vulnerability translations
	vulnTranslations, err := s.fetchVulnerabilityTranslations(ctx, q.VulnerabilityID, q.Locales)
	if err != nil {
		return nil, fmt.Errorf("fetch vulnerability translations: %w", err)
	}
	result.Vulnerability = vulnTranslations

	// 2. KEV translations
	kevTranslations, err := s.fetchKEVTranslations(ctx, q.VulnerabilityID, q.Locales)
	if err != nil {
		return nil, fmt.Errorf("fetch KEV translations: %w", err)
	}
	result.KEV = kevTranslations

	// 3. NVD description translations
	nvdTranslations, err := s.fetchNVDDescriptionTranslations(ctx, q.VulnerabilityID, q.Locales)
	if err != nil {
		return nil, fmt.Errorf("fetch NVD description translations: %w", err)
	}
	result.NVDDescriptions = nvdTranslations

	// 4. MITRE problem type translations (ordered by problem type position)
	ptTranslations, err := s.fetchMITREProblemTypeTranslationsOrdered(ctx, q.VulnerabilityID, q.Locales)
	if err != nil {
		return nil, fmt.Errorf("fetch MITRE problem type translations: %w", err)
	}
	result.MITREProblemTypes = ptTranslations

	// 5. MITRE credit translations (ordered by credit position)
	creditTranslations, err := s.fetchMITRECreditTranslationsOrdered(ctx, q.VulnerabilityID, q.Locales)
	if err != nil {
		return nil, fmt.Errorf("fetch MITRE credit translations: %w", err)
	}
	result.MITRECredits = creditTranslations

	return result, nil
}

// fetchVulnerabilityTranslations gets translations from vulnerabilities_translation.
func (s *PostgresStore) fetchVulnerabilityTranslations(ctx context.Context, vulnID string, locales []string) ([]model.VulnerabilityTranslation, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT locale, summary, details, translated_at
		 FROM vulnerabilities_translation
		 WHERE vulnerability_id = $1 AND locale = ANY($2)
		 ORDER BY translated_at DESC`,
		vulnID, locales)
	if err != nil {
		return nil, fmt.Errorf("query vulnerabilities_translation: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var translations []model.VulnerabilityTranslation
	for rows.Next() {
		var t model.VulnerabilityTranslation
		var summary, details sql.NullString
		if err := rows.Scan(&t.Locale, &summary, &details, &t.TranslatedAt); err != nil {
			return nil, fmt.Errorf("scan vulnerability translation: %w", err)
		}
		if summary.Valid {
			t.Summary = &summary.String
		}
		if details.Valid {
			t.Details = &details.String
		}
		translations = append(translations, t)
	}
	return translations, rows.Err()
}

// fetchKEVTranslations gets translations from kev_entries_translation.
func (s *PostgresStore) fetchKEVTranslations(ctx context.Context, vulnID string, locales []string) ([]model.KEVTranslation, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT kt.locale, kt.vulnerability_name, kt.short_description,
		        kt.required_action, kt.notes, kt.translated_at
		 FROM kev_entries_translation kt
		 JOIN kev_entries ke ON ke.id = kt.kev_entry_id
		 WHERE ke.vulnerability_id = $1 AND kt.locale = ANY($2)
		 ORDER BY kt.translated_at DESC`,
		vulnID, locales)
	if err != nil {
		return nil, fmt.Errorf("query kev_entries_translation: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var translations []model.KEVTranslation
	for rows.Next() {
		var t model.KEVTranslation
		var vulnName, shortDesc, reqAction, notes sql.NullString
		if err := rows.Scan(&t.Locale, &vulnName, &shortDesc, &reqAction, &notes, &t.TranslatedAt); err != nil {
			return nil, fmt.Errorf("scan KEV translation: %w", err)
		}
		if vulnName.Valid {
			t.VulnerabilityName = &vulnName.String
		}
		if shortDesc.Valid {
			t.ShortDescription = &shortDesc.String
		}
		if reqAction.Valid {
			t.RequiredAction = &reqAction.String
		}
		if notes.Valid {
			t.Notes = &notes.String
		}
		translations = append(translations, t)
	}
	return translations, rows.Err()
}

// fetchNVDDescriptionTranslations gets translations from nvd_descriptions_translation.
func (s *PostgresStore) fetchNVDDescriptionTranslations(ctx context.Context, vulnID string, locales []string) ([]model.NVDDescriptionTranslation, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT ndt.locale, ndt.value, ndt.translated_at
		 FROM nvd_descriptions_translation ndt
		 JOIN nvd_descriptions nd ON nd.id = ndt.nvd_description_id
		 JOIN nvd_entries ne ON ne.id = nd.nvd_entry_id
		 WHERE ne.vulnerability_id = $1 AND nd.lang = 'en' AND ndt.locale = ANY($2)
		 ORDER BY ndt.translated_at DESC`,
		vulnID, locales)
	if err != nil {
		return nil, fmt.Errorf("query nvd_descriptions_translation: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var translations []model.NVDDescriptionTranslation
	for rows.Next() {
		var t model.NVDDescriptionTranslation
		if err := rows.Scan(&t.Locale, &t.Value, &t.TranslatedAt); err != nil {
			return nil, fmt.Errorf("scan NVD description translation: %w", err)
		}
		translations = append(translations, t)
	}
	return translations, rows.Err()
}

// fetchMITREProblemTypeTranslationsOrdered gets translations from mitre_problem_types_translation
// returned as an ordered slice of slices, matching the order problem types are stored in the DB.
func (s *PostgresStore) fetchMITREProblemTypeTranslationsOrdered(ctx context.Context, vulnID string, locales []string) ([][]model.MITREProblemTypeTranslation, error) {
	// First get the problem type IDs in order
	idRows, err := s.db.QueryContext(ctx,
		`SELECT mpt.id
		 FROM mitre_problem_types mpt
		 JOIN mitre_containers mc ON mc.id = mpt.container_id
		 JOIN mitre_entries me ON me.id = mc.mitre_entry_id
		 WHERE me.vulnerability_id = $1
		 ORDER BY mpt.id`,
		vulnID)
	if err != nil {
		return nil, fmt.Errorf("query mitre_problem_type ids: %w", err)
	}
	defer func() { _ = idRows.Close() }()

	var ptIDs []int64
	for idRows.Next() {
		var id int64
		if err := idRows.Scan(&id); err != nil {
			return nil, err
		}
		ptIDs = append(ptIDs, id)
	}
	if err := idRows.Err(); err != nil {
		return nil, err
	}
	if len(ptIDs) == 0 {
		return nil, nil
	}

	// Fetch translations for these IDs
	rows, err := s.db.QueryContext(ctx,
		`SELECT mptt.problem_type_id, mptt.locale, mptt.description, mptt.translated_at
		 FROM mitre_problem_types_translation mptt
		 WHERE mptt.problem_type_id = ANY($1) AND mptt.locale = ANY($2)
		 ORDER BY mptt.problem_type_id, mptt.translated_at DESC`,
		ptIDs, locales)
	if err != nil {
		return nil, fmt.Errorf("query mitre_problem_types_translation: %w", err)
	}
	defer func() { _ = rows.Close() }()

	byID := make(map[int64][]model.MITREProblemTypeTranslation)
	for rows.Next() {
		var ptID int64
		var t model.MITREProblemTypeTranslation
		if err := rows.Scan(&ptID, &t.Locale, &t.Description, &t.TranslatedAt); err != nil {
			return nil, fmt.Errorf("scan MITRE problem type translation: %w", err)
		}
		byID[ptID] = append(byID[ptID], t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Build ordered result
	result := make([][]model.MITREProblemTypeTranslation, len(ptIDs))
	for i, id := range ptIDs {
		result[i] = byID[id]
	}
	return result, nil
}

// fetchMITRECreditTranslationsOrdered gets translations from mitre_credits_translation
// returned as an ordered slice of slices, matching the order credits are stored in the DB.
func (s *PostgresStore) fetchMITRECreditTranslationsOrdered(ctx context.Context, vulnID string, locales []string) ([][]model.MITRECreditTranslation, error) {
	// First get the credit IDs in order
	idRows, err := s.db.QueryContext(ctx,
		`SELECT mc2.id
		 FROM mitre_credits mc2
		 JOIN mitre_containers mc ON mc.id = mc2.container_id
		 JOIN mitre_entries me ON me.id = mc.mitre_entry_id
		 WHERE me.vulnerability_id = $1
		 ORDER BY mc2.id`,
		vulnID)
	if err != nil {
		return nil, fmt.Errorf("query mitre_credit ids: %w", err)
	}
	defer func() { _ = idRows.Close() }()

	var creditIDs []int64
	for idRows.Next() {
		var id int64
		if err := idRows.Scan(&id); err != nil {
			return nil, err
		}
		creditIDs = append(creditIDs, id)
	}
	if err := idRows.Err(); err != nil {
		return nil, err
	}
	if len(creditIDs) == 0 {
		return nil, nil
	}

	// Fetch translations for these IDs
	rows, err := s.db.QueryContext(ctx,
		`SELECT mct.credit_id, mct.locale, mct.value, mct.translated_at
		 FROM mitre_credits_translation mct
		 WHERE mct.credit_id = ANY($1) AND mct.locale = ANY($2)
		 ORDER BY mct.credit_id, mct.translated_at DESC`,
		creditIDs, locales)
	if err != nil {
		return nil, fmt.Errorf("query mitre_credits_translation: %w", err)
	}
	defer func() { _ = rows.Close() }()

	byID := make(map[int64][]model.MITRECreditTranslation)
	for rows.Next() {
		var creditID int64
		var t model.MITRECreditTranslation
		if err := rows.Scan(&creditID, &t.Locale, &t.Value, &t.TranslatedAt); err != nil {
			return nil, fmt.Errorf("scan MITRE credit translation: %w", err)
		}
		byID[creditID] = append(byID[creditID], t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Build ordered result
	result := make([][]model.MITRECreditTranslation, len(creditIDs))
	for i, id := range creditIDs {
		result[i] = byID[id]
	}
	return result, nil
}
