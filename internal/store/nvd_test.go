//go:build integration

package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/kato83/mayu/internal/model"
	"github.com/kato83/mayu/internal/testhelper"
)

func setupNVDTestStore(t *testing.T) *PostgresStore {
	t.Helper()
	ctx := context.Background()

	pg := testhelper.SetupPostgres(t)

	store, err := NewPostgresStore(ctx, pg.DatabaseURL)
	if err != nil {
		t.Fatalf("failed to connect to test database: %v", err)
	}

	// Clean all tables before each test
	if err := store.CleanAll(ctx); err != nil {
		t.Fatalf("failed to clean tables: %v", err)
	}

	t.Cleanup(func() {
		store.Close()
	})

	return store
}

// makeTestNVDCVE creates a realistic NVDCVE entry for testing.
func makeTestNVDCVE() *model.NVDCVE {
	published := model.NVDTime{Time: time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC)}
	lastModified := model.NVDTime{Time: time.Date(2024, 6, 20, 14, 30, 0, 0, time.UTC)}

	cvssV31Data := json.RawMessage(`{
		"version": "3.1",
		"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"baseScore": 9.8,
		"baseSeverity": "CRITICAL"
	}`)

	boolTrue := true

	entry := &model.NVDCVE{
		ID:               "CVE-2024-12345",
		SourceIdentifier: "cve@mitre.org",
		VulnStatus:       "Analyzed",
		Published:        published,
		LastModified:     lastModified,
		Descriptions: []model.NVDLangString{
			{Lang: "en", Value: "A critical vulnerability in example software allows remote code execution."},
			{Lang: "es", Value: "Una vulnerabilidad crítica en el software de ejemplo permite la ejecución remota de código."},
		},
		Metrics: model.NVDMetrics{
			CvssMetricV31: []model.NVDCVSSMetricV31{
				{
					Source:              "nvd@nist.gov",
					Type:                "Primary",
					CvssData:            cvssV31Data,
					ExploitabilityScore: float64Ptr(3.9),
					ImpactScore:         float64Ptr(5.9),
				},
			},
		},
		Weaknesses: []model.NVDWeakness{
			{
				Source: "nvd@nist.gov",
				Type:   "Primary",
				Description: []model.NVDLangString{
					{Lang: "en", Value: "CWE-79"},
				},
			},
		},
		Configurations: []model.NVDConfiguration{
			{
				Operator: "OR",
				Negate:   &boolTrue,
				Nodes: []model.NVDNode{
					{
						Operator: "OR",
						CpeMatch: []model.NVDCPEMatch{
							{
								Vulnerable:          true,
								Criteria:            "cpe:2.3:a:example:software:*:*:*:*:*:*:*:*",
								MatchCriteriaId:     "A1B2C3D4-E5F6-7890-ABCD-EF1234567890",
								VersionEndExcluding: "2.0.0",
							},
						},
					},
				},
			},
		},
		References: []model.NVDReference{
			{
				URL:    "https://example.com/advisory/CVE-2024-12345",
				Source: "cve@mitre.org",
				Tags:   []string{"Vendor Advisory", "Patch"},
			},
			{
				URL:    "https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
				Source: "nvd@nist.gov",
				Tags:   []string{"Third Party Advisory"},
			},
		},
	}

	// Marshal to populate RawJSON
	rawJSON, _ := json.Marshal(entry)
	entry.RawJSON = rawJSON

	return entry
}

func float64Ptr(f float64) *float64 {
	return &f
}

func TestUpsertNVDBatch_Basic(t *testing.T) {
	store := setupNVDTestStore(t)
	ctx := context.Background()

	entry := makeTestNVDCVE()

	// Upsert
	if err := store.UpsertNVDBatch(ctx, []*model.NVDCVE{entry}); err != nil {
		t.Fatalf("UpsertNVDBatch failed: %v", err)
	}

	// Verify vulnerabilities table
	var vulnID, source string
	var published, modified time.Time
	var summary *string
	err := store.db.QueryRowContext(ctx, `
		SELECT id, source, summary, published, modified FROM vulnerabilities WHERE id = $1`,
		"CVE-2024-12345",
	).Scan(&vulnID, &source, &summary, &published, &modified)
	if err != nil {
		t.Fatalf("query vulnerabilities: %v", err)
	}
	if vulnID != "CVE-2024-12345" {
		t.Errorf("vulnerability id = %q, want CVE-2024-12345", vulnID)
	}
	if source != "nvd" {
		t.Errorf("vulnerability source = %q, want nvd", source)
	}
	if summary == nil || *summary == "" {
		t.Error("vulnerability summary should not be empty")
	}
	if !published.Equal(entry.Published.Time) {
		t.Errorf("published = %v, want %v", published, entry.Published.Time)
	}
	if !modified.Equal(entry.LastModified.Time) {
		t.Errorf("modified = %v, want %v", modified, entry.LastModified.Time)
	}

	// Verify nvd_entries table
	var nvdEntryID int64
	var cveID, vulnStatusDB string
	var rawJSONDB []byte
	err = store.db.QueryRowContext(ctx, `
		SELECT id, cve_id, vuln_status, raw_json FROM nvd_entries WHERE cve_id = $1`,
		"CVE-2024-12345",
	).Scan(&nvdEntryID, &cveID, &vulnStatusDB, &rawJSONDB)
	if err != nil {
		t.Fatalf("query nvd_entries: %v", err)
	}
	if cveID != "CVE-2024-12345" {
		t.Errorf("nvd_entries.cve_id = %q, want CVE-2024-12345", cveID)
	}
	if vulnStatusDB != "Analyzed" {
		t.Errorf("nvd_entries.vuln_status = %q, want Analyzed", vulnStatusDB)
	}
	if len(rawJSONDB) == 0 {
		t.Error("nvd_entries.raw_json should not be empty")
	}

	// Verify nvd_descriptions
	var descValue string
	err = store.db.QueryRowContext(ctx, `
		SELECT value FROM nvd_descriptions WHERE nvd_entry_id = $1 AND lang = 'en'`,
		nvdEntryID,
	).Scan(&descValue)
	if err != nil {
		t.Fatalf("query nvd_descriptions: %v", err)
	}
	if descValue != "A critical vulnerability in example software allows remote code execution." {
		t.Errorf("description = %q, want expected English text", descValue)
	}

	// Verify nvd_metrics
	var baseScore float64
	var baseSeverity, metricVersion string
	err = store.db.QueryRowContext(ctx, `
		SELECT version, base_score, base_severity FROM nvd_metrics WHERE nvd_entry_id = $1`,
		nvdEntryID,
	).Scan(&metricVersion, &baseScore, &baseSeverity)
	if err != nil {
		t.Fatalf("query nvd_metrics: %v", err)
	}
	if metricVersion != "v31" {
		t.Errorf("metric version = %q, want v31", metricVersion)
	}
	if baseScore != 9.8 {
		t.Errorf("base_score = %f, want 9.8", baseScore)
	}
	if baseSeverity != "CRITICAL" {
		t.Errorf("base_severity = %q, want CRITICAL", baseSeverity)
	}

	// Verify nvd_weaknesses
	var cweID string
	err = store.db.QueryRowContext(ctx, `
		SELECT cwe_id FROM nvd_weaknesses WHERE nvd_entry_id = $1`,
		nvdEntryID,
	).Scan(&cweID)
	if err != nil {
		t.Fatalf("query nvd_weaknesses: %v", err)
	}
	if cweID != "CWE-79" {
		t.Errorf("cwe_id = %q, want CWE-79", cweID)
	}

	// Verify nvd_configurations
	var configID int64
	var configOperator string
	var configNegate bool
	err = store.db.QueryRowContext(ctx, `
		SELECT id, operator, negate FROM nvd_configurations WHERE nvd_entry_id = $1`,
		nvdEntryID,
	).Scan(&configID, &configOperator, &configNegate)
	if err != nil {
		t.Fatalf("query nvd_configurations: %v", err)
	}
	if configOperator != "OR" {
		t.Errorf("config operator = %q, want OR", configOperator)
	}
	if !configNegate {
		t.Error("config negate should be true")
	}

	// Verify nvd_cpe_matches
	var criteria, matchCriteriaID string
	var vulnerable bool
	var versionEndExcluding *string
	err = store.db.QueryRowContext(ctx, `
		SELECT vulnerable, criteria, match_criteria_id, version_end_excluding
		FROM nvd_cpe_matches WHERE configuration_id = $1`,
		configID,
	).Scan(&vulnerable, &criteria, &matchCriteriaID, &versionEndExcluding)
	if err != nil {
		t.Fatalf("query nvd_cpe_matches: %v", err)
	}
	if !vulnerable {
		t.Error("cpe_match.vulnerable should be true")
	}
	if criteria != "cpe:2.3:a:example:software:*:*:*:*:*:*:*:*" {
		t.Errorf("criteria = %q, want expected CPE URI", criteria)
	}
	if matchCriteriaID != "A1B2C3D4-E5F6-7890-ABCD-EF1234567890" {
		t.Errorf("match_criteria_id = %q, want expected UUID", matchCriteriaID)
	}
	if versionEndExcluding == nil || *versionEndExcluding != "2.0.0" {
		t.Errorf("version_end_excluding = %v, want 2.0.0", versionEndExcluding)
	}

	// Verify nvd_references
	var refCount int
	err = store.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM nvd_references WHERE nvd_entry_id = $1`,
		nvdEntryID,
	).Scan(&refCount)
	if err != nil {
		t.Fatalf("query nvd_references count: %v", err)
	}
	if refCount != 2 {
		t.Errorf("reference count = %d, want 2", refCount)
	}

	var refURL string
	err = store.db.QueryRowContext(ctx, `
		SELECT url FROM nvd_references WHERE nvd_entry_id = $1 AND source = 'cve@mitre.org'`,
		nvdEntryID,
	).Scan(&refURL)
	if err != nil {
		t.Fatalf("query nvd_references by source: %v", err)
	}
	if refURL != "https://example.com/advisory/CVE-2024-12345" {
		t.Errorf("reference url = %q, want expected URL", refURL)
	}
}

func TestUpsertNVDBatch_Update(t *testing.T) {
	store := setupNVDTestStore(t)
	ctx := context.Background()

	entry := makeTestNVDCVE()

	// First upsert
	if err := store.UpsertNVDBatch(ctx, []*model.NVDCVE{entry}); err != nil {
		t.Fatalf("first UpsertNVDBatch failed: %v", err)
	}

	// Update with newer lastModified and changed description
	updatedEntry := makeTestNVDCVE()
	updatedEntry.LastModified = model.NVDTime{Time: time.Date(2024, 9, 1, 0, 0, 0, 0, time.UTC)}
	updatedEntry.Descriptions = []model.NVDLangString{
		{Lang: "en", Value: "Updated description of the vulnerability."},
	}
	updatedEntry.VulnStatus = "Modified"
	rawJSON, _ := json.Marshal(updatedEntry)
	updatedEntry.RawJSON = rawJSON

	// Second upsert
	if err := store.UpsertNVDBatch(ctx, []*model.NVDCVE{updatedEntry}); err != nil {
		t.Fatalf("second UpsertNVDBatch failed: %v", err)
	}

	// Verify vulnerabilities.modified was updated
	var modified time.Time
	err := store.db.QueryRowContext(ctx, `
		SELECT modified FROM vulnerabilities WHERE id = $1`, "CVE-2024-12345",
	).Scan(&modified)
	if err != nil {
		t.Fatalf("query modified: %v", err)
	}
	expectedModified := time.Date(2024, 9, 1, 0, 0, 0, 0, time.UTC)
	if !modified.Equal(expectedModified) {
		t.Errorf("modified = %v, want %v", modified, expectedModified)
	}

	// Verify nvd_entries has only 1 row (old was replaced)
	var entryCount int
	err = store.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM nvd_entries WHERE cve_id = $1`, "CVE-2024-12345",
	).Scan(&entryCount)
	if err != nil {
		t.Fatalf("query nvd_entries count: %v", err)
	}
	if entryCount != 1 {
		t.Errorf("nvd_entries count = %d, want 1", entryCount)
	}

	// Verify vuln_status was updated
	var vulnStatus string
	err = store.db.QueryRowContext(ctx, `
		SELECT vuln_status FROM nvd_entries WHERE cve_id = $1`, "CVE-2024-12345",
	).Scan(&vulnStatus)
	if err != nil {
		t.Fatalf("query vuln_status: %v", err)
	}
	if vulnStatus != "Modified" {
		t.Errorf("vuln_status = %q, want Modified", vulnStatus)
	}

	// Verify description was updated (only 1 description now)
	var descCount int
	var nvdEntryID int64
	err = store.db.QueryRowContext(ctx, `SELECT id FROM nvd_entries WHERE cve_id = $1`, "CVE-2024-12345").Scan(&nvdEntryID)
	if err != nil {
		t.Fatalf("query nvd_entry_id: %v", err)
	}
	err = store.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM nvd_descriptions WHERE nvd_entry_id = $1`, nvdEntryID,
	).Scan(&descCount)
	if err != nil {
		t.Fatalf("query description count: %v", err)
	}
	if descCount != 1 {
		t.Errorf("description count = %d, want 1 (old descriptions should be removed)", descCount)
	}

	var descValue string
	err = store.db.QueryRowContext(ctx, `
		SELECT value FROM nvd_descriptions WHERE nvd_entry_id = $1 AND lang = 'en'`, nvdEntryID,
	).Scan(&descValue)
	if err != nil {
		t.Fatalf("query description value: %v", err)
	}
	if descValue != "Updated description of the vulnerability." {
		t.Errorf("description = %q, want updated text", descValue)
	}
}

func TestUpsertNVDBatch_MergeWithOSV(t *testing.T) {
	store := setupNVDTestStore(t)
	ctx := context.Background()

	osvModified := time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)

	// First: insert an OSV entry that has CVE-2024-99999 as canonical ID
	osvVuln := &model.Vulnerability{
		ID:       "GO-2024-9999",
		Modified: osvModified,
		Summary:  "OSV summary for this vulnerability",
		Aliases:  []string{"CVE-2024-99999"},
		Affected: []model.Affected{{
			Package: model.Package{Ecosystem: "Go", Name: "example.com/vulnerable"},
		}},
	}
	if err := store.Insert(ctx, osvVuln); err != nil {
		t.Fatalf("Insert OSV entry failed: %v", err)
	}

	// Verify OSV entry exists under CVE canonical ID
	var osvVulnID string
	err := store.db.QueryRowContext(ctx, `
		SELECT vulnerability_id FROM osv_entries WHERE osv_id = $1`, "GO-2024-9999",
	).Scan(&osvVulnID)
	if err != nil {
		t.Fatalf("query osv_entries: %v", err)
	}
	if osvVulnID != "CVE-2024-99999" {
		t.Fatalf("osv vulnerability_id = %q, want CVE-2024-99999", osvVulnID)
	}

	// Now upsert NVD entry for the same CVE with a later modified time
	nvdEntry := &model.NVDCVE{
		ID:               "CVE-2024-99999",
		SourceIdentifier: "nvd@nist.gov",
		VulnStatus:       "Analyzed",
		Published:        model.NVDTime{Time: time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC)},
		LastModified:     model.NVDTime{Time: time.Date(2024, 7, 15, 0, 0, 0, 0, time.UTC)},
		Descriptions: []model.NVDLangString{
			{Lang: "en", Value: "NVD description of CVE-2024-99999"},
		},
		References: []model.NVDReference{
			{URL: "https://nvd.nist.gov/vuln/detail/CVE-2024-99999", Source: "nvd@nist.gov"},
		},
	}
	rawJSON, _ := json.Marshal(nvdEntry)
	nvdEntry.RawJSON = rawJSON

	if err := store.UpsertNVDBatch(ctx, []*model.NVDCVE{nvdEntry}); err != nil {
		t.Fatalf("UpsertNVDBatch failed: %v", err)
	}

	// Verify: only 1 vulnerabilities row
	var vulnCount int
	err = store.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM vulnerabilities WHERE id = $1`, "CVE-2024-99999",
	).Scan(&vulnCount)
	if err != nil {
		t.Fatalf("query vulnerabilities count: %v", err)
	}
	if vulnCount != 1 {
		t.Errorf("vulnerabilities count = %d, want 1", vulnCount)
	}

	// Verify: modified uses GREATEST (NVD is newer: 2024-07-15 > 2024-03-01)
	var modified time.Time
	err = store.db.QueryRowContext(ctx, `
		SELECT modified FROM vulnerabilities WHERE id = $1`, "CVE-2024-99999",
	).Scan(&modified)
	if err != nil {
		t.Fatalf("query modified: %v", err)
	}
	expectedModified := time.Date(2024, 7, 15, 0, 0, 0, 0, time.UTC)
	if !modified.Equal(expectedModified) {
		t.Errorf("modified = %v, want %v (should use GREATEST)", modified, expectedModified)
	}

	// Verify: OSV summary is preserved (COALESCE logic — NVD summary should NOT overwrite)
	var summary string
	err = store.db.QueryRowContext(ctx, `
		SELECT summary FROM vulnerabilities WHERE id = $1`, "CVE-2024-99999",
	).Scan(&summary)
	if err != nil {
		t.Fatalf("query summary: %v", err)
	}
	if summary != "OSV summary for this vulnerability" {
		t.Errorf("summary = %q, want OSV summary preserved", summary)
	}

	// Verify: both osv_entries and nvd_entries reference the same vulnerability_id
	var osvVulnIDAfter string
	err = store.db.QueryRowContext(ctx, `
		SELECT vulnerability_id FROM osv_entries WHERE osv_id = $1`, "GO-2024-9999",
	).Scan(&osvVulnIDAfter)
	if err != nil {
		t.Fatalf("query osv_entries after NVD insert: %v", err)
	}
	if osvVulnIDAfter != "CVE-2024-99999" {
		t.Errorf("osv vulnerability_id = %q, want CVE-2024-99999", osvVulnIDAfter)
	}

	var nvdVulnID string
	err = store.db.QueryRowContext(ctx, `
		SELECT vulnerability_id FROM nvd_entries WHERE cve_id = $1`, "CVE-2024-99999",
	).Scan(&nvdVulnID)
	if err != nil {
		t.Fatalf("query nvd_entries: %v", err)
	}
	if nvdVulnID != "CVE-2024-99999" {
		t.Errorf("nvd vulnerability_id = %q, want CVE-2024-99999", nvdVulnID)
	}
}

func TestUpsertNVDBatch_EmptyMetrics(t *testing.T) {
	store := setupNVDTestStore(t)
	ctx := context.Background()

	// Entry with no metrics, no weaknesses, no configurations
	entry := &model.NVDCVE{
		ID:               "CVE-2024-00001",
		SourceIdentifier: "cve@mitre.org",
		VulnStatus:       "Awaiting Analysis",
		Published:        model.NVDTime{Time: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
		LastModified:     model.NVDTime{Time: time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)},
		Descriptions: []model.NVDLangString{
			{Lang: "en", Value: "Minimal entry with no metrics."},
		},
		// Empty: no Metrics, no Weaknesses, no Configurations, no References
	}
	rawJSON, _ := json.Marshal(entry)
	entry.RawJSON = rawJSON

	// Should not error
	if err := store.UpsertNVDBatch(ctx, []*model.NVDCVE{entry}); err != nil {
		t.Fatalf("UpsertNVDBatch with empty metrics failed: %v", err)
	}

	// Verify vulnerabilities row exists
	var vulnID string
	err := store.db.QueryRowContext(ctx, `
		SELECT id FROM vulnerabilities WHERE id = $1`, "CVE-2024-00001",
	).Scan(&vulnID)
	if err != nil {
		t.Fatalf("query vulnerabilities: %v", err)
	}
	if vulnID != "CVE-2024-00001" {
		t.Errorf("vulnerability id = %q, want CVE-2024-00001", vulnID)
	}

	// Verify nvd_entries row exists
	var nvdEntryID int64
	err = store.db.QueryRowContext(ctx, `
		SELECT id FROM nvd_entries WHERE cve_id = $1`, "CVE-2024-00001",
	).Scan(&nvdEntryID)
	if err != nil {
		t.Fatalf("query nvd_entries: %v", err)
	}

	// Verify no metrics
	var metricCount int
	err = store.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM nvd_metrics WHERE nvd_entry_id = $1`, nvdEntryID,
	).Scan(&metricCount)
	if err != nil {
		t.Fatalf("query nvd_metrics count: %v", err)
	}
	if metricCount != 0 {
		t.Errorf("metric count = %d, want 0", metricCount)
	}

	// Verify no weaknesses
	var weaknessCount int
	err = store.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM nvd_weaknesses WHERE nvd_entry_id = $1`, nvdEntryID,
	).Scan(&weaknessCount)
	if err != nil {
		t.Fatalf("query nvd_weaknesses count: %v", err)
	}
	if weaknessCount != 0 {
		t.Errorf("weakness count = %d, want 0", weaknessCount)
	}

	// Verify no configurations
	var configCount int
	err = store.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM nvd_configurations WHERE nvd_entry_id = $1`, nvdEntryID,
	).Scan(&configCount)
	if err != nil {
		t.Fatalf("query nvd_configurations count: %v", err)
	}
	if configCount != 0 {
		t.Errorf("configuration count = %d, want 0", configCount)
	}

	// Verify no references
	var refCount int
	err = store.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM nvd_references WHERE nvd_entry_id = $1`, nvdEntryID,
	).Scan(&refCount)
	if err != nil {
		t.Fatalf("query nvd_references count: %v", err)
	}
	if refCount != 0 {
		t.Errorf("reference count = %d, want 0", refCount)
	}
}
