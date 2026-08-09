package audit

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/kato83/mayu/internal/sbom"
	"github.com/kato83/mayu/internal/store"
)

// mockEnrichmentStore implements EnrichmentStore for testing.
type mockEnrichmentStore struct {
	summaries map[string]*store.VulnSummaryRow
	err       error
}

func (m *mockEnrichmentStore) GetVulnSummariesByIDs(_ context.Context, ids []string) (map[string]*store.VulnSummaryRow, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.summaries == nil {
		return make(map[string]*store.VulnSummaryRow), nil
	}
	result := make(map[string]*store.VulnSummaryRow, len(ids))
	for _, id := range ids {
		if row, ok := m.summaries[id]; ok {
			result[id] = row
		}
	}
	return result, nil
}

func float64Ptr(v float64) *float64 { return &v }

func TestGenerateEnrichedSBOM_CycloneDX(t *testing.T) {
	originalCDX := `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "golang.org/x/crypto",
      "version": "0.30.0",
      "purl": "pkg:golang/golang.org/x/crypto@0.30.0"
    }
  ]
}`

	findings := []Finding{
		{
			Component: sbom.Component{
				Purl:      "pkg:golang/golang.org/x/crypto@0.30.0",
				Name:      "golang.org/x/crypto",
				Version:   "0.30.0",
				Ecosystem: "Go",
			},
			VulnID:       "CVE-2024-45337",
			Severity:     "CRITICAL",
			Summary:      "SSH handshake vulnerability in golang.org/x/crypto",
			FixedVersion: "0.31.0",
		},
	}

	mockStore := &mockEnrichmentStore{
		summaries: map[string]*store.VulnSummaryRow{
			"CVE-2024-45337": {
				VulnerabilityID: "CVE-2024-45337",
				SeverityWorst:   5,
				SeverityBest:    5,
				EPSSScore:       float64Ptr(0.42),
				EPSSPercentile:  float64Ptr(0.95),
				InKEV:           true,
				LEVScore:        float64Ptr(0.87),
			},
		},
	}

	result, err := GenerateEnrichedSBOM(context.Background(), mockStore, EnrichedSBOMOptions{
		OriginalData: []byte(originalCDX),
		Format:       sbom.FormatCycloneDX,
		Components:   []sbom.Component{{Purl: "pkg:golang/golang.org/x/crypto@0.30.0", Name: "golang.org/x/crypto", Version: "0.30.0", Ecosystem: "Go"}},
		Findings:     findings,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify output is valid JSON
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(result, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// Verify original fields preserved
	if _, ok := doc["bomFormat"]; !ok {
		t.Error("bomFormat field missing from output")
	}
	if _, ok := doc["components"]; !ok {
		t.Error("components field missing from output")
	}

	// Verify vulnerabilities section exists
	vulnsRaw, ok := doc["vulnerabilities"]
	if !ok {
		t.Fatal("vulnerabilities field missing from output")
	}

	var vulns []cdxVulnerability
	if err := json.Unmarshal(vulnsRaw, &vulns); err != nil {
		t.Fatalf("failed to unmarshal vulnerabilities: %v", err)
	}

	if len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(vulns))
	}

	v := vulns[0]
	if v.ID != "CVE-2024-45337" {
		t.Errorf("expected ID CVE-2024-45337, got %q", v.ID)
	}
	if v.Source.Name != "mayu" {
		t.Errorf("expected source name mayu, got %q", v.Source.Name)
	}
	if v.Description != "SSH handshake vulnerability in golang.org/x/crypto" {
		t.Errorf("unexpected description: %q", v.Description)
	}
	if v.Recommendation != "Upgrade to version 0.31.0" {
		t.Errorf("unexpected recommendation: %q", v.Recommendation)
	}

	// Check ratings
	if len(v.Ratings) != 1 {
		t.Fatalf("expected 1 rating, got %d", len(v.Ratings))
	}
	if v.Ratings[0].Severity != "critical" {
		t.Errorf("expected severity critical, got %q", v.Ratings[0].Severity)
	}
	if v.Ratings[0].Method != "other" {
		t.Errorf("expected method other, got %q", v.Ratings[0].Method)
	}

	// Check affects
	if len(v.Affects) != 1 {
		t.Fatalf("expected 1 affects entry, got %d", len(v.Affects))
	}
	if v.Affects[0].Ref != "pkg:golang/golang.org/x/crypto@0.30.0" {
		t.Errorf("unexpected affects ref: %q", v.Affects[0].Ref)
	}

	// Check properties
	propMap := make(map[string]string)
	for _, p := range v.Properties {
		propMap[p.Name] = p.Value
	}
	if propMap["mayu:epss:score"] != "0.42" {
		t.Errorf("expected epss:score 0.42, got %q", propMap["mayu:epss:score"])
	}
	if propMap["mayu:epss:percentile"] != "0.95" {
		t.Errorf("expected epss:percentile 0.95, got %q", propMap["mayu:epss:percentile"])
	}
	if propMap["mayu:lev:score"] != "0.87" {
		t.Errorf("expected lev:score 0.87, got %q", propMap["mayu:lev:score"])
	}
	if propMap["mayu:kev"] != "true" {
		t.Errorf("expected kev true, got %q", propMap["mayu:kev"])
	}
	if propMap["mayu:severity:worst"] != "CRITICAL" {
		t.Errorf("expected severity:worst CRITICAL, got %q", propMap["mayu:severity:worst"])
	}
}

func TestGenerateEnrichedSBOM_SPDX(t *testing.T) {
	originalSPDX := `{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-project",
  "packages": [
    {
      "SPDXID": "SPDXRef-Package-1",
      "name": "express",
      "versionInfo": "4.18.0",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:npm/express@4.18.0"
        }
      ]
    }
  ]
}`

	findings := []Finding{
		{
			Component: sbom.Component{
				Purl:      "pkg:npm/express@4.18.0",
				Name:      "express",
				Version:   "4.18.0",
				Ecosystem: "npm",
			},
			VulnID:       "CVE-2024-12345",
			Severity:     "HIGH",
			Summary:      "Prototype pollution in express",
			FixedVersion: "4.19.0",
		},
	}

	mockStore := &mockEnrichmentStore{
		summaries: map[string]*store.VulnSummaryRow{
			"CVE-2024-12345": {
				VulnerabilityID: "CVE-2024-12345",
				SeverityWorst:   4,
				SeverityBest:    4,
				EPSSScore:       float64Ptr(0.15),
				EPSSPercentile:  float64Ptr(0.70),
				InKEV:           false,
				LEVScore:        float64Ptr(0.30),
			},
		},
	}

	result, err := GenerateEnrichedSBOM(context.Background(), mockStore, EnrichedSBOMOptions{
		OriginalData: []byte(originalSPDX),
		Format:       sbom.FormatSPDX,
		Components:   []sbom.Component{{Purl: "pkg:npm/express@4.18.0", Name: "express", Version: "4.18.0", Ecosystem: "npm"}},
		Findings:     findings,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Output should be CycloneDX format (since SPDX doesn't have vulnerabilities section)
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(result, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// Verify it's CycloneDX
	var bomFormat string
	if err := json.Unmarshal(doc["bomFormat"], &bomFormat); err != nil {
		t.Fatalf("failed to read bomFormat: %v", err)
	}
	if bomFormat != "CycloneDX" {
		t.Errorf("expected CycloneDX bomFormat, got %q", bomFormat)
	}

	// Verify vulnerabilities
	var vulns []cdxVulnerability
	if err := json.Unmarshal(doc["vulnerabilities"], &vulns); err != nil {
		t.Fatalf("failed to unmarshal vulnerabilities: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(vulns))
	}
	if vulns[0].ID != "CVE-2024-12345" {
		t.Errorf("expected ID CVE-2024-12345, got %q", vulns[0].ID)
	}

	// No KEV property since InKEV is false
	for _, p := range vulns[0].Properties {
		if p.Name == "mayu:kev" {
			t.Error("expected no mayu:kev property when InKEV is false")
		}
	}
}

func TestGenerateEnrichedSBOM_NoFindings(t *testing.T) {
	originalCDX := `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": []
}`

	mockStore := &mockEnrichmentStore{}

	result, err := GenerateEnrichedSBOM(context.Background(), mockStore, EnrichedSBOMOptions{
		OriginalData: []byte(originalCDX),
		Format:       sbom.FormatCycloneDX,
		Components:   nil,
		Findings:     nil,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should return original data unchanged
	if string(result) != originalCDX {
		t.Errorf("expected original data returned unchanged, got:\n%s", string(result))
	}
}

func TestGenerateEnrichedSBOM_NoFindings_SPDX(t *testing.T) {
	originalSPDX := `{"spdxVersion": "SPDX-2.3"}`

	mockStore := &mockEnrichmentStore{}

	result, err := GenerateEnrichedSBOM(context.Background(), mockStore, EnrichedSBOMOptions{
		OriginalData: []byte(originalSPDX),
		Format:       sbom.FormatSPDX,
		Components:   nil,
		Findings:     nil,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should be a minimal CycloneDX BOM with no vulnerabilities
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(result, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	var bomFormat string
	if err := json.Unmarshal(doc["bomFormat"], &bomFormat); err != nil {
		t.Fatalf("failed to read bomFormat: %v", err)
	}
	if bomFormat != "CycloneDX" {
		t.Errorf("expected CycloneDX, got %q", bomFormat)
	}

	// No vulnerabilities key expected (omitempty)
	if _, ok := doc["vulnerabilities"]; ok {
		t.Error("expected no vulnerabilities key when there are no findings")
	}
}

func TestGenerateEnrichedSBOM_PartialEnrichment(t *testing.T) {
	originalCDX := `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": []
}`

	findings := []Finding{
		{
			Component: sbom.Component{
				Purl:      "pkg:golang/example.com/lib@1.0.0",
				Name:      "example.com/lib",
				Version:   "1.0.0",
				Ecosystem: "Go",
			},
			VulnID:   "CVE-2024-99999",
			Severity: "MEDIUM",
			Summary:  "Some vulnerability",
		},
	}

	// Summary with partial data (no EPSS, no LEV, no KEV)
	mockStore := &mockEnrichmentStore{
		summaries: map[string]*store.VulnSummaryRow{
			"CVE-2024-99999": {
				VulnerabilityID: "CVE-2024-99999",
				SeverityWorst:   3,
				SeverityBest:    3,
				EPSSScore:       nil,
				EPSSPercentile:  nil,
				InKEV:           false,
				LEVScore:        nil,
			},
		},
	}

	result, err := GenerateEnrichedSBOM(context.Background(), mockStore, EnrichedSBOMOptions{
		OriginalData: []byte(originalCDX),
		Format:       sbom.FormatCycloneDX,
		Components:   []sbom.Component{{Purl: "pkg:golang/example.com/lib@1.0.0", Name: "example.com/lib", Version: "1.0.0", Ecosystem: "Go"}},
		Findings:     findings,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var doc map[string]json.RawMessage
	if err := json.Unmarshal(result, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	var vulns []cdxVulnerability
	if err := json.Unmarshal(doc["vulnerabilities"], &vulns); err != nil {
		t.Fatalf("failed to unmarshal vulnerabilities: %v", err)
	}

	if len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(vulns))
	}

	// Only severity:worst should be present (no EPSS, no LEV, no KEV)
	propMap := make(map[string]string)
	for _, p := range vulns[0].Properties {
		propMap[p.Name] = p.Value
	}
	if _, ok := propMap["mayu:epss:score"]; ok {
		t.Error("expected no mayu:epss:score property when EPSS is nil")
	}
	if _, ok := propMap["mayu:epss:percentile"]; ok {
		t.Error("expected no mayu:epss:percentile property when EPSS is nil")
	}
	if _, ok := propMap["mayu:lev:score"]; ok {
		t.Error("expected no mayu:lev:score property when LEV is nil")
	}
	if _, ok := propMap["mayu:kev"]; ok {
		t.Error("expected no mayu:kev property when InKEV is false")
	}
	if propMap["mayu:severity:worst"] != "MEDIUM" {
		t.Errorf("expected severity:worst MEDIUM, got %q", propMap["mayu:severity:worst"])
	}
}

func TestGenerateEnrichedSBOM_MultipleFindings_SameVuln(t *testing.T) {
	originalCDX := `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": []
}`

	// Same vuln affects two different packages
	findings := []Finding{
		{
			Component: sbom.Component{
				Purl:      "pkg:golang/example.com/a@1.0.0",
				Name:      "example.com/a",
				Version:   "1.0.0",
				Ecosystem: "Go",
			},
			VulnID:       "CVE-2024-11111",
			Severity:     "HIGH",
			Summary:      "Shared vuln",
			FixedVersion: "1.1.0",
		},
		{
			Component: sbom.Component{
				Purl:      "pkg:golang/example.com/b@2.0.0",
				Name:      "example.com/b",
				Version:   "2.0.0",
				Ecosystem: "Go",
			},
			VulnID:       "CVE-2024-11111",
			Severity:     "HIGH",
			Summary:      "Shared vuln",
			FixedVersion: "2.1.0",
		},
	}

	mockStore := &mockEnrichmentStore{
		summaries: map[string]*store.VulnSummaryRow{
			"CVE-2024-11111": {
				VulnerabilityID: "CVE-2024-11111",
				SeverityWorst:   4,
				EPSSScore:       float64Ptr(0.5),
			},
		},
	}

	result, err := GenerateEnrichedSBOM(context.Background(), mockStore, EnrichedSBOMOptions{
		OriginalData: []byte(originalCDX),
		Format:       sbom.FormatCycloneDX,
		Findings:     findings,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var doc map[string]json.RawMessage
	if err := json.Unmarshal(result, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	var vulns []cdxVulnerability
	if err := json.Unmarshal(doc["vulnerabilities"], &vulns); err != nil {
		t.Fatalf("failed to unmarshal vulnerabilities: %v", err)
	}

	// Should be 1 vulnerability entry (grouped)
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability (grouped), got %d", len(vulns))
	}

	// Should have 2 affects entries
	if len(vulns[0].Affects) != 2 {
		t.Errorf("expected 2 affects entries, got %d", len(vulns[0].Affects))
	}

	// Verify both purls are present
	refs := make(map[string]bool)
	for _, a := range vulns[0].Affects {
		refs[a.Ref] = true
	}
	if !refs["pkg:golang/example.com/a@1.0.0"] {
		t.Error("missing affects ref for example.com/a")
	}
	if !refs["pkg:golang/example.com/b@2.0.0"] {
		t.Error("missing affects ref for example.com/b")
	}
}

func TestGenerateEnrichedSBOM_NoEnrichmentData(t *testing.T) {
	originalCDX := `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": []
}`

	findings := []Finding{
		{
			Component: sbom.Component{
				Purl:      "pkg:npm/lodash@4.17.0",
				Name:      "lodash",
				Version:   "4.17.0",
				Ecosystem: "npm",
			},
			VulnID:   "CVE-2024-00000",
			Severity: "LOW",
			Summary:  "Minor issue",
		},
	}

	// No summary data available
	mockStore := &mockEnrichmentStore{
		summaries: map[string]*store.VulnSummaryRow{},
	}

	result, err := GenerateEnrichedSBOM(context.Background(), mockStore, EnrichedSBOMOptions{
		OriginalData: []byte(originalCDX),
		Format:       sbom.FormatCycloneDX,
		Findings:     findings,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var doc map[string]json.RawMessage
	if err := json.Unmarshal(result, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	var vulns []cdxVulnerability
	if err := json.Unmarshal(doc["vulnerabilities"], &vulns); err != nil {
		t.Fatalf("failed to unmarshal vulnerabilities: %v", err)
	}

	if len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(vulns))
	}

	// No properties when no enrichment data
	if len(vulns[0].Properties) != 0 {
		t.Errorf("expected no properties when no enrichment data, got %d", len(vulns[0].Properties))
	}

	// Still has basic fields
	if vulns[0].ID != "CVE-2024-00000" {
		t.Errorf("expected ID CVE-2024-00000, got %q", vulns[0].ID)
	}
	if vulns[0].Ratings[0].Severity != "low" {
		t.Errorf("expected severity low, got %q", vulns[0].Ratings[0].Severity)
	}
}
