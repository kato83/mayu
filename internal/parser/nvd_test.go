package parser

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestParseNVDFeed(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "nvd_sample_feed.json"))
	if err != nil {
		t.Fatalf("failed to read test fixture: %v", err)
	}

	p := New()
	result, err := p.ParseNVDFeed(data)
	if err != nil {
		t.Fatalf("ParseNVDFeed failed: %v", err)
	}

	// Verify 2 entries parsed successfully
	if len(result.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(result.Entries))
	}
	if len(result.Errors) != 0 {
		t.Errorf("expected 0 errors, got %d", len(result.Errors))
		for _, e := range result.Errors {
			t.Logf("  %s: %v", e.ID, e.Error)
		}
	}

	// Verify first entry ID
	if result.Entries[0].ID != "CVE-2023-44487" {
		t.Errorf("first entry ID = %q, want CVE-2023-44487", result.Entries[0].ID)
	}

	// Verify second entry ID
	if result.Entries[1].ID != "CVE-2024-0001" {
		t.Errorf("second entry ID = %q, want CVE-2024-0001", result.Entries[1].ID)
	}

	// Verify RawJSON is populated for each entry
	for i, entry := range result.Entries {
		if entry.RawJSON == nil {
			t.Errorf("entry[%d] (%s): RawJSON is nil", i, entry.ID)
		}
		if len(entry.RawJSON) == 0 {
			t.Errorf("entry[%d] (%s): RawJSON is empty", i, entry.ID)
		}
	}

	// Verify descriptions are present
	for i, entry := range result.Entries {
		if len(entry.Descriptions) == 0 {
			t.Errorf("entry[%d] (%s): Descriptions is empty", i, entry.ID)
		}
	}
}

func TestParseNVDFeed_Empty(t *testing.T) {
	p := New()
	_, err := p.ParseNVDFeed([]byte{})
	if err == nil {
		t.Error("expected error for empty data, got nil")
	}
}

func TestParseNVDFeed_InvalidJSON(t *testing.T) {
	p := New()
	_, err := p.ParseNVDFeed([]byte(`{invalid json`))
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

func TestParseNVDFeed_SkipsInvalidEntries(t *testing.T) {
	// Feed with one valid entry and one invalid entry (missing descriptions)
	feedJSON := `{
		"resultsPerPage": 2,
		"startIndex": 0,
		"totalResults": 2,
		"format": "NVD_CVE",
		"version": "2.0",
		"timestamp": "2024-01-15T10:00:00.000",
		"vulnerabilities": [
			{
				"cve": {
					"id": "CVE-2024-1234",
					"sourceIdentifier": "test@example.com",
					"published": "2024-01-01T00:00:00.000",
					"lastModified": "2024-01-02T00:00:00.000",
					"descriptions": [
						{"lang": "en", "value": "Valid entry"}
					]
				}
			},
			{
				"cve": {
					"id": "CVE-2024-5678",
					"sourceIdentifier": "test@example.com",
					"published": "2024-01-01T00:00:00.000",
					"lastModified": "2024-01-02T00:00:00.000",
					"descriptions": []
				}
			}
		]
	}`

	p := New()
	result, err := p.ParseNVDFeed([]byte(feedJSON))
	if err != nil {
		t.Fatalf("ParseNVDFeed failed: %v", err)
	}

	if len(result.Entries) != 1 {
		t.Errorf("expected 1 valid entry, got %d", len(result.Entries))
	}
	if len(result.Errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(result.Errors))
	}

	if result.Entries[0].ID != "CVE-2024-1234" {
		t.Errorf("valid entry ID = %q, want CVE-2024-1234", result.Entries[0].ID)
	}
	if len(result.Errors) > 0 && result.Errors[0].ID != "CVE-2024-5678" {
		t.Errorf("error entry ID = %q, want CVE-2024-5678", result.Errors[0].ID)
	}
}

func TestParseNVDFeed_StrictMode(t *testing.T) {
	// Same feed as above: one valid, one invalid (missing descriptions)
	feedJSON := `{
		"resultsPerPage": 2,
		"startIndex": 0,
		"totalResults": 2,
		"format": "NVD_CVE",
		"version": "2.0",
		"timestamp": "2024-01-15T10:00:00.000",
		"vulnerabilities": [
			{
				"cve": {
					"id": "CVE-2024-1234",
					"sourceIdentifier": "test@example.com",
					"published": "2024-01-01T00:00:00.000",
					"lastModified": "2024-01-02T00:00:00.000",
					"descriptions": [
						{"lang": "en", "value": "Valid entry"}
					]
				}
			},
			{
				"cve": {
					"id": "CVE-2024-5678",
					"sourceIdentifier": "test@example.com",
					"published": "2024-01-01T00:00:00.000",
					"lastModified": "2024-01-02T00:00:00.000",
					"descriptions": []
				}
			}
		]
	}`

	p := New()
	p.Strict = true

	_, err := p.ParseNVDFeed([]byte(feedJSON))
	if err == nil {
		t.Error("expected error in strict mode, got nil")
	}
}

func TestParseNVDSingle(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "nvd_sample_cve.json"))
	if err != nil {
		t.Fatalf("failed to read test fixture: %v", err)
	}

	p := New()
	cve, err := p.ParseNVDSingle(data)
	if err != nil {
		t.Fatalf("ParseNVDSingle failed: %v", err)
	}

	// Verify ID
	if cve.ID != "CVE-2023-44487" {
		t.Errorf("ID = %q, want CVE-2023-44487", cve.ID)
	}

	// Verify timestamps
	if cve.Published.Time.IsZero() {
		t.Error("Published is zero")
	}
	if cve.LastModified.Time.IsZero() {
		t.Error("LastModified is zero")
	}

	// Verify descriptions (fixture has both en and es)
	if len(cve.Descriptions) != 2 {
		t.Errorf("expected 2 descriptions, got %d", len(cve.Descriptions))
	}
	if cve.Descriptions[0].Lang != "en" {
		t.Errorf("first description lang = %q, want en", cve.Descriptions[0].Lang)
	}

	// Verify RawJSON is preserved
	if cve.RawJSON == nil {
		t.Error("RawJSON is nil")
	}

	// Verify source identifier
	if cve.SourceIdentifier != "cve@mitre.org" {
		t.Errorf("SourceIdentifier = %q, want cve@mitre.org", cve.SourceIdentifier)
	}

	// Verify vuln status
	if cve.VulnStatus != "Analyzed" {
		t.Errorf("VulnStatus = %q, want Analyzed", cve.VulnStatus)
	}

	// Verify weaknesses
	if len(cve.Weaknesses) != 1 {
		t.Errorf("expected 1 weakness, got %d", len(cve.Weaknesses))
	}

	// Verify references
	if len(cve.References) != 2 {
		t.Errorf("expected 2 references, got %d", len(cve.References))
	}

	// Verify CISA fields from fixture
	if cve.CisaExploitAdd != "2023-10-10" {
		t.Errorf("CisaExploitAdd = %q, want 2023-10-10", cve.CisaExploitAdd)
	}

	// Verify vendor comments
	if len(cve.VendorComments) != 1 {
		t.Errorf("expected 1 vendor comment, got %d", len(cve.VendorComments))
	}

	// Verify CVE tags
	if len(cve.CveTags) != 1 {
		t.Errorf("expected 1 cveTag, got %d", len(cve.CveTags))
	}
}

func TestParseNVDSingle_InvalidCVEID(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{
			name: "empty id",
			json: `{"id":"","published":"2024-01-01T00:00:00.000","lastModified":"2024-01-02T00:00:00.000","descriptions":[{"lang":"en","value":"test"}]}`,
		},
		{
			name: "no CVE prefix",
			json: `{"id":"GHSA-2024-1234","published":"2024-01-01T00:00:00.000","lastModified":"2024-01-02T00:00:00.000","descriptions":[{"lang":"en","value":"test"}]}`,
		},
		{
			name: "too short",
			json: `{"id":"CVE-24-1","published":"2024-01-01T00:00:00.000","lastModified":"2024-01-02T00:00:00.000","descriptions":[{"lang":"en","value":"test"}]}`,
		},
		{
			name: "letters in year",
			json: `{"id":"CVE-ABCD-1234","published":"2024-01-01T00:00:00.000","lastModified":"2024-01-02T00:00:00.000","descriptions":[{"lang":"en","value":"test"}]}`,
		},
		{
			name: "letters in number",
			json: `{"id":"CVE-2024-ABCD","published":"2024-01-01T00:00:00.000","lastModified":"2024-01-02T00:00:00.000","descriptions":[{"lang":"en","value":"test"}]}`,
		},
	}

	p := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := p.ParseNVDSingle([]byte(tt.json))
			if err == nil {
				t.Error("expected error for invalid CVE ID, got nil")
			}
		})
	}
}

func TestIsValidCVEID(t *testing.T) {
	tests := []struct {
		id    string
		valid bool
	}{
		{"CVE-2023-44487", true},
		{"CVE-2024-0001", true},
		{"CVE-2024-12345", true},
		{"CVE-2024-123456", true},
		{"CVE-1999-0001", true},
		{"", false},
		{"CVE-", false},
		{"CVE-2024", false},
		{"CVE-2024-", false},
		{"CVE-2024-1", false},      // number part too short (< 4 digits)
		{"CVE-2024-12", false},     // number part too short
		{"CVE-2024-123", false},    // number part too short
		{"CVE-ABCD-1234", false},   // non-digit year
		{"CVE-2024-ABCD", false},   // non-digit number
		{"GHSA-2024-1234", false},  // wrong prefix
		{"cve-2024-1234", false},   // lowercase
		{"CVE-20-12345678", false}, // year too short (only 2 digits before dash)
		{"CVE-2024-1234x", false},  // trailing letter in number
		{"CVE-2024x-1234", false},  // letter in year
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got := isValidCVEID(tt.id)
			if got != tt.valid {
				t.Errorf("isValidCVEID(%q) = %v, want %v", tt.id, got, tt.valid)
			}
		})
	}
}

func TestParseNVDFeed_RawJSONPreservation(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "nvd_sample_feed.json"))
	if err != nil {
		t.Fatalf("failed to read test fixture: %v", err)
	}

	p := New()
	result, err := p.ParseNVDFeed(data)
	if err != nil {
		t.Fatalf("ParseNVDFeed failed: %v", err)
	}

	for i, entry := range result.Entries {
		if entry.RawJSON == nil {
			t.Fatalf("entry[%d]: RawJSON is nil", i)
		}

		// Unmarshal the RawJSON back into a map to verify key fields are present
		var m map[string]interface{}
		if err := json.Unmarshal(entry.RawJSON, &m); err != nil {
			t.Fatalf("entry[%d]: failed to unmarshal RawJSON: %v", i, err)
		}

		// Verify the id field is present and matches
		id, ok := m["id"].(string)
		if !ok {
			t.Errorf("entry[%d]: RawJSON missing 'id' field", i)
		} else if id != entry.ID {
			t.Errorf("entry[%d]: RawJSON id = %q, struct ID = %q", i, id, entry.ID)
		}

		// Verify published field is present
		if _, ok := m["published"]; !ok {
			t.Errorf("entry[%d]: RawJSON missing 'published' field", i)
		}

		// Verify lastModified field is present
		if _, ok := m["lastModified"]; !ok {
			t.Errorf("entry[%d]: RawJSON missing 'lastModified' field", i)
		}

		// Verify descriptions field is present
		if _, ok := m["descriptions"]; !ok {
			t.Errorf("entry[%d]: RawJSON missing 'descriptions' field", i)
		}

		// Verify sourceIdentifier field is present
		if _, ok := m["sourceIdentifier"]; !ok {
			t.Errorf("entry[%d]: RawJSON missing 'sourceIdentifier' field", i)
		}
	}
}
