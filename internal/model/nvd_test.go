package model

import (
	"encoding/json"
	"os"
	"testing"
)

func TestParseNVDEntry(t *testing.T) {
	data, err := os.ReadFile("../../testdata/nvd_sample_cve.json")
	if err != nil {
		t.Fatalf("failed to read test fixture: %v", err)
	}

	cve, err := ParseNVDEntry(data)
	if err != nil {
		t.Fatalf("ParseNVDEntry failed: %v", err)
	}

	// Verify basic fields
	if cve.ID != "CVE-2023-44487" {
		t.Errorf("ID = %q, want %q", cve.ID, "CVE-2023-44487")
	}
	if cve.SourceIdentifier != "cve@mitre.org" {
		t.Errorf("SourceIdentifier = %q, want %q", cve.SourceIdentifier, "cve@mitre.org")
	}
	if cve.VulnStatus != "Analyzed" {
		t.Errorf("VulnStatus = %q, want %q", cve.VulnStatus, "Analyzed")
	}

	// Verify timestamps
	if cve.Published.Year() != 2023 || cve.Published.Month() != 10 || cve.Published.Day() != 10 {
		t.Errorf("Published = %v, want 2023-10-10", cve.Published.Time)
	}
	if cve.LastModified.Year() != 2024 || cve.LastModified.Month() != 6 || cve.LastModified.Day() != 27 {
		t.Errorf("LastModified = %v, want 2024-06-27", cve.LastModified.Time)
	}

	// Verify descriptions (en + es)
	if len(cve.Descriptions) != 2 {
		t.Fatalf("len(Descriptions) = %d, want 2", len(cve.Descriptions))
	}
	if cve.Descriptions[0].Lang != "en" {
		t.Errorf("Descriptions[0].Lang = %q, want %q", cve.Descriptions[0].Lang, "en")
	}
	if cve.Descriptions[1].Lang != "es" {
		t.Errorf("Descriptions[1].Lang = %q, want %q", cve.Descriptions[1].Lang, "es")
	}

	// Verify metrics (CVSS v3.1)
	if len(cve.Metrics.CvssMetricV31) != 1 {
		t.Fatalf("len(CvssMetricV31) = %d, want 1", len(cve.Metrics.CvssMetricV31))
	}
	m := cve.Metrics.CvssMetricV31[0]
	if m.Source != "nvd@nist.gov" {
		t.Errorf("CvssMetricV31[0].Source = %q, want %q", m.Source, "nvd@nist.gov")
	}
	if m.Type != "Primary" {
		t.Errorf("CvssMetricV31[0].Type = %q, want %q", m.Type, "Primary")
	}
	if m.ExploitabilityScore == nil || *m.ExploitabilityScore != 3.9 {
		t.Errorf("ExploitabilityScore = %v, want 3.9", m.ExploitabilityScore)
	}
	if m.ImpactScore == nil || *m.ImpactScore != 3.6 {
		t.Errorf("ImpactScore = %v, want 3.6", m.ImpactScore)
	}
	// Verify cvssData is valid JSON
	var cvssData map[string]interface{}
	if err := json.Unmarshal(m.CvssData, &cvssData); err != nil {
		t.Errorf("CvssData is not valid JSON: %v", err)
	}
	if cvssData["baseScore"] != 7.5 {
		t.Errorf("cvssData.baseScore = %v, want 7.5", cvssData["baseScore"])
	}

	// Verify weaknesses
	if len(cve.Weaknesses) != 1 {
		t.Fatalf("len(Weaknesses) = %d, want 1", len(cve.Weaknesses))
	}
	if cve.Weaknesses[0].Source != "nvd@nist.gov" {
		t.Errorf("Weaknesses[0].Source = %q, want %q", cve.Weaknesses[0].Source, "nvd@nist.gov")
	}
	if cve.Weaknesses[0].Description[0].Value != "CWE-400" {
		t.Errorf("Weaknesses[0].Description[0].Value = %q, want %q", cve.Weaknesses[0].Description[0].Value, "CWE-400")
	}

	// Verify configurations
	if len(cve.Configurations) != 1 {
		t.Fatalf("len(Configurations) = %d, want 1", len(cve.Configurations))
	}
	cfg := cve.Configurations[0]
	if cfg.Operator != "OR" {
		t.Errorf("Configurations[0].Operator = %q, want %q", cfg.Operator, "OR")
	}
	if len(cfg.Nodes) != 1 {
		t.Fatalf("len(Nodes) = %d, want 1", len(cfg.Nodes))
	}
	if len(cfg.Nodes[0].CpeMatch) != 2 {
		t.Fatalf("len(CpeMatch) = %d, want 2", len(cfg.Nodes[0].CpeMatch))
	}
	if !cfg.Nodes[0].CpeMatch[0].Vulnerable {
		t.Error("CpeMatch[0].Vulnerable = false, want true")
	}
	if cfg.Nodes[0].CpeMatch[1].VersionEndExcluding != "1.21.3" {
		t.Errorf("CpeMatch[1].VersionEndExcluding = %q, want %q", cfg.Nodes[0].CpeMatch[1].VersionEndExcluding, "1.21.3")
	}

	// Verify references
	if len(cve.References) != 2 {
		t.Fatalf("len(References) = %d, want 2", len(cve.References))
	}
	if cve.References[0].URL != "https://github.com/golang/go/issues/63417" {
		t.Errorf("References[0].URL = %q", cve.References[0].URL)
	}
	if len(cve.References[0].Tags) != 2 {
		t.Errorf("len(References[0].Tags) = %d, want 2", len(cve.References[0].Tags))
	}

	// Verify CVE tags
	if len(cve.CveTags) != 1 {
		t.Fatalf("len(CveTags) = %d, want 1", len(cve.CveTags))
	}
	if cve.CveTags[0].SourceIdentifier != "cve@mitre.org" {
		t.Errorf("CveTags[0].SourceIdentifier = %q, want %q", cve.CveTags[0].SourceIdentifier, "cve@mitre.org")
	}
	if cve.CveTags[0].Tags[0] != "disputed" {
		t.Errorf("CveTags[0].Tags[0] = %q, want %q", cve.CveTags[0].Tags[0], "disputed")
	}

	// Verify evaluator fields
	if cve.EvaluatorComment != "This CVE is related to the HTTP/2 Rapid Reset attack." {
		t.Errorf("EvaluatorComment = %q", cve.EvaluatorComment)
	}
	if cve.EvaluatorSolution != "Update affected software to the latest version." {
		t.Errorf("EvaluatorSolution = %q", cve.EvaluatorSolution)
	}
	if cve.EvaluatorImpact != "Denial of service affecting availability." {
		t.Errorf("EvaluatorImpact = %q", cve.EvaluatorImpact)
	}

	// Verify CISA fields
	if cve.CisaExploitAdd != "2023-10-10" {
		t.Errorf("CisaExploitAdd = %q, want %q", cve.CisaExploitAdd, "2023-10-10")
	}
	if cve.CisaActionDue != "2023-10-31" {
		t.Errorf("CisaActionDue = %q, want %q", cve.CisaActionDue, "2023-10-31")
	}
	if cve.CisaRequiredAction != "Apply mitigations per vendor instructions." {
		t.Errorf("CisaRequiredAction = %q", cve.CisaRequiredAction)
	}
	if cve.CisaVulnerabilityName != "HTTP/2 Rapid Reset Attack" {
		t.Errorf("CisaVulnerabilityName = %q", cve.CisaVulnerabilityName)
	}

	// Verify vendor comments
	if len(cve.VendorComments) != 1 {
		t.Fatalf("len(VendorComments) = %d, want 1", len(cve.VendorComments))
	}
	if cve.VendorComments[0].Organization != "Golang" {
		t.Errorf("VendorComments[0].Organization = %q, want %q", cve.VendorComments[0].Organization, "Golang")
	}
}

func TestParseNVDEntry_RawJSON(t *testing.T) {
	data, err := os.ReadFile("../../testdata/nvd_sample_cve.json")
	if err != nil {
		t.Fatalf("failed to read test fixture: %v", err)
	}

	cve, err := ParseNVDEntry(data)
	if err != nil {
		t.Fatalf("ParseNVDEntry failed: %v", err)
	}

	// RawJSON must be populated
	if cve.RawJSON == nil {
		t.Fatal("RawJSON is nil")
	}

	// RawJSON must be compact (no extra whitespace between tokens)
	if len(cve.RawJSON) == 0 {
		t.Fatal("RawJSON is empty")
	}

	// Verify it's valid JSON
	if !json.Valid(cve.RawJSON) {
		t.Fatal("RawJSON is not valid JSON")
	}

	// Verify RawJSON is compact (should be shorter than the indented source)
	if len(cve.RawJSON) >= len(data) {
		t.Errorf("RawJSON len (%d) should be less than source len (%d) due to compaction", len(cve.RawJSON), len(data))
	}

	// Verify RawJSON can be re-parsed to the same struct
	var reparsed NVDCVE
	if err := json.Unmarshal(cve.RawJSON, &reparsed); err != nil {
		t.Fatalf("failed to re-parse RawJSON: %v", err)
	}
	if reparsed.ID != cve.ID {
		t.Errorf("re-parsed ID = %q, want %q", reparsed.ID, cve.ID)
	}
}

func TestParseNVDEntry_Roundtrip(t *testing.T) {
	data, err := os.ReadFile("../../testdata/nvd_sample_cve.json")
	if err != nil {
		t.Fatalf("failed to read test fixture: %v", err)
	}

	// Parse → Marshal → Unmarshal → Compare
	cve, err := ParseNVDEntry(data)
	if err != nil {
		t.Fatalf("ParseNVDEntry failed: %v", err)
	}

	// Marshal the struct back to JSON (without RawJSON since it's json:"-")
	marshaled, err := json.Marshal(cve)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	// Unmarshal again
	var cve2 NVDCVE
	if err := json.Unmarshal(marshaled, &cve2); err != nil {
		t.Fatalf("second json.Unmarshal failed: %v", err)
	}

	// Compare key fields
	if cve2.ID != cve.ID {
		t.Errorf("roundtrip ID = %q, want %q", cve2.ID, cve.ID)
	}
	if cve2.SourceIdentifier != cve.SourceIdentifier {
		t.Errorf("roundtrip SourceIdentifier = %q, want %q", cve2.SourceIdentifier, cve.SourceIdentifier)
	}
	if cve2.VulnStatus != cve.VulnStatus {
		t.Errorf("roundtrip VulnStatus = %q, want %q", cve2.VulnStatus, cve.VulnStatus)
	}
	if !cve2.Published.Equal(cve.Published.Time) {
		t.Errorf("roundtrip Published = %v, want %v", cve2.Published.Time, cve.Published.Time)
	}
	if !cve2.LastModified.Equal(cve.LastModified.Time) {
		t.Errorf("roundtrip LastModified = %v, want %v", cve2.LastModified.Time, cve.LastModified.Time)
	}
	if len(cve2.Descriptions) != len(cve.Descriptions) {
		t.Errorf("roundtrip len(Descriptions) = %d, want %d", len(cve2.Descriptions), len(cve.Descriptions))
	}
	if len(cve2.Metrics.CvssMetricV31) != len(cve.Metrics.CvssMetricV31) {
		t.Errorf("roundtrip len(CvssMetricV31) = %d, want %d", len(cve2.Metrics.CvssMetricV31), len(cve.Metrics.CvssMetricV31))
	}
	if len(cve2.Weaknesses) != len(cve.Weaknesses) {
		t.Errorf("roundtrip len(Weaknesses) = %d, want %d", len(cve2.Weaknesses), len(cve.Weaknesses))
	}
	if len(cve2.Configurations) != len(cve.Configurations) {
		t.Errorf("roundtrip len(Configurations) = %d, want %d", len(cve2.Configurations), len(cve.Configurations))
	}
	if len(cve2.References) != len(cve.References) {
		t.Errorf("roundtrip len(References) = %d, want %d", len(cve2.References), len(cve.References))
	}
	if cve2.EvaluatorComment != cve.EvaluatorComment {
		t.Errorf("roundtrip EvaluatorComment = %q, want %q", cve2.EvaluatorComment, cve.EvaluatorComment)
	}
	if cve2.CisaExploitAdd != cve.CisaExploitAdd {
		t.Errorf("roundtrip CisaExploitAdd = %q, want %q", cve2.CisaExploitAdd, cve.CisaExploitAdd)
	}
}

func TestParseNVDFeedResponse(t *testing.T) {
	data, err := os.ReadFile("../../testdata/nvd_sample_feed.json")
	if err != nil {
		t.Fatalf("failed to read test fixture: %v", err)
	}

	feed, err := ParseNVDFeedResponse(data)
	if err != nil {
		t.Fatalf("ParseNVDFeedResponse failed: %v", err)
	}

	// Verify feed metadata
	if feed.ResultsPerPage != 2 {
		t.Errorf("ResultsPerPage = %d, want 2", feed.ResultsPerPage)
	}
	if feed.StartIndex != 0 {
		t.Errorf("StartIndex = %d, want 0", feed.StartIndex)
	}
	if feed.TotalResults != 2 {
		t.Errorf("TotalResults = %d, want 2", feed.TotalResults)
	}
	if feed.Format != "NVD_CVE" {
		t.Errorf("Format = %q, want %q", feed.Format, "NVD_CVE")
	}
	if feed.Version != "2.0" {
		t.Errorf("Version = %q, want %q", feed.Version, "2.0")
	}

	// Verify vulnerabilities count
	if len(feed.Vulnerabilities) != 2 {
		t.Fatalf("len(Vulnerabilities) = %d, want 2", len(feed.Vulnerabilities))
	}

	// Verify first entry
	if feed.Vulnerabilities[0].CVE.ID != "CVE-2023-44487" {
		t.Errorf("Vulnerabilities[0].CVE.ID = %q, want %q", feed.Vulnerabilities[0].CVE.ID, "CVE-2023-44487")
	}
	if feed.Vulnerabilities[0].CVE.RawJSON == nil {
		t.Error("Vulnerabilities[0].CVE.RawJSON is nil")
	}

	// Verify second entry
	if feed.Vulnerabilities[1].CVE.ID != "CVE-2024-0001" {
		t.Errorf("Vulnerabilities[1].CVE.ID = %q, want %q", feed.Vulnerabilities[1].CVE.ID, "CVE-2024-0001")
	}
	if feed.Vulnerabilities[1].CVE.VulnStatus != "Modified" {
		t.Errorf("Vulnerabilities[1].CVE.VulnStatus = %q, want %q", feed.Vulnerabilities[1].CVE.VulnStatus, "Modified")
	}
	if feed.Vulnerabilities[1].CVE.RawJSON == nil {
		t.Error("Vulnerabilities[1].CVE.RawJSON is nil")
	}

	// Verify RawJSON of each entry is valid JSON containing the CVE ID
	for i, v := range feed.Vulnerabilities {
		if !json.Valid(v.CVE.RawJSON) {
			t.Errorf("Vulnerabilities[%d].CVE.RawJSON is not valid JSON", i)
		}
		var parsed map[string]interface{}
		if err := json.Unmarshal(v.CVE.RawJSON, &parsed); err != nil {
			t.Errorf("Vulnerabilities[%d]: failed to unmarshal RawJSON: %v", i, err)
		}
		if id, ok := parsed["id"].(string); !ok || id != v.CVE.ID {
			t.Errorf("Vulnerabilities[%d]: RawJSON id = %v, want %q", i, parsed["id"], v.CVE.ID)
		}
	}
}

func TestParseNVDEntry_Invalid(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "empty bytes",
			data: []byte{},
		},
		{
			name: "invalid JSON",
			data: []byte(`{invalid json`),
		},
		{
			name: "null",
			data: []byte(`null`),
		},
		{
			name: "array instead of object",
			data: []byte(`[1, 2, 3]`),
		},
		{
			name: "empty object (missing id)",
			data: []byte(`{}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseNVDEntry(tt.data)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}
