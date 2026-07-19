package parser

import (
	"testing"

	"github.com/kato83/mayu/internal/model"
)

func TestIsGitHubAdvisoryJSON(t *testing.T) {
	tests := []struct {
		name string
		data string
		want bool
	}{
		{
			name: "GitHub advisory format",
			data: `{"ghsa_id":"GHSA-xxxx-xxxx-xxxx","cve_id":"CVE-2026-12345","severity":"high"}`,
			want: true,
		},
		{
			name: "OSV format",
			data: `{"id":"GHSA-xxxx-xxxx-xxxx","modified":"2026-01-01T00:00:00Z","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}`,
			want: false,
		},
		{
			name: "empty JSON",
			data: `{}`,
			want: false,
		},
		{
			name: "invalid JSON",
			data: `not json`,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsGitHubAdvisoryJSON([]byte(tt.data))
			if got != tt.want {
				t.Errorf("IsGitHubAdvisoryJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConvertGitHubToOSV(t *testing.T) {
	input := `{
		"ghsa_id": "GHSA-test-test-test",
		"cve_id": "CVE-2026-99999",
		"html_url": "https://github.com/example/repo/security/advisories/GHSA-test-test-test",
		"summary": "Test ` + "`vulnerability`" + `",
		"description": "A test vulnerability.\r\n\r\nAffects versions 1.0 to 1.5.",
		"severity": "high",
		"identifiers": [
			{"type": "GHSA", "value": "GHSA-test-test-test"},
			{"type": "CVE", "value": "CVE-2026-99999"}
		],
		"published_at": "2026-07-01T10:00:00Z",
		"updated_at": "2026-07-02T12:00:00Z",
		"vulnerabilities": [
			{
				"package": {"ecosystem": "npm", "name": "my-package"},
				"vulnerable_version_range": "1.0.0 - 1.5.0",
				"patched_versions": "1.5.1"
			},
			{
				"package": {"ecosystem": "npm", "name": "my-package"},
				"vulnerable_version_range": ">= 2.0.0, < 2.1.0",
				"patched_versions": "2.1.0"
			}
		],
		"cvss_severities": {
			"cvss_v3": {
				"vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
				"score": 7.5
			},
			"cvss_v4": null
		},
		"cvss": {"vector_string": null, "score": null},
		"cwes": [{"cwe_id": "CWE-79", "name": "XSS"}],
		"credits": [],
		"credits_detailed": [
			{"user": {"login": "researcher1"}, "type": "finder", "state": "accepted"}
		]
	}`

	vuln, err := ConvertGitHubToOSV([]byte(input))
	if err != nil {
		t.Fatalf("ConvertGitHubToOSV() error: %v", err)
	}

	// Check ID
	if vuln.ID != "GHSA-test-test-test" {
		t.Errorf("ID = %q, want %q", vuln.ID, "GHSA-test-test-test")
	}

	// Check aliases
	if len(vuln.Aliases) != 1 || vuln.Aliases[0] != "CVE-2026-99999" {
		t.Errorf("Aliases = %v, want [CVE-2026-99999]", vuln.Aliases)
	}

	// Check summary (backticks removed)
	if vuln.Summary != "Test vulnerability" {
		t.Errorf("Summary = %q, want %q", vuln.Summary, "Test vulnerability")
	}

	// Check details (CRLF normalized)
	if got := vuln.Details; got != "A test vulnerability.\n\nAffects versions 1.0 to 1.5." {
		t.Errorf("Details = %q, unexpected", got)
	}

	// Check modified time
	if vuln.Modified.IsZero() {
		t.Error("Modified should not be zero")
	}
	if vuln.Modified.Day() != 2 {
		t.Errorf("Modified day = %d, want 2 (from updated_at)", vuln.Modified.Day())
	}

	// Check severity
	if len(vuln.Severity) != 1 {
		t.Fatalf("Severity length = %d, want 1", len(vuln.Severity))
	}
	if vuln.Severity[0].Type != model.SeverityTypeCVSSV3 {
		t.Errorf("Severity[0].Type = %q, want CVSS_V3", vuln.Severity[0].Type)
	}
	if vuln.Severity[0].Score != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" {
		t.Errorf("Severity[0].Score = %q, unexpected", vuln.Severity[0].Score)
	}

	// Check affected packages
	if len(vuln.Affected) != 1 {
		t.Fatalf("Affected length = %d, want 1 (grouped by package)", len(vuln.Affected))
	}
	if vuln.Affected[0].Package.Ecosystem != "npm" {
		t.Errorf("Affected[0].Package.Ecosystem = %q, want npm", vuln.Affected[0].Package.Ecosystem)
	}
	if vuln.Affected[0].Package.Name != "my-package" {
		t.Errorf("Affected[0].Package.Name = %q, want my-package", vuln.Affected[0].Package.Name)
	}
	if len(vuln.Affected[0].Ranges) != 2 {
		t.Fatalf("Affected[0].Ranges length = %d, want 2", len(vuln.Affected[0].Ranges))
	}
	// First range: 1.0.0 - 1.5.0, fixed 1.5.1
	r0 := vuln.Affected[0].Ranges[0]
	if r0.Type != model.RangeTypeEcosystem {
		t.Errorf("Range[0].Type = %q, want ECOSYSTEM", r0.Type)
	}
	if len(r0.Events) != 2 {
		t.Fatalf("Range[0].Events length = %d, want 2", len(r0.Events))
	}
	if r0.Events[0].Introduced != "1.0.0" {
		t.Errorf("Range[0].Events[0].Introduced = %q, want 1.0.0", r0.Events[0].Introduced)
	}
	if r0.Events[1].Fixed != "1.5.1" {
		t.Errorf("Range[0].Events[1].Fixed = %q, want 1.5.1", r0.Events[1].Fixed)
	}

	// Check references
	if len(vuln.References) != 1 {
		t.Fatalf("References length = %d, want 1", len(vuln.References))
	}
	if vuln.References[0].Type != model.ReferenceTypeAdvisory {
		t.Errorf("References[0].Type = %q, want ADVISORY", vuln.References[0].Type)
	}

	// Check credits
	if len(vuln.Credits) != 1 {
		t.Fatalf("Credits length = %d, want 1", len(vuln.Credits))
	}
	if vuln.Credits[0].Name != "researcher1" {
		t.Errorf("Credits[0].Name = %q, want researcher1", vuln.Credits[0].Name)
	}
	if vuln.Credits[0].Type != model.CreditTypeFinder {
		t.Errorf("Credits[0].Type = %q, want FINDER", vuln.Credits[0].Type)
	}

	// Check RawJSON is set
	if len(vuln.RawJSON) == 0 {
		t.Error("RawJSON should not be empty")
	}
}

func TestConvertGitHubToOSV_NoCVSS(t *testing.T) {
	// Advisory without CVSS vector (common for repo-level advisories)
	input := `{
		"ghsa_id": "GHSA-no-cvss-test",
		"cve_id": "",
		"summary": "No CVSS advisory",
		"description": "Test",
		"severity": "critical",
		"identifiers": [{"type": "GHSA", "value": "GHSA-no-cvss-test"}],
		"published_at": "2026-01-01T00:00:00Z",
		"updated_at": "2026-01-01T00:00:00Z",
		"vulnerabilities": [],
		"cvss_severities": {"cvss_v3": {"vector_string": null, "score": null}, "cvss_v4": null},
		"cvss": {"vector_string": null, "score": null},
		"cwes": [],
		"credits": [],
		"credits_detailed": []
	}`

	vuln, err := ConvertGitHubToOSV([]byte(input))
	if err != nil {
		t.Fatalf("ConvertGitHubToOSV() error: %v", err)
	}

	if vuln.ID != "GHSA-no-cvss-test" {
		t.Errorf("ID = %q, want GHSA-no-cvss-test", vuln.ID)
	}

	// No CVSS vector → severity should be empty
	if len(vuln.Severity) != 0 {
		t.Errorf("Severity = %v, want empty (no CVSS vector available)", vuln.Severity)
	}

	// No aliases (empty cve_id)
	if len(vuln.Aliases) != 0 {
		t.Errorf("Aliases = %v, want empty", vuln.Aliases)
	}
}

func TestExtractIntroduced(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"6.8.0 - 6.8.5", "6.8.0"},
		{">= 1.0.0, < 2.0.0", "1.0.0"},
		{">= 1.0.0", "1.0.0"},
		{"> 1.0.0", "1.0.0"},
		{"< 1.5.0", ""},
		{"= 1.0.0", "1.0.0"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := extractIntroduced(tt.input)
			if got != tt.want {
				t.Errorf("extractIntroduced(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeEcosystem(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"npm", "npm"},
		{"pip", "PyPI"},
		{"rubygems", "RubyGems"},
		{"go", "Go"},
		{"maven", "Maven"},
		{"nuget", "NuGet"},
		{"composer", "Packagist"},
		{"rust", "crates.io"},
		{"wordpress", "Wordpress"},
		{"actions", "GitHub Actions"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeEcosystem(tt.input)
			if got != tt.want {
				t.Errorf("normalizeEcosystem(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
