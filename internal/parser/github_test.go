package parser

import (
	"testing"
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

func TestParseGitHubToGHSAEntry(t *testing.T) {
	input := `{
		"ghsa_id": "GHSA-test-test-test",
		"cve_id": "CVE-2026-99999",
		"html_url": "https://github.com/example/repo/security/advisories/GHSA-test-test-test",
		"summary": "Test ` + "`vulnerability`" + `",
		"description": "A test vulnerability.\r\n\r\nAffects versions 1.0 to 1.5.",
		"severity": "high",
		"state": "published",
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

	entry, err := ParseGitHubToGHSAEntry([]byte(input))
	if err != nil {
		t.Fatalf("ParseGitHubToGHSAEntry() error: %v", err)
	}

	// Check GHSA ID
	if entry.GHSAID != "GHSA-test-test-test" {
		t.Errorf("GHSAID = %q, want %q", entry.GHSAID, "GHSA-test-test-test")
	}

	// Check CVE ID
	if entry.CVEID != "CVE-2026-99999" {
		t.Errorf("CVEID = %q, want %q", entry.CVEID, "CVE-2026-99999")
	}

	// Check summary (backticks removed)
	if entry.Summary != "Test vulnerability" {
		t.Errorf("Summary = %q, want %q", entry.Summary, "Test vulnerability")
	}

	// Check description (CRLF normalized)
	if got := entry.Description; got != "A test vulnerability.\n\nAffects versions 1.0 to 1.5." {
		t.Errorf("Description = %q, unexpected", got)
	}

	// Check severity
	if entry.Severity != "high" {
		t.Errorf("Severity = %q, want %q", entry.Severity, "high")
	}

	// Check state
	if entry.State != "published" {
		t.Errorf("State = %q, want %q", entry.State, "published")
	}

	// Check timestamps
	if entry.PublishedAt == nil {
		t.Fatal("PublishedAt should not be nil")
	}
	if entry.UpdatedAt == nil {
		t.Fatal("UpdatedAt should not be nil")
	}
	if entry.UpdatedAt.Day() != 2 {
		t.Errorf("UpdatedAt day = %d, want 2", entry.UpdatedAt.Day())
	}

	// Check vulnerabilities (affected packages)
	if len(entry.Vulnerabilities) != 2 {
		t.Fatalf("Vulnerabilities length = %d, want 2", len(entry.Vulnerabilities))
	}
	if entry.Vulnerabilities[0].Ecosystem != "npm" {
		t.Errorf("Vulnerabilities[0].Ecosystem = %q, want npm", entry.Vulnerabilities[0].Ecosystem)
	}
	if entry.Vulnerabilities[0].PackageName != "my-package" {
		t.Errorf("Vulnerabilities[0].PackageName = %q, want my-package", entry.Vulnerabilities[0].PackageName)
	}
	if entry.Vulnerabilities[0].VulnerableVersionRange != "1.0.0 - 1.5.0" {
		t.Errorf("Vulnerabilities[0].VulnerableVersionRange = %q, want '1.0.0 - 1.5.0'", entry.Vulnerabilities[0].VulnerableVersionRange)
	}
	if entry.Vulnerabilities[0].PatchedVersions != "1.5.1" {
		t.Errorf("Vulnerabilities[0].PatchedVersions = %q, want 1.5.1", entry.Vulnerabilities[0].PatchedVersions)
	}

	// Check credits
	if len(entry.Credits) != 1 {
		t.Fatalf("Credits length = %d, want 1", len(entry.Credits))
	}
	if entry.Credits[0].Login != "researcher1" {
		t.Errorf("Credits[0].Login = %q, want researcher1", entry.Credits[0].Login)
	}

	// Check CWEs
	if len(entry.CWEs) != 1 {
		t.Fatalf("CWEs length = %d, want 1", len(entry.CWEs))
	}
	if entry.CWEs[0].CWEID != "CWE-79" {
		t.Errorf("CWEs[0].CWEID = %q, want CWE-79", entry.CWEs[0].CWEID)
	}
	if entry.CWEs[0].Name != "XSS" {
		t.Errorf("CWEs[0].Name = %q, want XSS", entry.CWEs[0].Name)
	}

	// Check HTML URL
	if entry.HTMLURL != "https://github.com/example/repo/security/advisories/GHSA-test-test-test" {
		t.Errorf("HTMLURL = %q, unexpected", entry.HTMLURL)
	}

	// Check RawJSON is set
	if len(entry.RawJSON) == 0 {
		t.Error("RawJSON should not be empty")
	}
}

func TestParseGitHubToGHSAEntry_NoCVSS(t *testing.T) {
	input := `{
		"ghsa_id": "GHSA-no-cvss-test",
		"cve_id": "",
		"summary": "No CVSS advisory",
		"description": "Test",
		"severity": "critical",
		"state": "published",
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

	entry, err := ParseGitHubToGHSAEntry([]byte(input))
	if err != nil {
		t.Fatalf("ParseGitHubToGHSAEntry() error: %v", err)
	}

	if entry.GHSAID != "GHSA-no-cvss-test" {
		t.Errorf("GHSAID = %q, want GHSA-no-cvss-test", entry.GHSAID)
	}

	// Severity label is preserved even without CVSS vector
	if entry.Severity != "critical" {
		t.Errorf("Severity = %q, want critical", entry.Severity)
	}

	// No CVE
	if entry.CVEID != "" {
		t.Errorf("CVEID = %q, want empty", entry.CVEID)
	}

	// No vulnerabilities
	if len(entry.Vulnerabilities) != 0 {
		t.Errorf("Vulnerabilities = %v, want empty", entry.Vulnerabilities)
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
