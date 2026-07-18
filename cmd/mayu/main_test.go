package main

import (
	"testing"

	"github.com/kato83/mayu/internal/model"
)

func TestParseCVSSScore(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  float64
	}{
		{"plain numeric", "9.8", 9.8},
		{"integer", "7", 7.0},
		{"zero", "0.0", 0.0},
		{"low score", "3.1", 3.1},
		{"empty string", "", 0},
		{"non-numeric", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 0},
		{"whitespace padded", "  9.8  ", 9.8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseCVSSScore(tt.input)
			if got != tt.want {
				t.Errorf("parseCVSSScore(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestFormatAliases(t *testing.T) {
	tests := []struct {
		name    string
		aliases []string
		maxLen  int
		want    string
	}{
		{"no aliases", nil, 15, "-"},
		{"empty slice", []string{}, 15, "-"},
		{"single CVE", []string{"CVE-2024-1234"}, 20, "CVE-2024-1234"},
		{"single non-CVE", []string{"GHSA-xxxx-yyyy"}, 20, "GHSA-xxxx-yyyy"},
		{"CVE prioritized", []string{"GHSA-xxxx-yyyy", "CVE-2024-1234"}, 20, "CVE-2024-1234 +1"},
		{"multiple CVEs", []string{"CVE-2024-1111", "CVE-2024-2222", "GHSA-aaaa"}, 20, "CVE-2024-1111 +2"},
		{"truncated", []string{"CVE-2024-1234"}, 10, "CVE-20..."},
		{"multiple non-CVE", []string{"GHSA-aaaa", "GHSA-bbbb", "GHSA-cccc"}, 20, "GHSA-aaaa +2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatAliases(tt.aliases, tt.maxLen)
			if got != tt.want {
				t.Errorf("formatAliases(%v, %d) = %q, want %q", tt.aliases, tt.maxLen, got, tt.want)
			}
		})
	}
}

func TestFormatSeverity(t *testing.T) {
	tests := []struct {
		name string
		vuln *model.Vulnerability
		want string
	}{
		{
			name: "no severity",
			vuln: &model.Vulnerability{},
			want: "-",
		},
		{
			name: "top-level severity",
			vuln: &model.Vulnerability{
				Severity: []model.Severity{
					{Type: model.SeverityTypeCVSSV3, Score: "9.8"},
				},
			},
			want: "9.8",
		},
		{
			name: "per-affected severity",
			vuln: &model.Vulnerability{
				Affected: []model.Affected{
					{
						Severity: []model.Severity{
							{Type: model.SeverityTypeCVSSV3, Score: "7.5"},
						},
					},
				},
			},
			want: "7.5",
		},
		{
			name: "highest score wins",
			vuln: &model.Vulnerability{
				Severity: []model.Severity{
					{Type: model.SeverityTypeCVSSV3, Score: "5.0"},
				},
				Affected: []model.Affected{
					{
						Severity: []model.Severity{
							{Type: model.SeverityTypeCVSSV3, Score: "8.1"},
						},
					},
					{
						Severity: []model.Severity{
							{Type: model.SeverityTypeCVSSV3, Score: "3.2"},
						},
					},
				},
			},
			want: "8.1",
		},
		{
			name: "non-numeric score ignored",
			vuln: &model.Vulnerability{
				Severity: []model.Severity{
					{Type: model.SeverityTypeCVSSV3, Score: "CVSS:3.1/AV:N/AC:L"},
				},
			},
			want: "-",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatSeverity(tt.vuln)
			if got != tt.want {
				t.Errorf("formatSeverity() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCsvEscape(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"plain text", "hello", "hello"},
		{"contains comma", "hello,world", "\"hello,world\""},
		{"contains quote", `say "hi"`, `"say ""hi"""`},
		{"contains newline", "line1\nline2", "\"line1\nline2\""},
		{"contains CR", "line1\rline2", "\"line1\rline2\""},
		{"empty string", "", ""},
		{"no special chars", "CVE-2024-1234", "CVE-2024-1234"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := csvEscape(tt.input)
			if got != tt.want {
				t.Errorf("csvEscape(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxRunes int
		want     string
	}{
		{"short string", "hello", 10, "hello"},
		{"exact length", "hello", 5, "hello"},
		{"truncated", "hello world", 8, "hello..."},
		{"very short max", "hello", 3, "..."},
		{"unicode safe", "こんにちは世界", 5, "こん..."},
		{"empty string", "", 10, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateString(tt.input, tt.maxRunes)
			if got != tt.want {
				t.Errorf("truncateString(%q, %d) = %q, want %q", tt.input, tt.maxRunes, got, tt.want)
			}
		})
	}
}

func TestLooksLikeVulnID(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"CVE", "CVE-2024-1234", true},
		{"GO prefix", "GO-2024-2687", true},
		{"GHSA", "GHSA-xxxx-yyyy-zzzz", true},
		{"PYSEC", "PYSEC-2024-1", true},
		{"RUSTSEC", "RUSTSEC-2024-0001", true},
		{"DSA", "DSA-5000", true},
		{"lowercase cve", "cve-2024-1234", true},
		{"package name", "golang.org/x/crypto", false},
		{"random text", "some query", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := looksLikeVulnID(tt.input)
			if got != tt.want {
				t.Errorf("looksLikeVulnID(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateDateInput(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid YYYY-MM-DD", "2024-01-15", false},
		{"valid RFC3339", "2024-01-15T10:30:00Z", false},
		{"valid RFC3339 with offset", "2024-01-15T10:30:00+09:00", false},
		{"invalid format", "01-15-2024", true},
		{"invalid date", "2024-13-45", true},
		{"empty string", "", true},
		{"random text", "yesterday", true},
		{"partial date", "2024-01", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDateInput(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateDateInput(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}
