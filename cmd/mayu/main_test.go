package main

import (
	"testing"
	"unicode/utf8"

	"github.com/kato83/mayu/internal/model"
	"github.com/kato83/mayu/internal/validate"
)

func TestTruncateString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxRunes int
		want     string
	}{
		{"short ascii", "hello", 40, "hello"},
		{"exact length", "12345", 5, "12345"},
		{"truncate ascii", "abcdefghij", 8, "abcde..."},
		{"multibyte japanese", "これは日本語の脆弱性の要約テキストです", 10, "これは日本語の..."},
		{"multibyte exact", "あいうえお", 5, "あいうえお"},
		{"very small max", "hello", 2, "..."},
		{"empty string", "", 10, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateString(tt.input, tt.maxRunes)
			if got != tt.want {
				t.Errorf("truncateString(%q, %d) = %q, want %q", tt.input, tt.maxRunes, got, tt.want)
			}
			// The result must always be valid UTF-8 (the core of the L-4 fix).
			if !utf8.ValidString(got) {
				t.Errorf("truncateString(%q, %d) produced invalid UTF-8: %q", tt.input, tt.maxRunes, got)
			}
			// The result must not exceed maxRunes runes.
			if n := utf8.RuneCountInString(got); n > tt.maxRunes && tt.maxRunes > 3 {
				t.Errorf("truncateString(%q, %d) returned %d runes, exceeds max", tt.input, tt.maxRunes, n)
			}
		})
	}
}

func TestIsLocalHost(t *testing.T) {
	local := []string{"", "localhost", "127.0.0.1", "::1"}
	for _, h := range local {
		if !isLocalHost(h) {
			t.Errorf("isLocalHost(%q) = false, want true", h)
		}
	}
	remote := []string{"db.example.com", "10.0.0.5", "192.168.1.1", "example.org"}
	for _, h := range remote {
		if isLocalHost(h) {
			t.Errorf("isLocalHost(%q) = true, want false", h)
		}
	}
}

func TestIsInsecureRemoteURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{"local disable is fine", "postgres://mayu:mayu@localhost:5432/mayu?sslmode=disable", false},
		{"local no sslmode is fine", "postgres://mayu:mayu@127.0.0.1:5432/mayu", false},
		{"remote disable is insecure", "postgres://u:p@db.example.com:5432/mayu?sslmode=disable", true},
		{"remote no sslmode is insecure", "postgres://u:p@db.example.com:5432/mayu", true},
		{"remote prefer is insecure", "postgres://u:p@db.example.com:5432/mayu?sslmode=prefer", true},
		{"remote require is fine", "postgres://u:p@db.example.com:5432/mayu?sslmode=require", false},
		{"remote verify-full is fine", "postgres://u:p@db.example.com:5432/mayu?sslmode=verify-full", false},
		{"unparseable is ignored", "://not a url", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, _ := isInsecureRemoteURL(tt.url)
			if got != tt.want {
				t.Errorf("isInsecureRemoteURL(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

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
		{"non-numeric", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"whitespace padded", "  9.8  ", 9.8},
		{"vector with scope changed", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1},
		{"cvss v4 unsupported", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 0},
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
		{"truncated", []string{"CVE-2024-1234"}, 10, "CVE-202..."},
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
			want: "9.8 CRITICAL",
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
			want: "7.5 HIGH",
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
			want: "8.1 HIGH",
		},
		{
			name: "CVSS vector string produces score",
			vuln: &model.Vulnerability{
				Severity: []model.Severity{
					{Type: model.SeverityTypeCVSSV3, Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
				},
			},
			want: "9.8 CRITICAL",
		},
		{
			name: "incomplete CVSS vector ignored",
			vuln: &model.Vulnerability{
				Severity: []model.Severity{
					{Type: model.SeverityTypeCVSSV3, Score: "CVSS:3.1/AV:N/AC:L"},
				},
			},
			want: "-",
		},
		{
			name: "max score 10.0",
			vuln: &model.Vulnerability{
				Severity: []model.Severity{
					{Type: model.SeverityTypeCVSSV3, Score: "10.0"},
				},
			},
			want: "10.0 CRITICAL",
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
			err := validate.DateInput(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("validate.DateInput(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}
