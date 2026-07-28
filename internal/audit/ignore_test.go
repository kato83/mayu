package audit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kato83/mayu/internal/sbom"
)

func TestParseIgnoreFile(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    map[string]bool
		wantErr bool
	}{
		{
			name:    "valid CVE IDs",
			content: "CVE-2024-1234\nCVE-2024-5678\n",
			want:    map[string]bool{"CVE-2024-1234": true, "CVE-2024-5678": true},
		},
		{
			name:    "GHSA IDs",
			content: "GHSA-xxxx-yyyy-zzzz\n",
			want:    map[string]bool{"GHSA-xxxx-yyyy-zzzz": true},
		},
		{
			name:    "comment lines skipped",
			content: "# This is a comment\nCVE-2024-1234\n# Another comment\n",
			want:    map[string]bool{"CVE-2024-1234": true},
		},
		{
			name:    "blank lines skipped",
			content: "\n\nCVE-2024-1234\n\n\nCVE-2024-5678\n\n",
			want:    map[string]bool{"CVE-2024-1234": true, "CVE-2024-5678": true},
		},
		{
			name:    "inline comments stripped",
			content: "CVE-2024-1234  # reason: no impact\nGHSA-xxxx-yyyy-zzzz # suppressed\n",
			want:    map[string]bool{"CVE-2024-1234": true, "GHSA-xxxx-yyyy-zzzz": true},
		},
		{
			name:    "whitespace trimmed",
			content: "  CVE-2024-1234  \n\tCVE-2024-5678\t\n",
			want:    map[string]bool{"CVE-2024-1234": true, "CVE-2024-5678": true},
		},
		{
			name:    "empty file",
			content: "",
			want:    map[string]bool{},
		},
		{
			name:    "only comments and blank lines",
			content: "# comment 1\n\n# comment 2\n",
			want:    map[string]bool{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, ".mayu-ignore")
			if err := os.WriteFile(path, []byte(tt.content), 0644); err != nil {
				t.Fatalf("write temp file: %v", err)
			}

			got, err := ParseIgnoreFile(path)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseIgnoreFile() error: %v", err)
			}

			if len(got) != len(tt.want) {
				t.Errorf("got %d entries, want %d", len(got), len(tt.want))
			}
			for id := range tt.want {
				if !got[id] {
					t.Errorf("missing expected ID: %s", id)
				}
			}
		})
	}
}

func TestParseIgnoreFile_NonExistentFile(t *testing.T) {
	_, err := ParseIgnoreFile("/nonexistent/path/.mayu-ignore")
	if err == nil {
		t.Fatal("expected error for non-existent file, got nil")
	}
}

func TestFilterFindings(t *testing.T) {
	findings := []Finding{
		{
			Component: sbom.Component{Name: "pkg-a", Version: "1.0.0"},
			VulnID:    "CVE-2024-1234",
			Aliases:   []string{"GHSA-aaaa-bbbb-cccc"},
			Severity:  "HIGH",
		},
		{
			Component: sbom.Component{Name: "pkg-b", Version: "2.0.0"},
			VulnID:    "CVE-2024-5678",
			Aliases:   []string{"GHSA-dddd-eeee-ffff"},
			Severity:  "CRITICAL",
		},
		{
			Component: sbom.Component{Name: "pkg-c", Version: "3.0.0"},
			VulnID:    "CVE-2024-9999",
			Severity:  "MEDIUM",
		},
	}

	tests := []struct {
		name    string
		ignored map[string]bool
		wantLen int
		wantIDs []string
	}{
		{
			name:    "no ignored IDs",
			ignored: map[string]bool{},
			wantLen: 3,
			wantIDs: []string{"CVE-2024-1234", "CVE-2024-5678", "CVE-2024-9999"},
		},
		{
			name:    "ignore by VulnID",
			ignored: map[string]bool{"CVE-2024-1234": true},
			wantLen: 2,
			wantIDs: []string{"CVE-2024-5678", "CVE-2024-9999"},
		},
		{
			name:    "ignore by alias",
			ignored: map[string]bool{"GHSA-aaaa-bbbb-cccc": true},
			wantLen: 2,
			wantIDs: []string{"CVE-2024-5678", "CVE-2024-9999"},
		},
		{
			name:    "ignore multiple",
			ignored: map[string]bool{"CVE-2024-1234": true, "CVE-2024-9999": true},
			wantLen: 1,
			wantIDs: []string{"CVE-2024-5678"},
		},
		{
			name:    "ignore all",
			ignored: map[string]bool{"CVE-2024-1234": true, "CVE-2024-5678": true, "CVE-2024-9999": true},
			wantLen: 0,
			wantIDs: []string{},
		},
		{
			name:    "nil ignored map",
			ignored: nil,
			wantLen: 3,
			wantIDs: []string{"CVE-2024-1234", "CVE-2024-5678", "CVE-2024-9999"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FilterFindings(findings, tt.ignored)
			if len(got) != tt.wantLen {
				t.Errorf("FilterFindings() returned %d findings, want %d", len(got), tt.wantLen)
			}
			for i, wantID := range tt.wantIDs {
				if i >= len(got) {
					break
				}
				if got[i].VulnID != wantID {
					t.Errorf("finding[%d].VulnID = %q, want %q", i, got[i].VulnID, wantID)
				}
			}
		})
	}
}
