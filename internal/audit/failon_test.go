package audit

import (
	"testing"

	"github.com/kato83/mayu/internal/sbom"
)

func TestParseFailOn(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		want    int
		wantErr bool
	}{
		{
			name: "critical only",
			spec: "critical",
			want: 5,
		},
		{
			name: "critical and high",
			spec: "critical,high",
			want: 4,
		},
		{
			name: "medium",
			spec: "medium",
			want: 3,
		},
		{
			name: "low",
			spec: "low",
			want: 2,
		},
		{
			name: "none",
			spec: "none",
			want: 1,
		},
		{
			name: "case insensitive",
			spec: "CRITICAL,High",
			want: 4,
		},
		{
			name: "with spaces",
			spec: " critical , high ",
			want: 4,
		},
		{
			name:    "invalid label",
			spec:    "invalid",
			wantErr: true,
		},
		{
			name:    "empty string",
			spec:    "",
			wantErr: true,
		},
		{
			name:    "only spaces",
			spec:    "   ",
			wantErr: true,
		},
		{
			name:    "mixed valid and invalid",
			spec:    "critical,bogus",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseFailOn(tt.spec)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseFailOn(%q) error: %v", tt.spec, err)
			}
			if got != tt.want {
				t.Errorf("ParseFailOn(%q) = %d, want %d", tt.spec, got, tt.want)
			}
		})
	}
}

func TestShouldFail(t *testing.T) {
	findings := []Finding{
		{
			Component:     sbom.Component{Name: "pkg-low", Version: "1.0.0"},
			VulnID:        "CVE-2024-0001",
			Severity:      "LOW",
			SeverityLevel: 2,
		},
		{
			Component:     sbom.Component{Name: "pkg-medium", Version: "1.0.0"},
			VulnID:        "CVE-2024-0002",
			Severity:      "MEDIUM",
			SeverityLevel: 3,
		},
		{
			Component:     sbom.Component{Name: "pkg-high", Version: "1.0.0"},
			VulnID:        "CVE-2024-0003",
			Severity:      "HIGH",
			SeverityLevel: 4,
		},
	}

	tests := []struct {
		name     string
		findings []Finding
		minLevel int
		want     bool
	}{
		{
			name:     "findings below threshold",
			findings: findings,
			minLevel: 5, // CRITICAL only
			want:     false,
		},
		{
			name:     "findings at threshold",
			findings: findings,
			minLevel: 4, // HIGH and above
			want:     true,
		},
		{
			name:     "findings above threshold",
			findings: findings,
			minLevel: 2, // LOW and above
			want:     true,
		},
		{
			name:     "empty findings",
			findings: []Finding{},
			minLevel: 1,
			want:     false,
		},
		{
			name:     "nil findings",
			findings: nil,
			minLevel: 1,
			want:     false,
		},
		{
			name: "exact threshold match",
			findings: []Finding{
				{
					Component:     sbom.Component{Name: "pkg", Version: "1.0.0"},
					VulnID:        "CVE-2024-0001",
					Severity:      "MEDIUM",
					SeverityLevel: 3,
				},
			},
			minLevel: 3,
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShouldFail(tt.findings, tt.minLevel)
			if got != tt.want {
				t.Errorf("ShouldFail() = %v, want %v", got, tt.want)
			}
		})
	}
}
