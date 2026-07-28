package audit

import (
	"encoding/json"
	"testing"

	"github.com/kato83/mayu/internal/sbom"
)

func TestGenerateSARIF(t *testing.T) {
	tests := []struct {
		name        string
		result      *AuditResult
		toolVersion string
		wantRules   int
		wantResults int
	}{
		{
			name: "empty findings produces valid SARIF",
			result: &AuditResult{
				Findings:      []Finding{},
				TotalPackages: 5,
			},
			toolVersion: "1.0.0",
			wantRules:   0,
			wantResults: 0,
		},
		{
			name: "single finding",
			result: &AuditResult{
				Findings: []Finding{
					{
						Component:     sbom.Component{Name: "express", Version: "4.18.2", Ecosystem: "npm"},
						VulnID:        "CVE-2024-1234",
						Severity:      "HIGH",
						SeverityLevel: 4,
						Summary:       "XSS vulnerability",
					},
				},
				TotalPackages:      1,
				VulnerablePackages: 1,
			},
			toolVersion: "dev",
			wantRules:   1,
			wantResults: 1,
		},
		{
			name: "multiple findings same vuln ID produce one rule",
			result: &AuditResult{
				Findings: []Finding{
					{
						Component:     sbom.Component{Name: "pkg-a", Version: "1.0.0", Ecosystem: "npm"},
						VulnID:        "CVE-2024-1234",
						Severity:      "HIGH",
						SeverityLevel: 4,
						Summary:       "Shared vuln",
					},
					{
						Component:     sbom.Component{Name: "pkg-b", Version: "2.0.0", Ecosystem: "npm"},
						VulnID:        "CVE-2024-1234",
						Severity:      "HIGH",
						SeverityLevel: 4,
						Summary:       "Shared vuln",
					},
				},
				TotalPackages:      2,
				VulnerablePackages: 2,
			},
			toolVersion: "1.2.3",
			wantRules:   1,
			wantResults: 2,
		},
		{
			name: "multiple different vuln IDs",
			result: &AuditResult{
				Findings: []Finding{
					{
						Component:     sbom.Component{Name: "pkg-a", Version: "1.0.0", Ecosystem: "npm"},
						VulnID:        "CVE-2024-1111",
						Severity:      "CRITICAL",
						SeverityLevel: 5,
						Summary:       "Critical vuln",
					},
					{
						Component:     sbom.Component{Name: "pkg-b", Version: "2.0.0", Ecosystem: "npm"},
						VulnID:        "CVE-2024-2222",
						Severity:      "LOW",
						SeverityLevel: 2,
						Summary:       "Low vuln",
					},
				},
				TotalPackages:      2,
				VulnerablePackages: 2,
			},
			toolVersion: "2.0.0",
			wantRules:   2,
			wantResults: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := GenerateSARIF(tt.result, tt.toolVersion)
			if err != nil {
				t.Fatalf("GenerateSARIF() error: %v", err)
			}

			// Verify valid JSON
			var log sarifLog
			if err := json.Unmarshal(data, &log); err != nil {
				t.Fatalf("invalid JSON output: %v", err)
			}

			// Check top-level fields
			if log.Version != "2.1.0" {
				t.Errorf("version = %q, want %q", log.Version, "2.1.0")
			}
			if log.Schema != sarifSchemaURI {
				t.Errorf("$schema = %q, want %q", log.Schema, sarifSchemaURI)
			}

			// Check runs
			if len(log.Runs) != 1 {
				t.Fatalf("len(runs) = %d, want 1", len(log.Runs))
			}
			run := log.Runs[0]

			// Check tool
			if run.Tool.Driver.Name != "mayu" {
				t.Errorf("tool.driver.name = %q, want %q", run.Tool.Driver.Name, "mayu")
			}
			if run.Tool.Driver.Version != tt.toolVersion {
				t.Errorf("tool.driver.version = %q, want %q", run.Tool.Driver.Version, tt.toolVersion)
			}

			// Check rules count
			if len(run.Tool.Driver.Rules) != tt.wantRules {
				t.Errorf("len(rules) = %d, want %d", len(run.Tool.Driver.Rules), tt.wantRules)
			}

			// Check results count
			if len(run.Results) != tt.wantResults {
				t.Errorf("len(results) = %d, want %d", len(run.Results), tt.wantResults)
			}
		})
	}
}

func TestGenerateSARIF_SeverityMapping(t *testing.T) {
	tests := []struct {
		name              string
		severityLevel     int
		wantLevel         string
		wantSecSeverity   string
	}{
		{name: "CRITICAL", severityLevel: 5, wantLevel: "error", wantSecSeverity: "9.0"},
		{name: "HIGH", severityLevel: 4, wantLevel: "error", wantSecSeverity: "7.0"},
		{name: "MEDIUM", severityLevel: 3, wantLevel: "warning", wantSecSeverity: "4.0"},
		{name: "LOW", severityLevel: 2, wantLevel: "note", wantSecSeverity: "2.0"},
		{name: "NONE", severityLevel: 1, wantLevel: "note", wantSecSeverity: "0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &AuditResult{
				Findings: []Finding{
					{
						Component:     sbom.Component{Name: "pkg", Version: "1.0.0", Ecosystem: "npm"},
						VulnID:        "CVE-2024-0001",
						Severity:      tt.name,
						SeverityLevel: tt.severityLevel,
						Summary:       "Test vulnerability",
					},
				},
			}

			data, err := GenerateSARIF(result, "test")
			if err != nil {
				t.Fatalf("GenerateSARIF() error: %v", err)
			}

			var log sarifLog
			if err := json.Unmarshal(data, &log); err != nil {
				t.Fatalf("invalid JSON: %v", err)
			}

			run := log.Runs[0]

			// Check result level
			if len(run.Results) != 1 {
				t.Fatalf("expected 1 result, got %d", len(run.Results))
			}
			if run.Results[0].Level != tt.wantLevel {
				t.Errorf("result level = %q, want %q", run.Results[0].Level, tt.wantLevel)
			}

			// Check rule security-severity
			if len(run.Tool.Driver.Rules) != 1 {
				t.Fatalf("expected 1 rule, got %d", len(run.Tool.Driver.Rules))
			}
			if run.Tool.Driver.Rules[0].Properties.SecuritySeverity != tt.wantSecSeverity {
				t.Errorf("security-severity = %q, want %q",
					run.Tool.Driver.Rules[0].Properties.SecuritySeverity, tt.wantSecSeverity)
			}
		})
	}
}

func TestGenerateSARIF_RuleFields(t *testing.T) {
	result := &AuditResult{
		Findings: []Finding{
			{
				Component:     sbom.Component{Name: "express", Version: "4.18.2", Ecosystem: "npm"},
				VulnID:        "CVE-2024-1234",
				Severity:      "HIGH",
				SeverityLevel: 4,
				Summary:       "XSS in express",
			},
		},
	}

	data, err := GenerateSARIF(result, "1.0.0")
	if err != nil {
		t.Fatalf("GenerateSARIF() error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	rule := log.Runs[0].Tool.Driver.Rules[0]

	if rule.ID != "CVE-2024-1234" {
		t.Errorf("rule.id = %q, want %q", rule.ID, "CVE-2024-1234")
	}
	if rule.ShortDescription.Text != "XSS in express" {
		t.Errorf("rule.shortDescription.text = %q, want %q", rule.ShortDescription.Text, "XSS in express")
	}
	wantURI := "https://osv.dev/vulnerability/CVE-2024-1234"
	if rule.HelpURI != wantURI {
		t.Errorf("rule.helpUri = %q, want %q", rule.HelpURI, wantURI)
	}

	// Check result message
	res := log.Runs[0].Results[0]
	if res.RuleID != "CVE-2024-1234" {
		t.Errorf("result.ruleId = %q, want %q", res.RuleID, "CVE-2024-1234")
	}
	if res.RuleIndex != 0 {
		t.Errorf("result.ruleIndex = %d, want 0", res.RuleIndex)
	}

	// Check locations field (required by GitHub Code Scanning)
	if len(res.Locations) != 1 {
		t.Fatalf("result.locations length = %d, want 1", len(res.Locations))
	}
	loc := res.Locations[0]
	if len(loc.LogicalLocations) != 1 {
		t.Fatalf("logicalLocations length = %d, want 1", len(loc.LogicalLocations))
	}
	ll := loc.LogicalLocations[0]
	wantName := "express@4.18.2"
	if ll.Name != wantName {
		t.Errorf("logicalLocation.name = %q, want %q", ll.Name, wantName)
	}
	if ll.Kind != "package" {
		t.Errorf("logicalLocation.kind = %q, want %q", ll.Kind, "package")
	}
}
