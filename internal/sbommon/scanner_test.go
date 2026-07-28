package sbommon

import (
	"context"
	"testing"

	"github.com/kato83/mayu/internal/model"
	"github.com/kato83/mayu/internal/store"
)

// mockVulnStore implements audit.VulnStore for testing.
type mockVulnStore struct {
	results map[string][]*model.Vulnerability
}

func (m *mockVulnStore) SearchByPackages(_ context.Context, packages []store.PackageQuery) (map[string][]*model.Vulnerability, error) {
	result := make(map[string][]*model.Vulnerability)
	for _, pkg := range packages {
		key := pkg.Ecosystem + "/" + pkg.Name
		if vulns, ok := m.results[key]; ok {
			result[key] = vulns
		}
	}
	return result, nil
}

func TestScanner_Scan(t *testing.T) {
	// Minimal CycloneDX SBOM with one component
	sbomData := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.7",
		"components": [
			{
				"type": "library",
				"purl": "pkg:npm/lodash@4.17.20"
			}
		]
	}`)

	vulnStore := &mockVulnStore{
		results: map[string][]*model.Vulnerability{
			"npm/lodash": {
				{
					ID:            "GHSA-test-1234",
					Aliases:       []string{"CVE-2021-23337"},
					Summary:       "Prototype pollution in lodash",
					SeverityLevel: 4,
					Affected: []model.Affected{
						{
							Package: model.Package{
								Ecosystem: "npm",
								Name:      "lodash",
							},
							Ranges: []model.Range{
								{
									Type: model.RangeTypeSemVer,
									Events: []model.Event{
										{Introduced: "0"},
										{Fixed: "4.17.21"},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	scanner := NewScanner(vulnStore)
	result, err := scanner.Scan(context.Background(), sbomData)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	if result.Status != "completed" {
		t.Errorf("Status = %q, want %q", result.Status, "completed")
	}
	if result.TotalPackages != 1 {
		t.Errorf("TotalPackages = %d, want 1", result.TotalPackages)
	}
	if result.VulnerablePackages != 1 {
		t.Errorf("VulnerablePackages = %d, want 1", result.VulnerablePackages)
	}
	if result.TotalFindings != 1 {
		t.Errorf("TotalFindings = %d, want 1", result.TotalFindings)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("len(Findings) = %d, want 1", len(result.Findings))
	}

	f := result.Findings[0]
	if f.VulnID != "GHSA-test-1234" {
		t.Errorf("VulnID = %q, want %q", f.VulnID, "GHSA-test-1234")
	}
	if f.Name != "lodash" {
		t.Errorf("Name = %q, want %q", f.Name, "lodash")
	}
	if f.Severity != "HIGH" {
		t.Errorf("Severity = %q, want %q", f.Severity, "HIGH")
	}
}

func TestScanner_ScanVersion(t *testing.T) {
	sbomData := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.7",
		"components": []
	}`)

	vulnStore := &mockVulnStore{results: map[string][]*model.Vulnerability{}}
	scanner := NewScanner(vulnStore)

	version := &SBOMVersion{
		ID:      42,
		RawSBOM: sbomData,
	}

	result, err := scanner.ScanVersion(context.Background(), version)
	if err != nil {
		t.Fatalf("ScanVersion() error = %v", err)
	}
	if result.VersionID != 42 {
		t.Errorf("VersionID = %d, want 42", result.VersionID)
	}
	if result.TotalPackages != 0 {
		t.Errorf("TotalPackages = %d, want 0", result.TotalPackages)
	}
}

func TestScanner_ScanVersion_NilVersion(t *testing.T) {
	vulnStore := &mockVulnStore{}
	scanner := NewScanner(vulnStore)

	_, err := scanner.ScanVersion(context.Background(), nil)
	if err == nil {
		t.Fatal("ScanVersion(nil) should return error")
	}
}

func TestComputeDiff(t *testing.T) {
	tests := []struct {
		name             string
		current          *SBOMScanResult
		previous         *SBOMScanResult
		wantNew          int
		wantResolved     int
	}{
		{
			name:    "nil current returns empty diff",
			current: nil,
			previous: &SBOMScanResult{
				Findings: []ScanFinding{{VulnID: "CVE-1", Name: "pkg", Version: "1.0", Ecosystem: "npm"}},
			},
			wantNew:      0,
			wantResolved: 0,
		},
		{
			name: "no previous scan - all findings are new",
			current: &SBOMScanResult{
				Findings: []ScanFinding{
					{VulnID: "CVE-1", Name: "pkg-a", Version: "1.0", Ecosystem: "npm"},
					{VulnID: "CVE-2", Name: "pkg-b", Version: "2.0", Ecosystem: "npm"},
				},
			},
			previous:     nil,
			wantNew:      2,
			wantResolved: 0,
		},
		{
			name: "new findings added",
			current: &SBOMScanResult{
				Findings: []ScanFinding{
					{VulnID: "CVE-1", Name: "pkg-a", Version: "1.0", Ecosystem: "npm"},
					{VulnID: "CVE-2", Name: "pkg-b", Version: "2.0", Ecosystem: "npm"},
					{VulnID: "CVE-3", Name: "pkg-c", Version: "3.0", Ecosystem: "npm"},
				},
			},
			previous: &SBOMScanResult{
				Findings: []ScanFinding{
					{VulnID: "CVE-1", Name: "pkg-a", Version: "1.0", Ecosystem: "npm"},
				},
			},
			wantNew:      2,
			wantResolved: 0,
		},
		{
			name: "findings resolved",
			current: &SBOMScanResult{
				Findings: []ScanFinding{
					{VulnID: "CVE-1", Name: "pkg-a", Version: "1.0", Ecosystem: "npm"},
				},
			},
			previous: &SBOMScanResult{
				Findings: []ScanFinding{
					{VulnID: "CVE-1", Name: "pkg-a", Version: "1.0", Ecosystem: "npm"},
					{VulnID: "CVE-2", Name: "pkg-b", Version: "2.0", Ecosystem: "npm"},
					{VulnID: "CVE-3", Name: "pkg-c", Version: "3.0", Ecosystem: "npm"},
				},
			},
			wantNew:      0,
			wantResolved: 2,
		},
		{
			name: "mixed - new and resolved",
			current: &SBOMScanResult{
				Findings: []ScanFinding{
					{VulnID: "CVE-1", Name: "pkg-a", Version: "1.0", Ecosystem: "npm"},
					{VulnID: "CVE-4", Name: "pkg-d", Version: "4.0", Ecosystem: "npm"},
				},
			},
			previous: &SBOMScanResult{
				Findings: []ScanFinding{
					{VulnID: "CVE-1", Name: "pkg-a", Version: "1.0", Ecosystem: "npm"},
					{VulnID: "CVE-2", Name: "pkg-b", Version: "2.0", Ecosystem: "npm"},
				},
			},
			wantNew:      1,
			wantResolved: 1,
		},
		{
			name: "no changes",
			current: &SBOMScanResult{
				Findings: []ScanFinding{
					{VulnID: "CVE-1", Name: "pkg-a", Version: "1.0", Ecosystem: "npm"},
				},
			},
			previous: &SBOMScanResult{
				Findings: []ScanFinding{
					{VulnID: "CVE-1", Name: "pkg-a", Version: "1.0", Ecosystem: "npm"},
				},
			},
			wantNew:      0,
			wantResolved: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			diff := ComputeDiff(tt.current, tt.previous)
			if len(diff.NewFindings) != tt.wantNew {
				t.Errorf("NewFindings = %d, want %d", len(diff.NewFindings), tt.wantNew)
			}
			if len(diff.ResolvedFindings) != tt.wantResolved {
				t.Errorf("ResolvedFindings = %d, want %d", len(diff.ResolvedFindings), tt.wantResolved)
			}
		})
	}
}
