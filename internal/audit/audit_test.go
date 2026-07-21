package audit

import (
	"context"
	"testing"

	"github.com/kato83/mayu/internal/model"
	"github.com/kato83/mayu/internal/sbom"
	"github.com/kato83/mayu/internal/store"
)

// mockVulnStore is a test mock for VulnStore.
type mockVulnStore struct {
	data map[string][]*model.Vulnerability
}

func (m *mockVulnStore) SearchByPackages(_ context.Context, packages []store.PackageQuery) (map[string][]*model.Vulnerability, error) {
	result := make(map[string][]*model.Vulnerability)
	for _, pkg := range packages {
		key := pkg.Ecosystem + "/" + pkg.Name
		if vulns, ok := m.data[key]; ok {
			result[key] = vulns
		}
	}
	return result, nil
}

func TestAudit_BasicMatch(t *testing.T) {
	store := &mockVulnStore{
		data: map[string][]*model.Vulnerability{
			"npm/express": {
				{
					ID:      "CVE-2024-1234",
					Summary: "XSS in express",
					Aliases: []string{"GHSA-xxxx"},
					Affected: []model.Affected{
						{
							Package: model.Package{Ecosystem: "npm", Name: "express"},
							Ranges: []model.Range{
								{
									Type: model.RangeTypeSemVer,
									Events: []model.Event{
										{Introduced: "4.0.0"},
										{Fixed: "4.18.3"},
									},
								},
							},
						},
					},
					SeverityLevel: 4, // HIGH
				},
			},
		},
	}

	auditor := NewAuditor(store)
	components := []sbom.Component{
		{Purl: "pkg:npm/express@4.18.2", Name: "express", Version: "4.18.2", Ecosystem: "npm"},
	}

	result, err := auditor.Audit(context.Background(), components, AuditOptions{})
	if err != nil {
		t.Fatalf("Audit() error: %v", err)
	}

	if len(result.Findings) != 1 {
		t.Fatalf("len(Findings) = %d, want 1", len(result.Findings))
	}

	f := result.Findings[0]
	if f.VulnID != "CVE-2024-1234" {
		t.Errorf("VulnID = %q, want %q", f.VulnID, "CVE-2024-1234")
	}
	if f.Severity != "HIGH" {
		t.Errorf("Severity = %q, want %q", f.Severity, "HIGH")
	}
	if f.Component.Name != "express" {
		t.Errorf("Component.Name = %q, want %q", f.Component.Name, "express")
	}
	if result.TotalPackages != 1 {
		t.Errorf("TotalPackages = %d, want 1", result.TotalPackages)
	}
	if result.VulnerablePackages != 1 {
		t.Errorf("VulnerablePackages = %d, want 1", result.VulnerablePackages)
	}
}

func TestAudit_VersionNotAffected(t *testing.T) {
	store := &mockVulnStore{
		data: map[string][]*model.Vulnerability{
			"npm/express": {
				{
					ID:      "CVE-2024-1234",
					Summary: "XSS in express",
					Affected: []model.Affected{
						{
							Package: model.Package{Ecosystem: "npm", Name: "express"},
							Ranges: []model.Range{
								{
									Type: model.RangeTypeSemVer,
									Events: []model.Event{
										{Introduced: "4.0.0"},
										{Fixed: "4.18.0"},
									},
								},
							},
						},
					},
					SeverityLevel: 4,
				},
			},
		},
	}

	auditor := NewAuditor(store)
	components := []sbom.Component{
		// Version 4.18.2 is >= fixed (4.18.0), so NOT affected
		{Purl: "pkg:npm/express@4.18.2", Name: "express", Version: "4.18.2", Ecosystem: "npm"},
	}

	result, err := auditor.Audit(context.Background(), components, AuditOptions{})
	if err != nil {
		t.Fatalf("Audit() error: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Errorf("len(Findings) = %d, want 0 (version not affected)", len(result.Findings))
	}
}

func TestAudit_ExcludeDevDependencies(t *testing.T) {
	store := &mockVulnStore{
		data: map[string][]*model.Vulnerability{
			"npm/vitest": {
				{
					ID:      "CVE-2024-9999",
					Summary: "Vuln in vitest",
					Affected: []model.Affected{
						{
							Package:  model.Package{Ecosystem: "npm", Name: "vitest"},
							Versions: []string{"3.2.4"},
						},
					},
					SeverityLevel: 3,
				},
			},
		},
	}

	auditor := NewAuditor(store)
	components := []sbom.Component{
		{Purl: "pkg:npm/vitest@3.2.4", Name: "vitest", Version: "3.2.4", Ecosystem: "npm", IsDev: true},
	}

	// Default: exclude dev
	result, err := auditor.Audit(context.Background(), components, AuditOptions{IncludeDev: false})
	if err != nil {
		t.Fatalf("Audit() error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("len(Findings) = %d, want 0 (dev excluded)", len(result.Findings))
	}
	if result.TotalPackages != 0 {
		t.Errorf("TotalPackages = %d, want 0 (dev excluded)", result.TotalPackages)
	}

	// Include dev
	result, err = auditor.Audit(context.Background(), components, AuditOptions{IncludeDev: true})
	if err != nil {
		t.Fatalf("Audit() error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Errorf("len(Findings) = %d, want 1 (dev included)", len(result.Findings))
	}
}

func TestAudit_NoVersionCheck(t *testing.T) {
	store := &mockVulnStore{
		data: map[string][]*model.Vulnerability{
			"npm/express": {
				{
					ID:      "CVE-2024-1234",
					Summary: "Old vuln",
					Affected: []model.Affected{
						{
							Package: model.Package{Ecosystem: "npm", Name: "express"},
							Ranges: []model.Range{
								{
									Type: model.RangeTypeSemVer,
									Events: []model.Event{
										{Introduced: "1.0.0"},
										{Fixed: "2.0.0"},
									},
								},
							},
						},
					},
					SeverityLevel: 2,
				},
			},
		},
	}

	auditor := NewAuditor(store)
	components := []sbom.Component{
		// Version 5.0.0 is well beyond the fixed range
		{Purl: "pkg:npm/express@5.0.0", Name: "express", Version: "5.0.0", Ecosystem: "npm"},
	}

	// With version check: not affected
	result, err := auditor.Audit(context.Background(), components, AuditOptions{NoVersionCheck: false})
	if err != nil {
		t.Fatalf("Audit() error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("With version check: len(Findings) = %d, want 0", len(result.Findings))
	}

	// Without version check: matches
	result, err = auditor.Audit(context.Background(), components, AuditOptions{NoVersionCheck: true})
	if err != nil {
		t.Fatalf("Audit() error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Errorf("Without version check: len(Findings) = %d, want 1", len(result.Findings))
	}
}

func TestAudit_NoVulnerabilities(t *testing.T) {
	store := &mockVulnStore{
		data: map[string][]*model.Vulnerability{}, // empty
	}

	auditor := NewAuditor(store)
	components := []sbom.Component{
		{Purl: "pkg:npm/safe-pkg@1.0.0", Name: "safe-pkg", Version: "1.0.0", Ecosystem: "npm"},
	}

	result, err := auditor.Audit(context.Background(), components, AuditOptions{})
	if err != nil {
		t.Fatalf("Audit() error: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Errorf("len(Findings) = %d, want 0", len(result.Findings))
	}
	if result.TotalPackages != 1 {
		t.Errorf("TotalPackages = %d, want 1", result.TotalPackages)
	}
	if result.VulnerablePackages != 0 {
		t.Errorf("VulnerablePackages = %d, want 0", result.VulnerablePackages)
	}
}

func TestAudit_EmptyComponents(t *testing.T) {
	store := &mockVulnStore{
		data: map[string][]*model.Vulnerability{},
	}

	auditor := NewAuditor(store)
	result, err := auditor.Audit(context.Background(), nil, AuditOptions{})
	if err != nil {
		t.Fatalf("Audit() error: %v", err)
	}

	if result.TotalPackages != 0 {
		t.Errorf("TotalPackages = %d, want 0", result.TotalPackages)
	}
}

func TestAudit_MultipleVulnsForSamePackage(t *testing.T) {
	store := &mockVulnStore{
		data: map[string][]*model.Vulnerability{
			"Go/golang.org/x/crypto": {
				{
					ID:      "CVE-2024-1111",
					Summary: "First vuln",
					Affected: []model.Affected{
						{
							Package:  model.Package{Ecosystem: "Go", Name: "golang.org/x/crypto"},
							Versions: []string{"0.17.0"},
						},
					},
					SeverityLevel: 4,
				},
				{
					ID:      "CVE-2024-2222",
					Summary: "Second vuln",
					Affected: []model.Affected{
						{
							Package: model.Package{Ecosystem: "Go", Name: "golang.org/x/crypto"},
							Ranges: []model.Range{
								{
									Type: model.RangeTypeSemVer,
									Events: []model.Event{
										{Introduced: "0"},
										{Fixed: "0.18.0"},
									},
								},
							},
						},
					},
					SeverityLevel: 5,
				},
			},
		},
	}

	auditor := NewAuditor(store)
	components := []sbom.Component{
		{Purl: "pkg:golang/golang.org/x/crypto@0.17.0", Name: "golang.org/x/crypto", Version: "0.17.0", Ecosystem: "Go"},
	}

	result, err := auditor.Audit(context.Background(), components, AuditOptions{})
	if err != nil {
		t.Fatalf("Audit() error: %v", err)
	}

	if len(result.Findings) != 2 {
		t.Fatalf("len(Findings) = %d, want 2", len(result.Findings))
	}
	if result.VulnerablePackages != 1 {
		t.Errorf("VulnerablePackages = %d, want 1", result.VulnerablePackages)
	}
}
