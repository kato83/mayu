package vex

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/kato83/mayu/internal/audit"
	"github.com/kato83/mayu/internal/sbom"
	"github.com/kato83/mayu/internal/sbommon"
)

func testdataPath(name string) string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "..", "testdata", "vex", name)
}

func TestImport(t *testing.T) {
	data, err := os.ReadFile(testdataPath("sample.openvex.json"))
	if err != nil {
		t.Fatalf("read test file: %v", err)
	}

	result, err := Import(data)
	if err != nil {
		t.Fatalf("Import() error = %v", err)
	}

	if result.TotalStatements != 4 {
		t.Errorf("TotalStatements = %d, want 4", result.TotalStatements)
	}

	// 4 statements: 1 product + 1 product + 2 products + 1 product = 5 statuses
	if result.ImportedStatements != 5 {
		t.Errorf("ImportedStatements = %d, want 5", result.ImportedStatements)
	}

	if len(result.Statuses) != 5 {
		t.Fatalf("len(Statuses) = %d, want 5", len(result.Statuses))
	}

	// Verify status mapping
	statusMap := make(map[string]string)
	for _, fs := range result.Statuses {
		statusMap[fs.VulnID+"|"+fs.Purl] = fs.Status
	}

	tests := []struct {
		vulnID string
		purl   string
		want   string
	}{
		{"CVE-2024-1234", "pkg:npm/%40angular/core@17.0.0", sbommon.FindingStatusFalsePositive},
		{"CVE-2024-5678", "pkg:golang/golang.org/x/crypto@0.17.0", sbommon.FindingStatusOpen},
		{"CVE-2024-9012", "pkg:npm/lodash@4.17.20", sbommon.FindingStatusResolved},
		{"CVE-2024-9012", "pkg:npm/lodash@4.17.21", sbommon.FindingStatusResolved},
		{"GHSA-xxxx-yyyy-zzzz", "pkg:pypi/requests@2.28.0", sbommon.FindingStatusInTriage},
	}

	for _, tc := range tests {
		key := tc.vulnID + "|" + tc.purl
		got, ok := statusMap[key]
		if !ok {
			t.Errorf("missing status for %s", key)
			continue
		}
		if got != tc.want {
			t.Errorf("status for %s = %q, want %q", key, got, tc.want)
		}
	}
}

func TestImport_Justification(t *testing.T) {
	data := []byte(`{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"@id": "urn:test:1",
		"author": "test",
		"timestamp": "2024-01-01T00:00:00Z",
		"statements": [
			{
				"vulnerability": {"@id": "CVE-2024-0001"},
				"products": [{"@id": "pkg:npm/foo@1.0.0"}],
				"status": "not_affected",
				"justification": "vulnerable_code_not_present",
				"impact_statement": "Function is not called"
			},
			{
				"vulnerability": {"@id": "CVE-2024-0002"},
				"products": [{"@id": "pkg:npm/bar@2.0.0"}],
				"status": "not_affected",
				"justification": "inline_mitigations_already_exist"
			},
			{
				"vulnerability": {"@id": "CVE-2024-0003"},
				"products": [{"@id": "pkg:npm/baz@3.0.0"}],
				"status": "not_affected"
			}
		]
	}`)

	result, err := Import(data)
	if err != nil {
		t.Fatalf("Import() error = %v", err)
	}

	justifications := make(map[string]string)
	for _, fs := range result.Statuses {
		justifications[fs.VulnID] = fs.Justification
	}

	if got := justifications["CVE-2024-0001"]; got != "vulnerable_code_not_present: Function is not called" {
		t.Errorf("CVE-2024-0001 justification = %q", got)
	}
	if got := justifications["CVE-2024-0002"]; got != "inline_mitigations_already_exist" {
		t.Errorf("CVE-2024-0002 justification = %q", got)
	}
	if got := justifications["CVE-2024-0003"]; got != "imported from VEX document" {
		t.Errorf("CVE-2024-0003 justification = %q", got)
	}
}

func TestImport_InvalidJSON(t *testing.T) {
	_, err := Import([]byte(`{invalid json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestImport_MissingContext(t *testing.T) {
	data := []byte(`{
		"@id": "urn:test:1",
		"author": "test",
		"timestamp": "2024-01-01T00:00:00Z",
		"statements": []
	}`)
	_, err := Import(data)
	if err == nil {
		t.Fatal("expected error for missing @context")
	}
}

func TestImport_InvalidStatus(t *testing.T) {
	data := []byte(`{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"@id": "urn:test:1",
		"author": "test",
		"timestamp": "2024-01-01T00:00:00Z",
		"statements": [
			{
				"vulnerability": {"@id": "CVE-2024-0001"},
				"products": [{"@id": "pkg:npm/foo@1.0.0"}],
				"status": "invalid_status"
			}
		]
	}`)
	_, err := Import(data)
	if err == nil {
		t.Fatal("expected error for invalid status")
	}
}

func TestImport_MissingVulnID(t *testing.T) {
	data := []byte(`{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"@id": "urn:test:1",
		"author": "test",
		"timestamp": "2024-01-01T00:00:00Z",
		"statements": [
			{
				"vulnerability": {"@id": ""},
				"products": [{"@id": "pkg:npm/foo@1.0.0"}],
				"status": "affected"
			}
		]
	}`)
	_, err := Import(data)
	if err == nil {
		t.Fatal("expected error for missing vulnerability ID")
	}
}

func TestSuppressedVulnIDs(t *testing.T) {
	data, err := os.ReadFile(testdataPath("sample.openvex.json"))
	if err != nil {
		t.Fatalf("read test file: %v", err)
	}

	suppressed, err := SuppressedVulnIDs(data)
	if err != nil {
		t.Fatalf("SuppressedVulnIDs() error = %v", err)
	}

	if !suppressed["CVE-2024-1234"] {
		t.Error("expected CVE-2024-1234 to be suppressed")
	}
	if suppressed["CVE-2024-5678"] {
		t.Error("CVE-2024-5678 should not be suppressed (status=affected)")
	}
	if suppressed["CVE-2024-9012"] {
		t.Error("CVE-2024-9012 should not be suppressed (status=fixed)")
	}
}

func TestFilterFindingsByVEX(t *testing.T) {
	vexData := []byte(`{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"@id": "urn:test:filter",
		"author": "test",
		"timestamp": "2024-01-01T00:00:00Z",
		"statements": [
			{
				"vulnerability": {"@id": "CVE-2024-1111"},
				"products": [],
				"status": "not_affected",
				"justification": "vulnerable_code_not_present"
			},
			{
				"vulnerability": {"@id": "CVE-2024-2222"},
				"products": [{"@id": "pkg:npm/foo@1.0.0"}],
				"status": "not_affected"
			}
		]
	}`)

	findings := []audit.Finding{
		{
			VulnID:    "CVE-2024-1111",
			Component: sbom.Component{Name: "bar", Purl: "pkg:npm/bar@2.0.0"},
		},
		{
			VulnID:    "CVE-2024-2222",
			Component: sbom.Component{Name: "foo", Purl: "pkg:npm/foo@1.0.0"},
		},
		{
			VulnID:    "CVE-2024-2222",
			Component: sbom.Component{Name: "foo", Purl: "pkg:npm/foo@2.0.0"},
		},
		{
			VulnID:    "CVE-2024-3333",
			Component: sbom.Component{Name: "baz", Purl: "pkg:npm/baz@1.0.0"},
		},
	}

	filtered, err := FilterFindingsByVEX(findings, vexData)
	if err != nil {
		t.Fatalf("FilterFindingsByVEX() error = %v", err)
	}

	// CVE-2024-1111 is blanket suppressed (no products)
	// CVE-2024-2222 with pkg:npm/foo@1.0.0 is product-specific suppressed
	// CVE-2024-2222 with pkg:npm/foo@2.0.0 should NOT be suppressed
	// CVE-2024-3333 is not suppressed
	if len(filtered) != 2 {
		t.Fatalf("len(filtered) = %d, want 2", len(filtered))
	}
	if filtered[0].VulnID != "CVE-2024-2222" || filtered[0].Component.Purl != "pkg:npm/foo@2.0.0" {
		t.Errorf("filtered[0] = %v, want CVE-2024-2222 with pkg:npm/foo@2.0.0", filtered[0])
	}
	if filtered[1].VulnID != "CVE-2024-3333" {
		t.Errorf("filtered[1] = %v, want CVE-2024-3333", filtered[1])
	}
}

func TestFilterFindingsByVEX_AliasSuppression(t *testing.T) {
	vexData := []byte(`{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"@id": "urn:test:alias",
		"author": "test",
		"timestamp": "2024-01-01T00:00:00Z",
		"statements": [
			{
				"vulnerability": {"@id": "GHSA-aaaa-bbbb-cccc"},
				"products": [],
				"status": "not_affected"
			}
		]
	}`)

	findings := []audit.Finding{
		{
			VulnID:    "CVE-2024-9999",
			Aliases:   []string{"GHSA-aaaa-bbbb-cccc"},
			Component: sbom.Component{Name: "pkg", Purl: "pkg:npm/pkg@1.0.0"},
		},
	}

	filtered, err := FilterFindingsByVEX(findings, vexData)
	if err != nil {
		t.Fatalf("FilterFindingsByVEX() error = %v", err)
	}

	if len(filtered) != 0 {
		t.Errorf("expected 0 findings after alias suppression, got %d", len(filtered))
	}
}

func TestImportFile(t *testing.T) {
	result, err := ImportFile(testdataPath("sample.openvex.json"))
	if err != nil {
		t.Fatalf("ImportFile() error = %v", err)
	}
	if result.TotalStatements != 4 {
		t.Errorf("TotalStatements = %d, want 4", result.TotalStatements)
	}
}

func TestImportFile_NotFound(t *testing.T) {
	_, err := ImportFile("/nonexistent/path.json")
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
}
