package sbommon

import (
	"context"
	"fmt"
	"time"

	"github.com/kato83/mayu/internal/audit"
	"github.com/kato83/mayu/internal/sbom"
)

// Scanner performs SBOM vulnerability scanning by delegating to the audit.Auditor.
type Scanner struct {
	vulnStore audit.VulnStore
}

// NewScanner creates a new Scanner with the given vulnerability store.
func NewScanner(vulnStore audit.VulnStore) *Scanner {
	return &Scanner{vulnStore: vulnStore}
}

// Scan parses raw SBOM data and runs an audit against the vulnerability database.
// It returns a scan result with all findings.
func (s *Scanner) Scan(ctx context.Context, sbomData []byte) (*SBOMScanResult, error) {
	parsed, err := sbom.Parse(sbomData)
	if err != nil {
		return nil, fmt.Errorf("parse sbom: %w", err)
	}

	auditor := audit.NewAuditor(s.vulnStore)
	result, err := auditor.Audit(ctx, parsed.Components, audit.AuditOptions{
		IncludeDev: false,
	})
	if err != nil {
		return nil, fmt.Errorf("audit sbom: %w", err)
	}

	findings := make([]ScanFinding, 0, len(result.Findings))
	for _, f := range result.Findings {
		findings = append(findings, ScanFinding{
			Purl:          f.Component.Purl,
			Name:          f.Component.Name,
			Version:       f.Component.Version,
			Ecosystem:     f.Component.Ecosystem,
			VulnID:        f.VulnID,
			Aliases:       f.Aliases,
			Severity:      f.Severity,
			SeverityLevel: f.SeverityLevel,
			Summary:       f.Summary,
		})
	}

	return &SBOMScanResult{
		ScannedAt:          time.Now().UTC(),
		TotalPackages:      result.TotalPackages,
		VulnerablePackages: result.VulnerablePackages,
		TotalFindings:      len(findings),
		Findings:           findings,
		Status:             "completed",
	}, nil
}

// ScanVersion loads the raw SBOM from a version and runs a scan.
func (s *Scanner) ScanVersion(ctx context.Context, version *SBOMVersion) (*SBOMScanResult, error) {
	if version == nil {
		return nil, fmt.Errorf("version is nil")
	}
	if len(version.RawSBOM) == 0 {
		return nil, fmt.Errorf("version %d has no raw SBOM data", version.ID)
	}

	result, err := s.Scan(ctx, version.RawSBOM)
	if err != nil {
		return nil, err
	}
	result.VersionID = version.ID
	return result, nil
}

// ComputeDiff compares two scan results and identifies new and resolved findings.
// If previous is nil, all current findings are considered new.
func ComputeDiff(current, previous *SBOMScanResult) *ScanDiff {
	if current == nil {
		return &ScanDiff{}
	}

	if previous == nil {
		// No previous scan - all findings are new
		newFindings := make([]ScanFinding, len(current.Findings))
		copy(newFindings, current.Findings)
		return &ScanDiff{
			NewFindings:      newFindings,
			ResolvedFindings: nil,
		}
	}

	// Build sets keyed by component+vuln for comparison
	currentSet := make(map[string]ScanFinding, len(current.Findings))
	for _, f := range current.Findings {
		key := findingKey(f)
		currentSet[key] = f
	}

	previousSet := make(map[string]ScanFinding, len(previous.Findings))
	for _, f := range previous.Findings {
		key := findingKey(f)
		previousSet[key] = f
	}

	// New findings: in current but not in previous
	var newFindings []ScanFinding
	for key, f := range currentSet {
		if _, exists := previousSet[key]; !exists {
			newFindings = append(newFindings, f)
		}
	}

	// Resolved findings: in previous but not in current
	var resolvedFindings []ScanFinding
	for key, f := range previousSet {
		if _, exists := currentSet[key]; !exists {
			resolvedFindings = append(resolvedFindings, f)
		}
	}

	return &ScanDiff{
		NewFindings:      newFindings,
		ResolvedFindings: resolvedFindings,
	}
}

// findingKey creates a unique key for a finding based on package identity and vulnerability.
func findingKey(f ScanFinding) string {
	return f.Ecosystem + "/" + f.Name + "@" + f.Version + ":" + f.VulnID
}
