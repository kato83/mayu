package audit

import (
	"context"
	"fmt"
	"strings"

	"github.com/kato83/mayu/internal/model"
	"github.com/kato83/mayu/internal/sbom"
	"github.com/kato83/mayu/internal/store"
)

// VulnStore is the interface for querying vulnerabilities needed by the auditor.
// This is a subset of the full store.Store interface focused on audit use cases.
type VulnStore interface {
	// SearchByPackages queries vulnerabilities for multiple packages in a single batch.
	// Returns a map keyed by "ecosystem/name" with the matching vulnerabilities.
	SearchByPackages(ctx context.Context, packages []store.PackageQuery) (map[string][]*model.Vulnerability, error)
}

// Finding represents a single vulnerability match for an SBOM component.
type Finding struct {
	// Component is the SBOM component that matched.
	Component sbom.Component

	// VulnID is the vulnerability identifier (e.g., "CVE-2024-45337").
	VulnID string

	// Aliases are alternative identifiers for the vulnerability.
	Aliases []string

	// Severity is the human-readable severity level (e.g., "CRITICAL", "HIGH").
	Severity string

	// SeverityLevel is the normalized numeric severity (5=CRITICAL, 4=HIGH, 3=MEDIUM, 2=LOW, 1=NONE).
	SeverityLevel int

	// Summary is a short description of the vulnerability.
	Summary string
}

// AuditOptions controls the behavior of the audit process.
type AuditOptions struct {
	// IncludeDev includes development dependencies in the audit.
	// Default: false (dev deps are excluded).
	IncludeDev bool

	// NoVersionCheck skips version matching and reports all vulnerabilities
	// for matching package names regardless of version.
	NoVersionCheck bool
}

// AuditResult holds the complete result of an SBOM audit.
type AuditResult struct {
	// Findings is the list of vulnerability matches.
	Findings []Finding

	// TotalPackages is the number of packages analyzed.
	TotalPackages int

	// VulnerablePackages is the number of packages with at least one finding.
	VulnerablePackages int
}

// Auditor performs SBOM risk analysis against the vulnerability database.
type Auditor struct {
	store VulnStore
}

// NewAuditor creates a new Auditor with the given vulnerability store.
func NewAuditor(store VulnStore) *Auditor {
	return &Auditor{store: store}
}

// Audit analyzes the given SBOM components against the vulnerability database
// and returns findings for affected packages.
func (a *Auditor) Audit(ctx context.Context, components []sbom.Component, opts AuditOptions) (*AuditResult, error) {
	// Filter components based on options
	var filtered []sbom.Component
	for _, c := range components {
		if !opts.IncludeDev && c.IsDev {
			continue
		}
		filtered = append(filtered, c)
	}

	if len(filtered) == 0 {
		return &AuditResult{}, nil
	}

	// Build unique package queries (deduplicate by ecosystem+name)
	queryMap := make(map[string]store.PackageQuery)
	for _, c := range filtered {
		key := packageKey(c.Ecosystem, c.Name)
		if _, exists := queryMap[key]; !exists {
			queryMap[key] = store.PackageQuery{
				Ecosystem: c.Ecosystem,
				Name:      c.Name,
			}
		}
	}

	queries := make([]store.PackageQuery, 0, len(queryMap))
	for _, q := range queryMap {
		queries = append(queries, q)
	}

	// Fetch vulnerabilities from database
	vulnMap, err := a.store.SearchByPackages(ctx, queries)
	if err != nil {
		return nil, fmt.Errorf("search vulnerabilities: %w", err)
	}

	// Match each component against its vulnerabilities
	var findings []Finding
	vulnerableSet := make(map[string]bool)

	for _, comp := range filtered {
		key := packageKey(comp.Ecosystem, comp.Name)
		vulns, ok := vulnMap[key]
		if !ok || len(vulns) == 0 {
			continue
		}

		for _, vuln := range vulns {
			if matchesComponent(comp, vuln, opts.NoVersionCheck) {
				finding := Finding{
					Component:     comp,
					VulnID:        vuln.ID,
					Aliases:       vuln.Aliases,
					Severity:      severityLabel(vuln.SeverityLevel),
					SeverityLevel: vuln.SeverityLevel,
					Summary:       vuln.Summary,
				}
				findings = append(findings, finding)
				vulnerableSet[key+"/"+comp.Version] = true
			}
		}
	}

	return &AuditResult{
		Findings:           findings,
		TotalPackages:      len(filtered),
		VulnerablePackages: len(vulnerableSet),
	}, nil
}

// matchesComponent checks if a vulnerability affects the given component.
func matchesComponent(comp sbom.Component, vuln *model.Vulnerability, noVersionCheck bool) bool {
	if noVersionCheck {
		return true
	}

	// If no version specified in SBOM, we can't do version matching — match all
	if comp.Version == "" {
		return true
	}

	// Check each affected entry for matching ecosystem+package
	for _, affected := range vuln.Affected {
		if !matchesPackage(comp, affected) {
			continue
		}
		if IsAffected(comp.Version, affected) {
			return true
		}
	}

	return false
}

// matchesPackage checks if the component matches the affected package identity.
func matchesPackage(comp sbom.Component, affected model.Affected) bool {
	// Match by ecosystem + name (case-sensitive for ecosystem, case-sensitive for name)
	if affected.Package.Ecosystem == comp.Ecosystem && affected.Package.Name == comp.Name {
		return true
	}
	return false
}

// packageKey creates a map key from ecosystem and package name.
func packageKey(ecosystem, name string) string {
	return ecosystem + "/" + name
}

// severityLabel converts a numeric severity level to a human-readable label.
func severityLabel(level int) string {
	switch level {
	case 5:
		return "CRITICAL"
	case 4:
		return "HIGH"
	case 3:
		return "MEDIUM"
	case 2:
		return "LOW"
	case 1:
		return "NONE"
	default:
		return "UNKNOWN"
	}
}

// SeverityFromLabel converts a human-readable severity label to the numeric level.
func SeverityFromLabel(label string) int {
	switch strings.ToUpper(label) {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "NONE":
		return 1
	default:
		return 0
	}
}
