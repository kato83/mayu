// Package sbommon provides SBOM continuous monitoring functionality.
// It manages SBOM projects, versions, scan results, and diff detection
// for tracking vulnerability changes over time.
package sbommon

import (
	"encoding/json"
	"time"
)

// SBOMProject represents a user's SBOM monitoring project.
type SBOMProject struct {
	ID        int64
	UserID    int64
	TeamID    *int64
	Name      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// SBOMVersion represents a specific SBOM version within a project.
type SBOMVersion struct {
	ID             int64
	ProjectID      int64
	Version        string
	Environment    string
	SBOMFormat     string
	RawSBOM        json.RawMessage
	ComponentCount int
	CreatedAt      time.Time
}

// SBOMScanResult represents the result of scanning an SBOM version for vulnerabilities.
type SBOMScanResult struct {
	ID                 int64
	VersionID          int64
	ScannedAt          time.Time
	TotalPackages      int
	VulnerablePackages int
	TotalFindings      int
	NewFindings        int
	ResolvedFindings   int
	Findings           []ScanFinding
	Status             string // "completed" or "failed"
	Trigger            string // "manual", "ingest", or "api"
}

// ScanFinding represents a single vulnerability finding within a scan result.
type ScanFinding struct {
	// Purl is the Package URL of the affected component.
	Purl string `json:"purl"`

	// Name is the package name.
	Name string `json:"name"`

	// Version is the package version.
	Version string `json:"version"`

	// Ecosystem is the package ecosystem.
	Ecosystem string `json:"ecosystem"`

	// VulnID is the vulnerability identifier (e.g., "CVE-2024-45337").
	VulnID string `json:"vuln_id"`

	// Aliases are alternative identifiers for the vulnerability.
	Aliases []string `json:"aliases,omitempty"`

	// Severity is the human-readable severity level (e.g., "CRITICAL", "HIGH").
	Severity string `json:"severity"`

	// SeverityLevel is the normalized numeric severity.
	SeverityLevel int `json:"severity_level"`

	// Summary is a short description of the vulnerability.
	Summary string `json:"summary"`

	// FixedVersion is the minimum version that fixes this vulnerability (empty if unknown).
	FixedVersion string `json:"fixed_version,omitempty"`
}

// ScanDiff represents the difference between two scan results.
type ScanDiff struct {
	// NewFindings are vulnerabilities present in the current scan but not the previous.
	NewFindings []ScanFinding `json:"new_findings"`

	// ResolvedFindings are vulnerabilities present in the previous scan but not the current.
	ResolvedFindings []ScanFinding `json:"resolved_findings"`
}

// Finding status constants define the allowed values for FindingStatus.Status.
const (
	FindingStatusOpen          = "open"
	FindingStatusInTriage      = "in_triage"
	FindingStatusSuppressed    = "suppressed"
	FindingStatusFalsePositive = "false_positive"
	FindingStatusRiskAccepted  = "risk_accepted"
	FindingStatusResolved      = "resolved"
)

// FindingStatus represents the triage status of a specific vulnerability finding
// within an SBOM version.
type FindingStatus struct {
	ID            int64
	VersionID     int64
	VulnID        string
	Purl          string
	Status        string
	Justification string
	UpdatedBy     int64
	UpdatedAt     time.Time
	ExpiresAt     *time.Time
}

// FindingStatusLog represents an audit log entry for a finding status change.
type FindingStatusLog struct {
	ID              int64
	FindingStatusID int64
	OldStatus       string
	NewStatus       string
	Justification   string
	ChangedBy       int64
	ChangedAt       time.Time
}

// ValidFindingStatuses is the set of allowed status values.
var ValidFindingStatuses = map[string]bool{
	FindingStatusOpen:          true,
	FindingStatusInTriage:      true,
	FindingStatusSuppressed:    true,
	FindingStatusFalsePositive: true,
	FindingStatusRiskAccepted:  true,
	FindingStatusResolved:      true,
}

// IsExcludedFromCounts returns true if this status should exclude
// the finding from vulnerability counts in reports.
func (fs *FindingStatus) IsExcludedFromCounts() bool {
	return fs.Status == FindingStatusSuppressed ||
		fs.Status == FindingStatusFalsePositive ||
		fs.Status == FindingStatusResolved
}

// IsExpired returns true if the status has an expiry date that has passed.
func (fs *FindingStatus) IsExpired() bool {
	if fs.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*fs.ExpiresAt)
}
