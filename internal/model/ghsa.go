// Package model defines Go structs for GitHub Security Advisories
// fetched via the GitHub Repository Security Advisories REST API.
// See https://docs.github.com/en/rest/security-advisories/repository-advisories
//
// Design principle: reversibility.
//   - The RawJSON field preserves the original GitHub API response for storage in
//     PostgreSQL (raw_json JSONB column), ensuring no data loss.
//   - This pattern is shared with NVD, MITRE, KEV, and EPSS models.
package model

import (
	"encoding/json"
	"time"
)

// GHSAEntry represents a GitHub Security Advisory stored in ghsa_entries.
type GHSAEntry struct {
	ID              int64
	GHSAID          string
	VulnerabilityID string
	CVEID           string
	Summary         string
	Description     string
	Severity        string // critical, high, medium, low
	State           string // published, withdrawn
	HTMLURL         string
	CVSSV3Vector    string
	CVSSV3Score     *float64
	CVSSV4Vector    string
	CVSSV4Score     *float64
	PublishedAt     *time.Time
	UpdatedAt       *time.Time
	WithdrawnAt     *time.Time
	RawJSON         json.RawMessage

	// Child records
	Vulnerabilities []GHSAVulnerability
	Credits         []GHSACredit
	CWEs            []GHSACWE
}

// GHSAVulnerability represents an affected package in a GHSA advisory.
type GHSAVulnerability struct {
	ID                     int64
	GHSAEntryID            int64
	Ecosystem              string
	PackageName            string
	VulnerableVersionRange string
	PatchedVersions        string
	VulnerableFunctions    []string
}

// GHSACredit represents a credit entry for a GHSA advisory.
type GHSACredit struct {
	ID          int64
	GHSAEntryID int64
	Login       string
	CreditType  string
}

// GHSACWE represents a CWE association for a GHSA advisory.
type GHSACWE struct {
	ID          int64
	GHSAEntryID int64
	CWEID       string
	Name        string
}

// GHSASeverityLevel converts a GHSA severity label string to the normalized
// 5-level scale used in vulnerability_summary.
func GHSASeverityLevel(severity string) int {
	switch severity {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	default:
		return 0
	}
}
