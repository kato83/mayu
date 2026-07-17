// Package model defines Go structs for the OSV (Open Source Vulnerability) schema v1.8.0.
// See https://ossf.github.io/osv-schema/ for the full specification.
//
// Design principle: reversibility.
//   - database_specific, ecosystem_specific fields are stored as json.RawMessage
//     so that no information is lost during unmarshal/marshal roundtrips.
//   - The RawJSON field preserves the original source JSON byte-for-byte for
//     storage in PostgreSQL (raw_json JSONB column), ensuring that even fields
//     not yet modeled in Go structs can be recovered.
package model

import (
	"encoding/json"
	"time"
)

// Vulnerability represents a single OSV vulnerability entry.
// All fields follow the OSV Schema v1.8.0 specification.
//
// RawJSON holds the original unmodified source JSON. It is NOT part of the
// OSV schema itself but is used for persistence (raw_json JSONB column in DB).
// It is populated by the parser during ingestion and excluded from JSON
// serialization of the struct.
type Vulnerability struct {
	SchemaVersion    string          `json:"schema_version,omitempty"`
	ID               string          `json:"id"`
	Modified         time.Time       `json:"modified"`
	Published        *time.Time      `json:"published,omitempty"`
	Withdrawn        *time.Time      `json:"withdrawn,omitempty"`
	Aliases          []string        `json:"aliases,omitempty"`
	Related          []string        `json:"related,omitempty"`
	Upstream         []string        `json:"upstream,omitempty"`
	Summary          string          `json:"summary,omitempty"`
	Details          string          `json:"details,omitempty"`
	Severity         []Severity      `json:"severity,omitempty"`
	Affected         []Affected      `json:"affected,omitempty"`
	References       []Reference     `json:"references,omitempty"`
	Credits          []Credit        `json:"credits,omitempty"`
	DatabaseSpecific json.RawMessage `json:"database_specific,omitempty"`

	// RawJSON stores the original source JSON for reversibility.
	// It is excluded from JSON marshaling to avoid circular encoding.
	// Populated during ingestion; used when writing to the database.
	RawJSON json.RawMessage `json:"-"`
}

// Severity represents a severity score entry.
type Severity struct {
	Type   SeverityType `json:"type"`
	Score  string       `json:"score"`
	Source string       `json:"source,omitempty"`
}

// SeverityType represents the type of severity scoring system.
type SeverityType string

const (
	SeverityTypeCVSSV2 SeverityType = "CVSS_V2"
	SeverityTypeCVSSV3 SeverityType = "CVSS_V3"
	SeverityTypeCVSSV4 SeverityType = "CVSS_V4"
	SeverityTypeUbuntu SeverityType = "Ubuntu"
)

// Affected describes a single affected package and its version ranges.
type Affected struct {
	Package           Package         `json:"package,omitempty"`
	Severity          []Severity      `json:"severity,omitempty"`
	Ranges            []Range         `json:"ranges,omitempty"`
	Versions          []string        `json:"versions,omitempty"`
	EcosystemSpecific json.RawMessage `json:"ecosystem_specific,omitempty"`
	DatabaseSpecific  json.RawMessage `json:"database_specific,omitempty"`
}

// Package identifies the affected package.
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Purl      string `json:"purl,omitempty"`
}

// Range describes the version range in which the vulnerability is present.
type Range struct {
	Type             RangeType       `json:"type"`
	Repo             string          `json:"repo,omitempty"`
	Events           []Event         `json:"events"`
	DatabaseSpecific json.RawMessage `json:"database_specific,omitempty"`
}

// RangeType represents the type of version range.
type RangeType string

const (
	RangeTypeGit       RangeType = "GIT"
	RangeTypeSemVer    RangeType = "SEMVER"
	RangeTypeEcosystem RangeType = "ECOSYSTEM"
)

// Event represents a version event in a range (introduced, fixed, last_affected, or limit).
// Only one field should be set per event.
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// Reference is a URL with a type classification.
type Reference struct {
	Type ReferenceType `json:"type"`
	URL  string        `json:"url"`
}

// ReferenceType represents the type of reference.
type ReferenceType string

const (
	ReferenceTypeAdvisory   ReferenceType = "ADVISORY"
	ReferenceTypeArticle    ReferenceType = "ARTICLE"
	ReferenceTypeDetection  ReferenceType = "DETECTION"
	ReferenceTypeDiscussion ReferenceType = "DISCUSSION"
	ReferenceTypeReport     ReferenceType = "REPORT"
	ReferenceTypeFix        ReferenceType = "FIX"
	ReferenceTypeIntroduced ReferenceType = "INTRODUCED"
	ReferenceTypeGit        ReferenceType = "GIT"
	ReferenceTypePackage    ReferenceType = "PACKAGE"
	ReferenceTypeEvidence   ReferenceType = "EVIDENCE"
	ReferenceTypeWeb        ReferenceType = "WEB"
)

// Credit describes a person or entity credited for the vulnerability discovery or fix.
type Credit struct {
	Name    string     `json:"name"`
	Contact []string   `json:"contact,omitempty"`
	Type    CreditType `json:"type,omitempty"`
}

// CreditType represents the type of credit.
type CreditType string

const (
	CreditTypeFinder               CreditType = "FINDER"
	CreditTypeReporter             CreditType = "REPORTER"
	CreditTypeAnalyst              CreditType = "ANALYST"
	CreditTypeCoordinator          CreditType = "COORDINATOR"
	CreditTypeRemediationDeveloper CreditType = "REMEDIATION_DEVELOPER"
	CreditTypeRemediationReviewer  CreditType = "REMEDIATION_REVIEWER"
	CreditTypeRemediationVerifier  CreditType = "REMEDIATION_VERIFIER"
	CreditTypeTool                 CreditType = "TOOL"
	CreditTypeSponsor              CreditType = "SPONSOR"
	CreditTypeOther                CreditType = "OTHER"
)

// ParseVulnerability parses raw OSV JSON bytes into a Vulnerability struct,
// preserving the original JSON in the RawJSON field for reversibility.
func ParseVulnerability(data []byte) (*Vulnerability, error) {
	var vuln Vulnerability
	if err := json.Unmarshal(data, &vuln); err != nil {
		return nil, err
	}
	// Store a compact copy of the original JSON for DB persistence.
	// Using json.Compact ensures consistent formatting regardless of source indentation.
	compact, err := compactJSON(data)
	if err != nil {
		// If compact fails, store as-is (still valid JSON, just not compacted)
		vuln.RawJSON = make(json.RawMessage, len(data))
		copy(vuln.RawJSON, data)
	} else {
		vuln.RawJSON = compact
	}
	return &vuln, nil
}

// compactJSON returns a compact representation of JSON data.
func compactJSON(data []byte) (json.RawMessage, error) {
	var buf json.RawMessage
	if err := json.Unmarshal(data, &buf); err != nil {
		return nil, err
	}
	// json.Marshal on RawMessage produces compact output
	compact, err := json.Marshal(buf)
	if err != nil {
		return nil, err
	}
	return compact, nil
}
