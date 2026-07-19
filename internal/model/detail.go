// Package model defines the VulnerabilityDetail struct for enriched vulnerability display.
// It aggregates information from OSV, NVD, and MITRE sources into a single response object.
package model

import "time"

// VulnerabilityDetail is an enriched view of a vulnerability that combines
// data from OSV, NVD, and MITRE sources. Used by CLI --detail and API /{id} endpoints.
type VulnerabilityDetail struct {
	// Base fields (from vulnerabilities table + OSV)
	ID        string     `json:"id"`
	Modified  time.Time  `json:"modified"`
	Published *time.Time `json:"published,omitempty"`
	Withdrawn *time.Time `json:"withdrawn,omitempty"`
	Aliases   []string   `json:"aliases,omitempty"`
	Related   []string   `json:"related,omitempty"`
	Summary   string     `json:"summary,omitempty"`
	Details   string     `json:"details,omitempty"`

	// OSV severity (from osv_severity / raw_json)
	Severity []Severity `json:"severity,omitempty"`

	// Affected packages (from OSV)
	Affected []Affected `json:"affected,omitempty"`

	// References (from OSV)
	References []Reference `json:"references,omitempty"`

	// Credits (from OSV)
	Credits []Credit `json:"credits,omitempty"`

	// NVD enrichment
	NVD *NVDDetail `json:"nvd,omitempty"`

	// MITRE enrichment
	MITRE *MITREDetail `json:"mitre,omitempty"`
}

// NVDDetail contains NVD-specific enrichment data for a vulnerability.
type NVDDetail struct {
	// VulnStatus indicates NVD analysis status (Received, Awaiting Analysis, Analyzed, Modified, etc.)
	VulnStatus string `json:"vuln_status,omitempty"`

	// SourceIdentifier is the CNA that reported the CVE to NVD (e.g., "cve@mitre.org")
	SourceIdentifier string `json:"source_identifier,omitempty"`

	// Published is the NVD publication date
	Published *time.Time `json:"published,omitempty"`

	// LastModified is the last modification date in NVD
	LastModified *time.Time `json:"last_modified,omitempty"`

	// Description is the English description from NVD
	Description string `json:"description,omitempty"`

	// Metrics contains all CVSS scores from NVD (multiple sources/versions)
	Metrics []NVDMetricDetail `json:"metrics,omitempty"`

	// Weaknesses contains CWE classifications
	Weaknesses []NVDWeaknessDetail `json:"weaknesses,omitempty"`

	// References contains NVD-specific references with tags
	References []NVDReferenceDetail `json:"references,omitempty"`
}

// NVDMetricDetail represents a single CVSS metric entry from NVD.
type NVDMetricDetail struct {
	// Version is the CVSS version (v2, v31, v40)
	Version string `json:"version"`

	// Source identifies who provided this score (e.g., "nvd@nist.gov", "contact@wpscan.com")
	Source string `json:"source"`

	// Type is Primary or Secondary
	Type string `json:"type"`

	// BaseScore is the CVSS base score
	BaseScore float64 `json:"base_score"`

	// BaseSeverity is the textual severity (CRITICAL, HIGH, MEDIUM, LOW, NONE)
	BaseSeverity string `json:"base_severity"`

	// VectorString is the full CVSS vector string
	VectorString string `json:"vector_string,omitempty"`

	// ExploitabilityScore from NVD analysis
	ExploitabilityScore *float64 `json:"exploitability_score,omitempty"`

	// ImpactScore from NVD analysis
	ImpactScore *float64 `json:"impact_score,omitempty"`
}

// NVDWeaknessDetail represents a CWE classification from NVD.
type NVDWeaknessDetail struct {
	// Source identifies who classified this weakness
	Source string `json:"source"`

	// Type is Primary or Secondary
	Type string `json:"type"`

	// CWEID is the CWE identifier (e.g., "CWE-79")
	CWEID string `json:"cwe_id"`

	// Description is the CWE name/description
	Description string `json:"description,omitempty"`
}

// NVDReferenceDetail represents an NVD reference with tags.
type NVDReferenceDetail struct {
	URL    string   `json:"url"`
	Source string   `json:"source,omitempty"`
	Tags   []string `json:"tags,omitempty"`
}

// MITREDetail contains MITRE CVE Record enrichment data.
type MITREDetail struct {
	// State is the CVE record state (PUBLISHED, REJECTED)
	State string `json:"state,omitempty"`

	// AssignerShortName is the CNA that assigned the CVE (e.g., "WPScan")
	AssignerShortName string `json:"assigner_short_name,omitempty"`

	// DatePublished is the MITRE publication date
	DatePublished *time.Time `json:"date_published,omitempty"`

	// DateUpdated is the last update date
	DateUpdated *time.Time `json:"date_updated,omitempty"`

	// Metrics contains CVSS and SSVC scores from MITRE containers
	Metrics []MITREMetricDetail `json:"metrics,omitempty"`

	// ProblemTypes contains CWE classifications from MITRE
	ProblemTypes []MITREProblemTypeDetail `json:"problem_types,omitempty"`

	// Credits contains discovery/coordination credits
	Credits []MITRECreditDetail `json:"credits,omitempty"`

	// References contains MITRE-specific references
	References []MITREReferenceDetail `json:"references,omitempty"`

	// SSVC contains CISA SSVC assessment data (if available)
	SSVC *SSVCDetail `json:"ssvc,omitempty"`
}

// MITREMetricDetail represents a CVSS metric entry from MITRE.
type MITREMetricDetail struct {
	// Format is "CVSS" or "Other" (SSVC)
	Format string `json:"format"`

	// CvssVersion is the CVSS version (e.g., "3.1", "4.0")
	CvssVersion string `json:"cvss_version,omitempty"`

	// Source is the provider short name (container provider)
	Source string `json:"source,omitempty"`

	// BaseScore is the CVSS base score
	BaseScore float64 `json:"base_score,omitempty"`

	// BaseSeverity is the textual severity
	BaseSeverity string `json:"base_severity,omitempty"`

	// VectorString is the full CVSS vector
	VectorString string `json:"vector_string,omitempty"`
}

// MITREProblemTypeDetail represents a CWE from MITRE.
type MITREProblemTypeDetail struct {
	CWEID       string `json:"cwe_id,omitempty"`
	Description string `json:"description"`
	Lang        string `json:"lang,omitempty"`
}

// MITRECreditDetail represents a credit entry from MITRE.
type MITRECreditDetail struct {
	Type  string `json:"type,omitempty"`
	Value string `json:"value"`
	Lang  string `json:"lang,omitempty"`
}

// MITREReferenceDetail represents a MITRE reference.
type MITREReferenceDetail struct {
	URL  string   `json:"url"`
	Name string   `json:"name,omitempty"`
	Tags []string `json:"tags,omitempty"`
}

// SSVCDetail contains CISA SSVC (Stakeholder-Specific Vulnerability Categorization) data.
type SSVCDetail struct {
	// Version is the SSVC version (e.g., "2.0.3")
	Version string `json:"version,omitempty"`

	// Role is the assessor role (e.g., "CISA Coordinator")
	Role string `json:"role,omitempty"`

	// Timestamp is when the assessment was made
	Timestamp string `json:"timestamp,omitempty"`

	// Options contains the SSVC decision points
	Options []SSVCOption `json:"options,omitempty"`
}

// SSVCOption represents a single SSVC decision point (e.g., Exploitation: none).
type SSVCOption struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
