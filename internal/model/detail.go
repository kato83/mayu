// Package model defines the VulnerabilityDetail struct for enriched vulnerability display.
// It aggregates information from OSV, NVD, MITRE, EPSS, KEV, and LEV sources
// into a single response object.
package model

import (
	"encoding/json"
	"time"
)

// OSVEntryDetail represents a single OSV entry associated with a vulnerability.
// A vulnerability may have multiple OSV entries (e.g., GHSA-xxx, BIT-xxx for the same CVE).
type OSVEntryDetail struct {
	// OsvID is the OSV identifier (e.g., "GHSA-6f9g-cxwr-q5jr", "BIT-jenkins-2024-23897").
	OsvID string `json:"osv_id"`

	// Severity contains severity/CVSS information specific to this OSV entry.
	Severity []Severity `json:"severity,omitempty"`

	// Summary is the one-line summary from this OSV entry.
	Summary string `json:"summary,omitempty"`

	// Details is the detailed description from this OSV entry.
	Details string `json:"details,omitempty"`

	// Affected contains affected packages specific to this OSV entry.
	Affected []Affected `json:"affected,omitempty"`

	// References contains reference links specific to this OSV entry.
	References []Reference `json:"references,omitempty"`

	// Credits contains credits specific to this OSV entry.
	Credits []Credit `json:"credits,omitempty"`

	// RawJSON is the original OSV JSON for this entry.
	RawJSON json.RawMessage `json:"raw_json,omitempty"`

	// Translations contains translations for this OSV entry's text fields
	// when a non-English locale is requested via the Accept-Language header.
	Translations []OSVEntryTranslation `json:"translations,omitempty"`
}

// VulnerabilityDetail is an enriched view of a vulnerability that combines
// data from OSV, NVD, MITRE, EPSS, KEV, and LEV sources.
// Used by CLI --detail and API /{id} endpoints.
type VulnerabilityDetail struct {
	// Base fields (from vulnerabilities table + OSV)
	ID        string     `json:"id"`
	Modified  *time.Time `json:"modified,omitempty"`
	Published *time.Time `json:"published,omitempty"`
	Withdrawn *time.Time `json:"withdrawn,omitempty"`
	Aliases   []string   `json:"aliases,omitempty"`
	Related   []string   `json:"related,omitempty"`
	Summary   string     `json:"summary,omitempty"`
	Details   string     `json:"details,omitempty"`

	// OSV severity (from osv_severity / raw_json)
	Severity []Severity `json:"severity,omitempty"`

	// OsvRawJSON is the original OSV JSON for raw display
	OsvRawJSON json.RawMessage `json:"osv_raw_json,omitempty"`

	// OsvEntries contains all OSV entries associated with this vulnerability.
	// A vulnerability may have multiple OSV entries (e.g., GHSA and BIT entries for the same CVE).
	OsvEntries []OSVEntryDetail `json:"osv_entries,omitempty"`

	// Normalized severity from vulnerability_summary (5-level scale label)
	SeverityWorst string `json:"severity_worst,omitempty"`
	SeverityBest  string `json:"severity_best,omitempty"`

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

	// EPSS enrichment (latest score from FIRST EPSS)
	EPSS *EPSSDetail `json:"epss,omitempty"`

	// KEV enrichment (CISA Known Exploited Vulnerabilities catalog)
	KEV *KEVDetail `json:"kev,omitempty"`

	// LEV (Likely Exploited Vulnerabilities) computed score
	// Based on NIST CSWP 41: probability of past exploitation
	LEV *LEVDetail `json:"lev,omitempty"`

	// EOL enrichment: lifecycle status of affected products
	EOL []EOLEnrichment `json:"eol,omitempty"`

	// ExploitDB enrichment: public exploits from the Exploit Database
	ExploitDB []ExploitDBDetail `json:"exploitdb,omitempty"`

	// Translations contains translations for text fields when a non-English
	// locale is requested via the Accept-Language header.
	Translations []VulnerabilityTranslation `json:"translations,omitempty"`
}

// EPSSDetail contains EPSS enrichment data for a vulnerability.
type EPSSDetail struct {
	// EPSS is the probability of exploitation in the next 30 days [0.0, 1.0].
	EPSS float64 `json:"epss"`

	// Percentile is the relative ranking among all scored CVEs [0.0, 1.0].
	Percentile float64 `json:"percentile"`

	// ScoreDate is the date the score was calculated.
	ScoreDate string `json:"score_date"`
}

// KEVDetail contains CISA KEV enrichment data for a vulnerability.
type KEVDetail struct {
	// VendorProject is the vendor or project name (e.g., "Microsoft").
	VendorProject string `json:"vendor_project"`

	// Product is the affected product name (e.g., "Windows").
	Product string `json:"product"`

	// VulnerabilityName is the descriptive vulnerability name.
	VulnerabilityName string `json:"vulnerability_name"`

	// DateAdded is when the CVE was added to the KEV catalog.
	DateAdded string `json:"date_added"`

	// DueDate is the remediation due date set by CISA.
	DueDate string `json:"due_date"`

	// RequiredAction describes the required remediation action.
	RequiredAction string `json:"required_action"`

	// KnownRansomwareCampaignUse indicates if used in ransomware ("Known", "Unknown").
	KnownRansomwareCampaignUse string `json:"known_ransomware_campaign_use"`

	// Translations contains translations for text fields when a non-English
	// locale is requested via the Accept-Language header.
	Translations []KEVTranslation `json:"translations,omitempty"`
}

// LEVDetail contains LEV (Likely Exploited Vulnerabilities) enrichment data.
// Based on NIST CSWP 41: https://doi.org/10.6028/NIST.CSWP.41
type LEVDetail struct {
	// LEV is the probability that this vulnerability has been exploited
	// in the wild at some point in the past [0.0, 1.0].
	LEV float64 `json:"lev"`

	// InKEV indicates whether the CVE is confirmed exploited (in CISA KEV).
	// If true, LEV is 1.0.
	InKEV bool `json:"in_kev"`

	// EPSSScoreCount is the number of historical EPSS scores used in computation.
	EPSSScoreCount int `json:"epss_score_count"`

	// FirstEPSSDate is the earliest EPSS score date used.
	FirstEPSSDate string `json:"first_epss_date,omitempty"`

	// LastEPSSDate is the most recent EPSS score date used.
	LastEPSSDate string `json:"last_epss_date,omitempty"`

	// ComputedAt is when this LEV score was computed.
	ComputedAt string `json:"computed_at"`
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

	// Configurations contains CPE match criteria (affected software)
	Configurations []NVDConfigurationDetail `json:"configurations,omitempty"`

	// SSVC contains CISA SSVC assessment data from NVD (if available)
	SSVC *SSVCDetail `json:"ssvc,omitempty"`

	// RawJSON is the original NVD JSON for raw display
	RawJSON json.RawMessage `json:"raw_json,omitempty"`

	// DescriptionTranslations contains translations of the NVD description
	// when a non-English locale is requested via the Accept-Language header.
	DescriptionTranslations []NVDDescriptionTranslation `json:"description_translations,omitempty"`
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

// NVDConfigurationDetail represents a CPE configuration node from NVD.
type NVDConfigurationDetail struct {
	Operator string              `json:"operator,omitempty"`
	Negate   bool                `json:"negate,omitempty"`
	Matches  []NVDCPEMatchDetail `json:"matches,omitempty"`
}

// NVDCPEMatchDetail represents a single CPE match criteria.
type NVDCPEMatchDetail struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"version_start_including,omitempty"`
	VersionStartExcluding string `json:"version_start_excluding,omitempty"`
	VersionEndIncluding   string `json:"version_end_including,omitempty"`
	VersionEndExcluding   string `json:"version_end_excluding,omitempty"`
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

	// RawJSON is the original MITRE CVE Record JSON for raw display
	RawJSON json.RawMessage `json:"raw_json,omitempty"`
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
	CWEID        string                        `json:"cwe_id,omitempty"`
	Description  string                        `json:"description"`
	Lang         string                        `json:"lang,omitempty"`
	Translations []MITREProblemTypeTranslation `json:"translations,omitempty"`
}

// MITRECreditDetail represents a credit entry from MITRE.
type MITRECreditDetail struct {
	Type         string                   `json:"type,omitempty"`
	Value        string                   `json:"value"`
	Lang         string                   `json:"lang,omitempty"`
	Translations []MITRECreditTranslation `json:"translations,omitempty"`
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

	// Decision is the computed CISA Coordinator decision tree outcome
	// (Track, Track*, Attend, Act). Computed from Options using worst-case
	// Mission & Well-Being assumption.
	Decision string `json:"decision,omitempty"`
}

// SSVCOption represents a single SSVC decision point (e.g., Exploitation: none).
type SSVCOption struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// EOLEnrichment contains lifecycle status for an affected product/package.
type EOLEnrichment struct {
	// ProductName is the endoflife.date product identifier (e.g., "nodejs", "angular")
	ProductName string `json:"product_name"`

	// ProductLabel is the human-readable product name (e.g., "Node.js", "Angular")
	ProductLabel string `json:"product_label"`

	// Category is the product category (e.g., "framework", "lang", "os")
	Category string `json:"category,omitempty"`

	// MatchedIdentifier is the purl/cpe that matched this product to the vulnerability
	MatchedIdentifier string `json:"matched_identifier"`

	// MatchedPackage is the package name from the vulnerability's affected list
	MatchedPackage string `json:"matched_package,omitempty"`

	// LatestRelease is the most recent release cycle information
	LatestRelease *EOLReleaseStatus `json:"latest_release,omitempty"`

	// AllReleases lists all release cycles with their EOL status
	AllReleases []EOLReleaseStatus `json:"all_releases,omitempty"`
}

// EOLReleaseStatus represents the lifecycle status of a single release cycle.
type EOLReleaseStatus struct {
	// Name is the release cycle name (e.g., "22", "3.12")
	Name string `json:"name"`

	// Label is the human-readable release label (e.g., "22 (LTS)")
	Label string `json:"label,omitempty"`

	// IsEol indicates whether this release has reached end of life
	IsEol *bool `json:"is_eol,omitempty"`

	// EolFrom is the date when EOL status begins (YYYY-MM-DD)
	EolFrom string `json:"eol_from,omitempty"`

	// IsMaintained indicates whether this release is currently maintained
	IsMaintained *bool `json:"is_maintained,omitempty"`

	// IsLts indicates whether this is an LTS release
	IsLts *bool `json:"is_lts,omitempty"`

	// LatestVersion is the latest patch version in this cycle
	LatestVersion string `json:"latest_version,omitempty"`
}

// ExploitDBDetail contains Exploit-DB enrichment data for a vulnerability.
// Each entry represents a public exploit associated with the CVE.
type ExploitDBDetail struct {
	// EDBID is the Exploit-DB identifier (e.g., 39446).
	EDBID int `json:"edb_id"`

	// Description is the exploit title (e.g., "MySQL 4.x/5.0 (Linux) - User-Defined Function (UDF)").
	Description string `json:"description"`

	// ExploitType is the exploit category (dos, local, remote, webapps, shellcode).
	ExploitType string `json:"exploit_type"`

	// Platform is the target platform (linux, windows, multiple, etc.).
	Platform string `json:"platform"`

	// Author is the exploit author.
	Author string `json:"author"`

	// DatePublished is the publication date (YYYY-MM-DD).
	DatePublished string `json:"date_published,omitempty"`

	// Verified indicates whether the exploit was verified by the EDB team.
	Verified bool `json:"verified"`

	// Port is the target port (0 if not applicable).
	Port int `json:"port,omitempty"`

	// Codes contains all reference codes (CVE, OSVDB, MS IDs).
	Codes []string `json:"codes,omitempty"`

	// Tags contains exploit tags (e.g., "Metasploit Framework (MSF)").
	Tags []string `json:"tags,omitempty"`

	// SourceURL is the original advisory or reference URL.
	SourceURL string `json:"source_url,omitempty"`

	// URL is the Exploit-DB page URL (computed from EDB-ID).
	URL string `json:"url"`
}
