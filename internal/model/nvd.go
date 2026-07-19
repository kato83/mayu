// Package model defines Go structs for the NVD CVE 2.0 schema.
// See https://nvd.nist.gov/developers/vulnerabilities for the full specification.
//
// Design principle: reversibility.
//   - cvssData fields are stored as json.RawMessage because the structure
//     varies across CVSS versions (v2, v3.0, v3.1, v4.0).
//   - The RawJSON field preserves the original source JSON for storage in
//     PostgreSQL (raw_json JSONB column), ensuring no data loss.
package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// NVDTime is a custom time type that handles NVD's timestamp format.
// NVD timestamps may lack timezone info (e.g., "2023-10-10T14:15:10.883")
// and are assumed to be UTC.
type NVDTime struct {
	time.Time
}

// nvdTimeFormats lists the time formats used by NVD, tried in order.
var nvdTimeFormats = []string{
	"2006-01-02T15:04:05.000",
	"2006-01-02T15:04:05",
	time.RFC3339,
	"2006-01-02T15:04:05Z07:00",
	"2006-01-02T15:04:05.999Z07:00",
}

// UnmarshalJSON implements json.Unmarshaler for NVDTime.
func (t *NVDTime) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	if s == "" || s == "null" {
		return nil
	}
	for _, format := range nvdTimeFormats {
		parsed, err := time.Parse(format, s)
		if err == nil {
			t.Time = parsed.UTC()
			return nil
		}
	}
	return fmt.Errorf("cannot parse NVD time %q", s)
}

// MarshalJSON implements json.Marshaler for NVDTime.
// Outputs in the NVD format without timezone suffix.
func (t NVDTime) MarshalJSON() ([]byte, error) {
	if t.IsZero() {
		return []byte(`null`), nil
	}
	return []byte(fmt.Sprintf(`"%s"`, t.Time.UTC().Format("2006-01-02T15:04:05.000"))), nil
}

// NVDFeedResponse represents the top-level NVD JSON Feed 2.0 response wrapper.
type NVDFeedResponse struct {
	ResultsPerPage  int          `json:"resultsPerPage"`
	StartIndex      int          `json:"startIndex"`
	TotalResults    int          `json:"totalResults"`
	Format          string       `json:"format"`
	Version         string       `json:"version"`
	Timestamp       string       `json:"timestamp"`
	Vulnerabilities []NVDCVEItem `json:"vulnerabilities"`
}

// NVDCVEItem wraps a single CVE entry in the feed's vulnerabilities array.
// It matches the {"cve": {...}} structure.
type NVDCVEItem struct {
	CVE NVDCVE `json:"cve"`
}

// NVDCVE represents a single NVD CVE 2.0 entry with all fields.
//
// RawJSON holds the original unmodified source JSON for the "cve" object.
// It is NOT part of the NVD schema itself but is used for persistence
// (raw_json JSONB column in DB). It is populated by ParseNVDEntry and
// excluded from JSON serialization of the struct.
type NVDCVE struct {
	ID                    string             `json:"id"`
	SourceIdentifier      string             `json:"sourceIdentifier,omitempty"`
	VulnStatus            string             `json:"vulnStatus,omitempty"`
	Published             NVDTime            `json:"published"`
	LastModified          NVDTime            `json:"lastModified"`
	Descriptions          []NVDLangString    `json:"descriptions,omitempty"`
	Metrics               NVDMetrics         `json:"metrics,omitempty"`
	Weaknesses            []NVDWeakness      `json:"weaknesses,omitempty"`
	Configurations        []NVDConfiguration `json:"configurations,omitempty"`
	References            []NVDReference     `json:"references,omitempty"`
	CveTags               []NVDCveTag        `json:"cveTags,omitempty"`
	EvaluatorComment      string             `json:"evaluatorComment,omitempty"`
	EvaluatorSolution     string             `json:"evaluatorSolution,omitempty"`
	EvaluatorImpact       string             `json:"evaluatorImpact,omitempty"`
	CisaExploitAdd        string             `json:"cisaExploitAdd,omitempty"`
	CisaActionDue         string             `json:"cisaActionDue,omitempty"`
	CisaRequiredAction    string             `json:"cisaRequiredAction,omitempty"`
	CisaVulnerabilityName string             `json:"cisaVulnerabilityName,omitempty"`
	VendorComments        []NVDVendorComment `json:"vendorComments,omitempty"`
	Affected              []NVDAffected      `json:"affected,omitempty"`

	// RawJSON stores the original source JSON for reversibility.
	// It is excluded from JSON marshaling to avoid circular encoding.
	// Populated during ingestion; used when writing to the database.
	RawJSON json.RawMessage `json:"-"`
}

// NVDLangString represents a localized string with a language tag.
type NVDLangString struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// NVDReference represents a reference URL with source attribution and tags.
type NVDReference struct {
	URL    string   `json:"url"`
	Source string   `json:"source,omitempty"`
	Tags   []string `json:"tags,omitempty"`
}

// NVDMetrics contains all CVSS metric versions for a CVE.
type NVDMetrics struct {
	CvssMetricV40 []NVDCVSSMetricV40 `json:"cvssMetricV40,omitempty"`
	CvssMetricV31 []NVDCVSSMetricV31 `json:"cvssMetricV31,omitempty"`
	CvssMetricV30 []NVDCVSSMetricV30 `json:"cvssMetricV30,omitempty"`
	CvssMetricV2  []NVDCVSSMetricV2  `json:"cvssMetricV2,omitempty"`
	SSVCV203      []NVDSSVCV203      `json:"ssvcV203,omitempty"`
}

// NVDCVSSMetricV40 represents a CVSS v4.0 metric entry.
type NVDCVSSMetricV40 struct {
	Source   string          `json:"source"`
	Type     string          `json:"type"`
	CvssData json.RawMessage `json:"cvssData"`
}

// NVDCVSSMetricV31 represents a CVSS v3.1 metric entry.
type NVDCVSSMetricV31 struct {
	Source              string          `json:"source"`
	Type                string          `json:"type"`
	CvssData            json.RawMessage `json:"cvssData"`
	ExploitabilityScore *float64        `json:"exploitabilityScore,omitempty"`
	ImpactScore         *float64        `json:"impactScore,omitempty"`
}

// NVDCVSSMetricV30 represents a CVSS v3.0 metric entry (same structure as v3.1).
type NVDCVSSMetricV30 struct {
	Source              string          `json:"source"`
	Type                string          `json:"type"`
	CvssData            json.RawMessage `json:"cvssData"`
	ExploitabilityScore *float64        `json:"exploitabilityScore,omitempty"`
	ImpactScore         *float64        `json:"impactScore,omitempty"`
}

// NVDCVSSMetricV2 represents a CVSS v2.0 metric entry.
type NVDCVSSMetricV2 struct {
	Source                  string          `json:"source"`
	Type                    string          `json:"type"`
	CvssData                json.RawMessage `json:"cvssData"`
	BaseSeverity            string          `json:"baseSeverity,omitempty"`
	ExploitabilityScore     *float64        `json:"exploitabilityScore,omitempty"`
	ImpactScore             *float64        `json:"impactScore,omitempty"`
	AcInsufInfo             *bool           `json:"acInsufInfo,omitempty"`
	ObtainAllPrivilege      *bool           `json:"obtainAllPrivilege,omitempty"`
	ObtainUserPrivilege     *bool           `json:"obtainUserPrivilege,omitempty"`
	ObtainOtherPrivilege    *bool           `json:"obtainOtherPrivilege,omitempty"`
	UserInteractionRequired *bool           `json:"userInteractionRequired,omitempty"`
}

// NVDSSVCV203 represents an SSVC v2.0.3 assessment entry.
type NVDSSVCV203 struct {
	Source   string          `json:"source"`
	SsvcData json.RawMessage `json:"ssvcData"`
}

// NVDAffected represents an affected product entry (vendor-supplied).
type NVDAffected struct {
	Source       string          `json:"source"`
	AffectedData json.RawMessage `json:"affectedData"`
}

// NVDWeakness represents a CWE weakness classification.
type NVDWeakness struct {
	Source      string          `json:"source"`
	Type        string          `json:"type"`
	Description []NVDLangString `json:"description"`
}

// NVDConfiguration represents a CPE applicability configuration.
type NVDConfiguration struct {
	Operator string    `json:"operator,omitempty"`
	Negate   *bool     `json:"negate,omitempty"`
	Nodes    []NVDNode `json:"nodes"`
}

// NVDNode represents a node within a CPE configuration tree.
type NVDNode struct {
	Operator string        `json:"operator"`
	Negate   *bool         `json:"negate,omitempty"`
	CpeMatch []NVDCPEMatch `json:"cpeMatch"`
}

// NVDCPEMatch represents a single CPE match criteria.
type NVDCPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	MatchCriteriaId       string `json:"matchCriteriaId"`
	VersionStartExcluding string `json:"versionStartExcluding,omitempty"`
	VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
	VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
	VersionEndIncluding   string `json:"versionEndIncluding,omitempty"`
}

// NVDVendorComment represents a vendor-supplied comment on a CVE.
type NVDVendorComment struct {
	Organization string `json:"organization"`
	Comment      string `json:"comment"`
	LastModified string `json:"lastModified"`
}

// NVDCveTag represents CVE-level tags from a specific source.
type NVDCveTag struct {
	SourceIdentifier string   `json:"sourceIdentifier"`
	Tags             []string `json:"tags"`
}

// ParseNVDEntry parses a single NVD CVE JSON object into an NVDCVE struct,
// preserving the original JSON in the RawJSON field for reversibility.
func ParseNVDEntry(data []byte) (*NVDCVE, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}

	var cve NVDCVE
	if err := json.Unmarshal(data, &cve); err != nil {
		return nil, err
	}

	// Validate required fields
	if cve.ID == "" {
		return nil, errors.New("NVD CVE entry missing required field: id")
	}

	// Store a compact copy of the original JSON for DB persistence.
	// Using compactJSON ensures consistent formatting regardless of source indentation.
	compact, err := compactJSON(data)
	if err != nil {
		// If compact fails, store as-is (still valid JSON, just not compacted)
		cve.RawJSON = make(json.RawMessage, len(data))
		copy(cve.RawJSON, data)
	} else {
		cve.RawJSON = compact
	}
	return &cve, nil
}

// ParseNVDFeedResponse parses a full NVD feed JSON response.
// Each CVE entry in the response has its RawJSON populated from
// the original "cve" object.
func ParseNVDFeedResponse(data []byte) (*NVDFeedResponse, error) {
	// First, parse the feed structure
	var feed NVDFeedResponse
	if err := json.Unmarshal(data, &feed); err != nil {
		return nil, err
	}

	// Now extract raw JSON for each CVE entry.
	// We re-parse the vulnerabilities array to get the raw "cve" objects.
	var raw struct {
		Vulnerabilities []struct {
			CVE json.RawMessage `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	for i := range feed.Vulnerabilities {
		if i < len(raw.Vulnerabilities) {
			compact, err := compactJSON(raw.Vulnerabilities[i].CVE)
			if err != nil {
				feed.Vulnerabilities[i].CVE.RawJSON = raw.Vulnerabilities[i].CVE
			} else {
				feed.Vulnerabilities[i].CVE.RawJSON = compact
			}
		}
	}

	return &feed, nil
}
