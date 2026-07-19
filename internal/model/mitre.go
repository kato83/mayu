// Package model defines Go structs for the CVE JSON 5.x schema
// (the MITRE/CVE Program's official CVE Record Format).
// See https://www.cve.org/AllResources/CveServices for the full specification.
//
// Design principle: reversibility.
//   - CVSS fields (cvssV3_1, cvssV4_0, cvssV2_0) are stored as json.RawMessage
//     because the structure varies across CVSS versions.
//   - The "other" metric field, supportingMedia, source, and version changes
//     are also stored as json.RawMessage for schema flexibility.
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

// MITRETime is a custom time type that handles MITRE CVE timestamps.
// MITRE timestamps use RFC3339 format, often with millisecond precision
// (e.g., "2024-02-14T17:32:34.809Z").
type MITRETime struct {
	time.Time
}

// mitreTimeFormats lists the time formats used by MITRE CVE records, tried in order.
var mitreTimeFormats = []string{
	"2006-01-02T15:04:05.999Z07:00",
	time.RFC3339,
	"2006-01-02T15:04:05Z07:00",
	"2006-01-02T15:04:05.999",
	"2006-01-02T15:04:05",
}

// UnmarshalJSON implements json.Unmarshaler for MITRETime.
func (t *MITRETime) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	if s == "" || s == "null" {
		return nil
	}
	for _, format := range mitreTimeFormats {
		parsed, err := time.Parse(format, s)
		if err == nil {
			t.Time = parsed.UTC()
			return nil
		}
	}
	return fmt.Errorf("cannot parse MITRE time %q", s)
}

// MarshalJSON implements json.Marshaler for MITRETime.
// Outputs in RFC3339 format with millisecond precision.
func (t MITRETime) MarshalJSON() ([]byte, error) {
	if t.Time.IsZero() {
		return []byte(`null`), nil
	}
	return []byte(fmt.Sprintf(`"%s"`, t.Time.UTC().Format("2006-01-02T15:04:05.000Z"))), nil
}

// MITRECVERecord represents a top-level CVE JSON 5.x record.
//
// RawJSON holds the original unmodified source JSON for the entire record.
// It is NOT part of the CVE schema itself but is used for persistence
// (raw_json JSONB column in DB). It is populated by ParseMITREEntry and
// excluded from JSON serialization of the struct.
type MITRECVERecord struct {
	DataType    string          `json:"dataType"`
	DataVersion string          `json:"dataVersion"`
	CVEMetadata MITREMetadata   `json:"cveMetadata"`
	Containers  MITREContainers `json:"containers"`

	// RawJSON stores the original source JSON for reversibility.
	// It is excluded from JSON marshaling to avoid circular encoding.
	// Populated during ingestion; used when writing to the database.
	RawJSON json.RawMessage `json:"-"`
}

// MITREMetadata represents the cveMetadata section of a CVE record.
type MITREMetadata struct {
	CVEID             string    `json:"cveId"`
	AssignerOrgID     string    `json:"assignerOrgId,omitempty"`
	State             string    `json:"state"`
	AssignerShortName string    `json:"assignerShortName,omitempty"`
	DateReserved      MITRETime `json:"dateReserved,omitempty"`
	DatePublished     MITRETime `json:"datePublished,omitempty"`
	DateUpdated       MITRETime `json:"dateUpdated,omitempty"`
	DateRejected      MITRETime `json:"dateRejected,omitempty"`
}

// MITREContainers holds the CNA and ADP containers of a CVE record.
type MITREContainers struct {
	CNA *MITRECNAContainer  `json:"cna,omitempty"`
	ADP []MITREADPContainer `json:"adp,omitempty"`
}

// MITRECNAContainer represents the CNA (CVE Numbering Authority) container.
type MITRECNAContainer struct {
	Title            string                `json:"title,omitempty"`
	DatePublic       MITRETime             `json:"datePublic,omitempty"`
	Affected         []MITREAffected       `json:"affected,omitempty"`
	Descriptions     []MITREDescription    `json:"descriptions,omitempty"`
	Metrics          []MITREMetric         `json:"metrics,omitempty"`
	ProblemTypes     []MITREProblemType    `json:"problemTypes,omitempty"`
	References       []MITREReference      `json:"references,omitempty"`
	Credits          []MITRECredit         `json:"credits,omitempty"`
	Solutions        []MITRETextBlock      `json:"solutions,omitempty"`
	Workarounds      []MITRETextBlock      `json:"workarounds,omitempty"`
	Exploits         []MITRETextBlock      `json:"exploits,omitempty"`
	Configurations   []MITRETextBlock      `json:"configurations,omitempty"`
	Timeline         []MITRETimeline       `json:"timeline,omitempty"`
	Source           json.RawMessage       `json:"source,omitempty"`
	ProviderMetadata MITREProviderMetadata `json:"providerMetadata,omitempty"`
}

// MITREADPContainer represents an ADP (Authorized Data Publisher) container.
type MITREADPContainer struct {
	Title            string                `json:"title,omitempty"`
	ProviderMetadata MITREProviderMetadata `json:"providerMetadata,omitempty"`
	Affected         []MITREAffected       `json:"affected,omitempty"`
	Descriptions     []MITREDescription    `json:"descriptions,omitempty"`
	Metrics          []MITREMetric         `json:"metrics,omitempty"`
	ProblemTypes     []MITREProblemType    `json:"problemTypes,omitempty"`
	References       []MITREReference      `json:"references,omitempty"`
	Credits          []MITRECredit         `json:"credits,omitempty"`
	Solutions        []MITRETextBlock      `json:"solutions,omitempty"`
	Workarounds      []MITRETextBlock      `json:"workarounds,omitempty"`
	Exploits         []MITRETextBlock      `json:"exploits,omitempty"`
	Configurations   []MITRETextBlock      `json:"configurations,omitempty"`
	Timeline         []MITRETimeline       `json:"timeline,omitempty"`
	Source           json.RawMessage       `json:"source,omitempty"`
}

// MITREAffected represents an affected product/package entry.
type MITREAffected struct {
	Vendor        string         `json:"vendor,omitempty"`
	Product       string         `json:"product,omitempty"`
	DefaultStatus string         `json:"defaultStatus,omitempty"`
	Versions      []MITREVersion `json:"versions,omitempty"`
	Platforms     []string       `json:"platforms,omitempty"`
	Modules       []string       `json:"modules,omitempty"`
	CollectionURL string         `json:"collectionURL,omitempty"`
	PackageName   string         `json:"packageName,omitempty"`
	PackageURL    string         `json:"packageUrl,omitempty"`
	Repo          string         `json:"repo,omitempty"`
	Cpes          []string       `json:"cpes,omitempty"`
	ProgramFiles  []string       `json:"programFiles,omitempty"`
}

// MITREVersion represents a version entry within an affected product.
type MITREVersion struct {
	Version     string          `json:"version"`
	VersionType string          `json:"versionType,omitempty"`
	Status      string          `json:"status"`
	LessThan    string          `json:"lessThan,omitempty"`
	LessOrEqual string          `json:"lessOrEqual,omitempty"`
	Changes     json.RawMessage `json:"changes,omitempty"`
}

// MITREDescription represents a localized description with optional supporting media.
type MITREDescription struct {
	Lang            string          `json:"lang"`
	Value           string          `json:"value"`
	SupportingMedia json.RawMessage `json:"supportingMedia,omitempty"`
}

// MITREMetric represents a metric entry (CVSS or other scoring).
type MITREMetric struct {
	Format    string          `json:"format,omitempty"`
	Scenarios []MITREScenario `json:"scenarios,omitempty"`
	CvssV2_0  json.RawMessage `json:"cvssV2_0,omitempty"`
	CvssV3_0  json.RawMessage `json:"cvssV3_0,omitempty"`
	CvssV3_1  json.RawMessage `json:"cvssV3_1,omitempty"`
	CvssV4_0  json.RawMessage `json:"cvssV4_0,omitempty"`
	Other     json.RawMessage `json:"other,omitempty"`
}

// MITREScenario represents a metric scenario context.
type MITREScenario struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// MITREProblemType represents a problem type classification (e.g., CWE).
type MITREProblemType struct {
	Descriptions []MITREProblemTypeDescription `json:"descriptions,omitempty"`
}

// MITREProblemTypeDescription represents a single problem type description.
type MITREProblemTypeDescription struct {
	Lang        string `json:"lang"`
	Type        string `json:"type,omitempty"`
	CWEID       string `json:"cweId,omitempty"`
	Description string `json:"description"`
}

// MITREReference represents a reference URL with optional name and tags.
type MITREReference struct {
	URL  string   `json:"url"`
	Name string   `json:"name,omitempty"`
	Tags []string `json:"tags,omitempty"`
}

// MITRECredit represents a credit entry for vulnerability discovery or coordination.
type MITRECredit struct {
	Lang  string `json:"lang"`
	Type  string `json:"type,omitempty"`
	Value string `json:"value"`
}

// MITRETextBlock represents a localized text block with optional supporting media.
// Used for solutions, workarounds, exploits, and configurations.
type MITRETextBlock struct {
	Lang            string          `json:"lang"`
	Value           string          `json:"value"`
	SupportingMedia json.RawMessage `json:"supportingMedia,omitempty"`
}

// MITRETimeline represents a timeline entry.
type MITRETimeline struct {
	Lang  string    `json:"lang"`
	Time  MITRETime `json:"time"`
	Value string    `json:"value"`
}

// MITREProviderMetadata represents the metadata about the data provider.
type MITREProviderMetadata struct {
	OrgID       string    `json:"orgId"`
	ShortName   string    `json:"shortName,omitempty"`
	DateUpdated MITRETime `json:"dateUpdated,omitempty"`
}

// ParseMITREEntry parses a single MITRE CVE JSON 5.x record into a MITRECVERecord struct,
// preserving the original JSON in the RawJSON field for reversibility.
func ParseMITREEntry(data []byte) (*MITRECVERecord, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}

	var record MITRECVERecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, err
	}

	// Validate required fields
	if record.CVEMetadata.CVEID == "" {
		return nil, errors.New("MITRE CVE record missing required field: cveMetadata.cveId")
	}

	// Store a compact copy of the original JSON for DB persistence.
	// Using compactJSON ensures consistent formatting regardless of source indentation.
	compact, err := compactJSON(data)
	if err != nil {
		// If compact fails, store as-is (still valid JSON, just not compacted)
		record.RawJSON = make(json.RawMessage, len(data))
		copy(record.RawJSON, data)
	} else {
		record.RawJSON = compact
	}
	return &record, nil
}
