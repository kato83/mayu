// Package model defines Go structs for the CISA KEV (Known Exploited Vulnerabilities) catalog.
// See https://www.cisa.gov/known-exploited-vulnerabilities-catalog for the specification.
//
// Design principle: reversibility.
//   - The RawJSON field preserves the original catalog entry for storage in
//     PostgreSQL (raw_json JSONB column), ensuring no data loss.
//   - This pattern is shared with NVD, MITRE, and EPSS models.
package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// KEVCatalog represents the top-level CISA KEV catalog JSON response.
// Endpoint: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
type KEVCatalog struct {
	Title           string     `json:"title"`
	CatalogVersion  string     `json:"catalogVersion"`
	DateReleased    string     `json:"dateReleased"`
	Count           int        `json:"count"`
	Vulnerabilities []KEVEntry `json:"vulnerabilities"`
}

// KEVEntry represents a single vulnerability entry from the CISA KEV catalog.
type KEVEntry struct {
	CVEID                      string   `json:"cveID"`
	VendorProject              string   `json:"vendorProject"`
	Product                    string   `json:"product"`
	VulnerabilityName          string   `json:"vulnerabilityName"`
	DateAdded                  string   `json:"dateAdded"`
	ShortDescription           string   `json:"shortDescription"`
	RequiredAction             string   `json:"requiredAction"`
	DueDate                    string   `json:"dueDate"`
	KnownRansomwareCampaignUse string   `json:"knownRansomwareCampaignUse"`
	Notes                      string   `json:"notes"`
	CWEs                       []string `json:"cwes"`

	// RawJSON stores the original catalog entry for reversibility.
	// It is excluded from JSON marshaling to avoid circular encoding.
	// Populated during parsing; used when writing to the database.
	RawJSON json.RawMessage `json:"-"`
}

// KEVRecord represents a parsed and validated KEV entry ready for storage.
// This is the normalized form used by the store layer.
type KEVRecord struct {
	CVEID                      string
	VendorProject              string
	Product                    string
	VulnerabilityName          string
	DateAdded                  time.Time
	ShortDescription           string
	RequiredAction             string
	DueDate                    time.Time
	KnownRansomwareCampaignUse string
	Notes                      string
	CWEs                       []string
	RawJSON                    json.RawMessage
}

// ParseKEVRecord validates and converts a KEVEntry into a KEVRecord.
// Returns an error if required fields are missing or malformed.
func (e *KEVEntry) ParseKEVRecord() (*KEVRecord, error) {
	if e.CVEID == "" {
		return nil, errors.New("KEV entry missing required field: cveID")
	}
	if !strings.HasPrefix(strings.ToUpper(e.CVEID), "CVE-") {
		return nil, fmt.Errorf("KEV entry has invalid CVE ID: %q", e.CVEID)
	}
	if e.VendorProject == "" {
		return nil, fmt.Errorf("KEV entry %s missing required field: vendorProject", e.CVEID)
	}
	if e.Product == "" {
		return nil, fmt.Errorf("KEV entry %s missing required field: product", e.CVEID)
	}
	if e.VulnerabilityName == "" {
		return nil, fmt.Errorf("KEV entry %s missing required field: vulnerabilityName", e.CVEID)
	}
	if e.DateAdded == "" {
		return nil, fmt.Errorf("KEV entry %s missing required field: dateAdded", e.CVEID)
	}
	if e.ShortDescription == "" {
		return nil, fmt.Errorf("KEV entry %s missing required field: shortDescription", e.CVEID)
	}
	if e.RequiredAction == "" {
		return nil, fmt.Errorf("KEV entry %s missing required field: requiredAction", e.CVEID)
	}
	if e.DueDate == "" {
		return nil, fmt.Errorf("KEV entry %s missing required field: dueDate", e.CVEID)
	}

	dateAdded, err := time.Parse("2006-01-02", e.DateAdded)
	if err != nil {
		return nil, fmt.Errorf("parse dateAdded for %s: %w", e.CVEID, err)
	}

	dueDate, err := time.Parse("2006-01-02", e.DueDate)
	if err != nil {
		return nil, fmt.Errorf("parse dueDate for %s: %w", e.CVEID, err)
	}

	ransomwareUse := e.KnownRansomwareCampaignUse
	if ransomwareUse == "" {
		ransomwareUse = "Unknown"
	}

	return &KEVRecord{
		CVEID:                      strings.ToUpper(e.CVEID),
		VendorProject:              e.VendorProject,
		Product:                    e.Product,
		VulnerabilityName:          e.VulnerabilityName,
		DateAdded:                  dateAdded,
		ShortDescription:           e.ShortDescription,
		RequiredAction:             e.RequiredAction,
		DueDate:                    dueDate,
		KnownRansomwareCampaignUse: ransomwareUse,
		Notes:                      e.Notes,
		CWEs:                       e.CWEs,
		RawJSON:                    e.RawJSON,
	}, nil
}

// ParseKEVCatalog parses the full CISA KEV catalog JSON response.
// Each entry in the response has its RawJSON populated from the original data item.
func ParseKEVCatalog(data []byte) (*KEVCatalog, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}

	var catalog KEVCatalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		return nil, fmt.Errorf("unmarshal KEV catalog: %w", err)
	}

	if catalog.Title == "" {
		return nil, errors.New("KEV catalog missing title field")
	}

	// Extract raw JSON for each vulnerability entry to preserve original format.
	var raw struct {
		Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("extract raw KEV entries: %w", err)
	}

	for i := range catalog.Vulnerabilities {
		if i < len(raw.Vulnerabilities) {
			compact, err := compactJSON(raw.Vulnerabilities[i])
			if err != nil {
				catalog.Vulnerabilities[i].RawJSON = raw.Vulnerabilities[i]
			} else {
				catalog.Vulnerabilities[i].RawJSON = compact
			}
		}
	}

	return &catalog, nil
}
