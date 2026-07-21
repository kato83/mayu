// Package model defines Go structs for the product_identifiers table.
// This unified table aggregates package/product identification from all sources
// (OSV, NVD, MITRE) into a single searchable structure.
//
// Design principles:
//   - CPE URIs are decomposed into individual fields for efficient querying.
//   - Purl strings are decomposed into type/namespace/name/version for efficient querying.
//   - version_constraint stores normalized version range info as structured data.
//   - The source field indicates which data source contributed this identifier.
package model

import "encoding/json"

// ProductIdentifier represents a single entry in the product_identifiers table.
// It unifies package/product identification across all vulnerability data sources.
type ProductIdentifier struct {
	// VulnerabilityID links to vulnerabilities(id).
	VulnerabilityID string

	// Source indicates which data source contributed this identifier.
	// Values: "osv", "nvd", "mitre"
	Source string

	// --- Purl fields (decomposed from a Package URL) ---

	// PurlType is the purl package type (e.g., "golang", "npm", "maven").
	PurlType string

	// PurlNamespace is the purl namespace (e.g., "github.com/go-git" for golang).
	PurlNamespace string

	// PurlName is the purl package name (e.g., "go-git").
	PurlName string

	// PurlVersion is the purl version (may be empty for affected-range entries).
	PurlVersion string

	// PurlQualifiers stores purl qualifiers as key=value pairs (optional).
	PurlQualifiers string

	// PurlSubpath is the purl subpath component (optional).
	PurlSubpath string

	// --- CPE fields (decomposed from a CPE 2.3 URI) ---

	// CPEPart is "a" (application), "o" (OS), or "h" (hardware).
	CPEPart string

	// CPEVendor is the CPE vendor name (e.g., "apache", "microsoft").
	CPEVendor string

	// CPEProduct is the CPE product name (e.g., "http_server", "windows").
	CPEProduct string

	// CPEVersion is the CPE version string (may be "*" for any).
	CPEVersion string

	// CPEUpdate is the CPE update field (may be "*" for any).
	CPEUpdate string

	// CPEEdition is the CPE edition field (may be "*" for any).
	CPEEdition string

	// CPELanguage is the CPE language field (may be "*" for any).
	CPELanguage string

	// CPESWEdition is the CPE sw_edition field (may be "*" for any).
	CPESWEdition string

	// CPETargetSW is the CPE target_sw field (may be "*" for any).
	CPETargetSW string

	// CPETargetHW is the CPE target_hw field (may be "*" for any).
	CPETargetHW string

	// CPEOther is the CPE other field (may be "*" for any).
	CPEOther string

	// --- Generic fields ---

	// Ecosystem is the OSV ecosystem name (e.g., "Go", "npm", "PyPI").
	// Populated from OSV data or mapped from CPE/purl.
	Ecosystem string

	// Name is the human-readable package name (e.g., "golang.org/x/crypto").
	// For OSV: the package name. For NVD/MITRE: vendor/product combined.
	Name string

	// Vendor is the vendor name (from CPE or MITRE affected).
	Vendor string

	// Product is the product name (from CPE or MITRE affected).
	Product string

	// VersionConstraint stores normalized version range information.
	// Structure varies by source but is stored as JSONB.
	VersionConstraint json.RawMessage
}

// CPEFields holds the decomposed fields of a CPE 2.3 URI.
// CPE format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
type CPEFields struct {
	Part      string `json:"part"`
	Vendor    string `json:"vendor"`
	Product   string `json:"product"`
	Version   string `json:"version"`
	Update    string `json:"update"`
	Edition   string `json:"edition"`
	Language  string `json:"language"`
	SWEdition string `json:"sw_edition"`
	TargetSW  string `json:"target_sw"`
	TargetHW  string `json:"target_hw"`
	Other     string `json:"other"`
}

// PurlFields holds the decomposed fields of a Package URL.
type PurlFields struct {
	Type       string `json:"type"`
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
	Version    string `json:"version"`
	Qualifiers string `json:"qualifiers"`
	Subpath    string `json:"subpath"`
}

// ParseCPE23 decomposes a CPE 2.3 URI string into its constituent fields.
// CPE 2.3 format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
//
// Returns nil if the input is not a valid CPE 2.3 URI (doesn't start with "cpe:2.3:").
// Fields with value "*" or "-" are preserved as-is (wildcard / not-applicable).
func ParseCPE23(cpe string) *CPEFields {
	if len(cpe) < 8 {
		return nil
	}
	// Must start with "cpe:2.3:"
	if cpe[:8] != "cpe:2.3:" {
		return nil
	}

	// Split remaining fields by ':'
	// A CPE 2.3 URI has exactly 13 colon-separated components total:
	// cpe : 2.3 : part : vendor : product : version : update : edition : language : sw_edition : target_sw : target_hw : other
	parts := splitCPEFields(cpe[8:])
	if len(parts) < 11 {
		return nil
	}

	return &CPEFields{
		Part:      parts[0],
		Vendor:    parts[1],
		Product:   parts[2],
		Version:   parts[3],
		Update:    parts[4],
		Edition:   parts[5],
		Language:  parts[6],
		SWEdition: getOrDefault(parts, 7, "*"),
		TargetSW:  getOrDefault(parts, 8, "*"),
		TargetHW:  getOrDefault(parts, 9, "*"),
		Other:     getOrDefault(parts, 10, "*"),
	}
}

// splitCPEFields splits a CPE field string by ':', handling escaped colons (\:).
func splitCPEFields(s string) []string {
	var parts []string
	var current []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			// Escaped character — include both backslash and next char
			current = append(current, s[i], s[i+1])
			i++
		} else if s[i] == ':' {
			parts = append(parts, string(current))
			current = current[:0]
		} else {
			current = append(current, s[i])
		}
	}
	parts = append(parts, string(current))
	return parts
}

// getOrDefault returns the element at index i, or the default value if out of bounds.
func getOrDefault(parts []string, i int, def string) string {
	if i < len(parts) {
		return parts[i]
	}
	return def
}

// ReconstructCPE23 reconstructs a CPE 2.3 URI string from decomposed fields.
func (c *CPEFields) ReconstructCPE23() string {
	return "cpe:2.3:" + c.Part + ":" + c.Vendor + ":" + c.Product + ":" +
		c.Version + ":" + c.Update + ":" + c.Edition + ":" + c.Language + ":" +
		c.SWEdition + ":" + c.TargetSW + ":" + c.TargetHW + ":" + c.Other
}
