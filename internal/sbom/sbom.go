// Package sbom provides parsers for Software Bill of Materials (SBOM) formats.
// It supports CycloneDX (JSON, XML, YAML) and SPDX 2.3 (JSON, XML, YAML)
// formats with automatic format detection based on document content.
package sbom

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/kato83/mayu/internal/purl"
	"gopkg.in/yaml.v3"
)

// Format constants for SBOM document types.
const (
	FormatCycloneDX = "CycloneDX"
	FormatSPDX      = "SPDX"
)

// Encoding constants for SBOM document encodings.
const (
	encodingJSON = "json"
	encodingXML  = "xml"
	encodingYAML = "yaml"
)

// detectedFormat holds both the SBOM format and its encoding.
type detectedFormat struct {
	format   string
	encoding string
}

// Component represents a single package extracted from an SBOM document.
type Component struct {
	// Purl is the Package URL (e.g., "pkg:npm/%40angular/core@22.0.7").
	Purl string

	// Name is the resolved package name (e.g., "@angular/core").
	Name string

	// Version is the package version string (e.g., "22.0.7").
	Version string

	// Ecosystem is the OSV ecosystem name (e.g., "npm", "Go", "PyPI").
	Ecosystem string

	// IsDev indicates whether this is a development-only dependency.
	// For CycloneDX: determined by scope="excluded" or cdx:npm:package:development property.
	// For SPDX: always false (format does not distinguish dev dependencies).
	IsDev bool
}

// SBOM represents a parsed SBOM document with its extracted components.
type SBOM struct {
	// Format is the detected SBOM format (FormatCycloneDX or FormatSPDX).
	Format string

	// Components is the list of packages extracted from the SBOM.
	Components []Component
}

// Parse reads SBOM data and returns the parsed result. It automatically detects
// the format (CycloneDX or SPDX) and encoding (JSON, XML, or YAML) based on
// document content. Components without a valid purl are skipped.
func Parse(data []byte) (*SBOM, error) {
	detected, err := detectFormat(data)
	if err != nil {
		return nil, err
	}

	switch {
	case detected.format == FormatCycloneDX && detected.encoding == encodingJSON:
		return parseCycloneDX(data)
	case detected.format == FormatCycloneDX && detected.encoding == encodingXML:
		return parseCycloneDXXML(data)
	case detected.format == FormatCycloneDX && detected.encoding == encodingYAML:
		return parseCycloneDXYAML(data)
	case detected.format == FormatSPDX && detected.encoding == encodingJSON:
		return parseSPDX(data)
	case detected.format == FormatSPDX && detected.encoding == encodingXML:
		return parseSPDXXML(data)
	case detected.format == FormatSPDX && detected.encoding == encodingYAML:
		return parseSPDXYAML(data)
	default:
		return nil, fmt.Errorf("unsupported SBOM format: %s (%s)", detected.format, detected.encoding)
	}
}

// detectFormat inspects the data to determine the SBOM format and encoding.
// Detection strategy:
//  1. If the content starts with '<' (after trimming whitespace), treat as XML
//     and use an XML decoder to read the first start element for identification.
//  2. Try JSON unmarshaling into a probe struct.
//  3. Try YAML unmarshaling into a probe struct.
//
// JSON must be tried before YAML because YAML is a strict superset of JSON:
// yaml.Unmarshal will successfully parse any valid JSON document. If the order
// were reversed, all JSON documents would be misclassified as YAML.
func detectFormat(data []byte) (*detectedFormat, error) {
	trimmed := bytes.TrimSpace(data)

	// Check for XML
	if len(trimmed) > 0 && trimmed[0] == '<' {
		return detectXMLFormat(trimmed)
	}

	// Try JSON first (must precede YAML; see function comment above).
	var jsonProbe struct {
		BomFormat   string `json:"bomFormat"`
		SpdxVersion string `json:"spdxVersion"`
	}
	if err := json.Unmarshal(data, &jsonProbe); err == nil {
		if jsonProbe.BomFormat == "CycloneDX" {
			return &detectedFormat{format: FormatCycloneDX, encoding: encodingJSON}, nil
		}
		if jsonProbe.SpdxVersion != "" {
			return &detectedFormat{format: FormatSPDX, encoding: encodingJSON}, nil
		}
	}

	// Try YAML (any valid JSON also passes yaml.Unmarshal, so this must come last).
	var yamlProbe struct {
		BomFormat   string `yaml:"bomFormat"`
		SpdxVersion string `yaml:"spdxVersion"`
	}
	if err := yaml.Unmarshal(data, &yamlProbe); err == nil {
		if yamlProbe.BomFormat == "CycloneDX" {
			return &detectedFormat{format: FormatCycloneDX, encoding: encodingYAML}, nil
		}
		if yamlProbe.SpdxVersion != "" {
			return &detectedFormat{format: FormatSPDX, encoding: encodingYAML}, nil
		}
	}

	return nil, fmt.Errorf("unrecognized SBOM format: unable to detect format from content")
}

// detectXMLFormat determines the SBOM format from XML content by using an XML
// decoder to read the first start element and inspect its name and namespace.
// This avoids false positives from substring matching (e.g., a comment or CDATA
// section that happens to contain "cyclonedx.org" or "<bom").
func detectXMLFormat(data []byte) (*detectedFormat, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		// Inspect the first start element's local name and namespace.
		localName := strings.ToLower(se.Name.Local)
		ns := strings.ToLower(se.Name.Space)

		// CycloneDX: root element is <bom> with namespace containing "cyclonedx.org"
		if localName == "bom" || strings.Contains(ns, "cyclonedx.org") {
			return &detectedFormat{format: FormatCycloneDX, encoding: encodingXML}, nil
		}

		// SPDX: root element is <Document> (or variants) with namespace containing "spdx.org"
		if localName == "document" || localName == "spdxdocument" || strings.Contains(ns, "spdx.org") {
			return &detectedFormat{format: FormatSPDX, encoding: encodingXML}, nil
		}

		// Only inspect the first start element; if it does not match, fail.
		break
	}
	return nil, fmt.Errorf("unrecognized XML SBOM format")
}

// resolveComponent resolves a purl string into a Component with ecosystem and package name.
// Returns nil if the purl cannot be parsed (component should be skipped).
func resolveComponent(purlStr string, isDev bool) *Component {
	parsed, err := purl.Parse(purlStr)
	if err != nil {
		return nil
	}

	return &Component{
		Purl:      purlStr,
		Name:      parsed.Package,
		Version:   parsed.Version,
		Ecosystem: parsed.Ecosystem,
		IsDev:     isDev,
	}
}
