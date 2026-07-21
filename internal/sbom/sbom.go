// Package sbom provides parsers for Software Bill of Materials (SBOM) formats.
// It supports CycloneDX 1.7 (JSON) and SPDX 2.3 (JSON) formats with automatic
// format detection based on document content.
package sbom

import (
	"encoding/json"
	"fmt"

	"github.com/kato83/mayu/internal/purl"
)

// Format constants for SBOM document types.
const (
	FormatCycloneDX = "CycloneDX"
	FormatSPDX      = "SPDX"
)

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
// the format (CycloneDX or SPDX) based on the JSON structure.
// Components without a valid purl are skipped.
func Parse(data []byte) (*SBOM, error) {
	format, err := detectFormat(data)
	if err != nil {
		return nil, err
	}

	switch format {
	case FormatCycloneDX:
		return parseCycloneDX(data)
	case FormatSPDX:
		return parseSPDX(data)
	default:
		return nil, fmt.Errorf("unsupported SBOM format: %s", format)
	}
}

// detectFormat inspects the JSON structure to determine the SBOM format.
func detectFormat(data []byte) (string, error) {
	var probe struct {
		BomFormat   string `json:"bomFormat"`
		SpdxVersion string `json:"spdxVersion"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return "", fmt.Errorf("failed to parse SBOM JSON: %w", err)
	}

	if probe.BomFormat == "CycloneDX" {
		return FormatCycloneDX, nil
	}
	if probe.SpdxVersion != "" {
		return FormatSPDX, nil
	}

	return "", fmt.Errorf("unrecognized SBOM format: missing bomFormat or spdxVersion field")
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
