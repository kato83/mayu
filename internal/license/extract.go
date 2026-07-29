package license

import (
	"encoding/json"
	"fmt"
)

// cycloneDXBOM is a minimal CycloneDX structure for license extraction.
type cycloneDXBOM struct {
	Components []cycloneDXComponent `json:"components"`
}

type cycloneDXComponent struct {
	Name     string             `json:"name"`
	Version  string             `json:"version"`
	Purl     string             `json:"purl"`
	Licenses []cycloneDXLicense `json:"licenses"`
}

// cycloneDXLicense represents a license entry in CycloneDX.
// CycloneDX supports two forms:
//   - { "license": { "id": "MIT" } }           (SPDX expression)
//   - { "license": { "name": "Custom Lic" } }  (free-text name)
//   - { "expression": "MIT OR Apache-2.0" }    (SPDX expression string)
type cycloneDXLicense struct {
	License    *cycloneDXLicenseDetail `json:"license,omitempty"`
	Expression string                  `json:"expression,omitempty"`
}

type cycloneDXLicenseDetail struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
}

// spdxDocument is a minimal SPDX 2.3 structure for license extraction.
type spdxDocument struct {
	Packages []spdxPackage `json:"packages"`
}

type spdxPackage struct {
	Name             string            `json:"name"`
	VersionInfo      string            `json:"versionInfo"`
	LicenseConcluded string            `json:"licenseConcluded"`
	LicenseDeclared  string            `json:"licenseDeclared"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

// ExtractFromCycloneDX extracts license info from CycloneDX SBOM raw JSON.
// Each component may have multiple licenses; each produces a separate ComponentLicense entry.
// Components without any license information produce a single entry with an empty License.SPDXID.
func ExtractFromCycloneDX(raw []byte) ([]ComponentLicense, error) {
	var bom cycloneDXBOM
	if err := json.Unmarshal(raw, &bom); err != nil {
		return nil, fmt.Errorf("parse CycloneDX: %w", err)
	}

	var results []ComponentLicense

	for _, comp := range bom.Components {
		if comp.Purl == "" && comp.Name == "" {
			continue
		}

		licenses := extractCycloneDXLicenses(comp)
		if len(licenses) == 0 {
			// No license detected
			results = append(results, ComponentLicense{
				Purl:    comp.Purl,
				Name:    comp.Name,
				Version: comp.Version,
				License: Info{Category: Unknown},
			})
			continue
		}

		for _, lic := range licenses {
			results = append(results, ComponentLicense{
				Purl:    comp.Purl,
				Name:    comp.Name,
				Version: comp.Version,
				License: lic,
			})
		}
	}

	return results, nil
}

// extractCycloneDXLicenses extracts license Info from a CycloneDX component.
func extractCycloneDXLicenses(comp cycloneDXComponent) []Info {
	var licenses []Info

	for _, lic := range comp.Licenses {
		if lic.Expression != "" {
			// SPDX expression — normalize as a single identifier
			normalized := Normalize(lic.Expression)
			licenses = append(licenses, LookupSPDX(normalized))
		} else if lic.License != nil {
			if lic.License.ID != "" {
				// Standard SPDX ID
				normalized := Normalize(lic.License.ID)
				licenses = append(licenses, LookupSPDX(normalized))
			} else if lic.License.Name != "" {
				// Free-text license name
				normalized := Normalize(lic.License.Name)
				licenses = append(licenses, LookupSPDX(normalized))
			}
		}
	}

	return licenses
}

// ExtractFromSPDX extracts license info from SPDX SBOM raw JSON.
// Uses licenseConcluded preferentially; falls back to licenseDeclared.
func ExtractFromSPDX(raw []byte) ([]ComponentLicense, error) {
	var doc spdxDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse SPDX: %w", err)
	}

	var results []ComponentLicense

	for _, pkg := range doc.Packages {
		purlStr := extractSPDXPurl(pkg)

		// Prefer licenseConcluded, fall back to licenseDeclared
		licenseStr := pkg.LicenseConcluded
		if licenseStr == "" || licenseStr == "NOASSERTION" {
			licenseStr = pkg.LicenseDeclared
		}

		if licenseStr == "" || licenseStr == "NOASSERTION" || licenseStr == "NONE" {
			results = append(results, ComponentLicense{
				Purl:    purlStr,
				Name:    pkg.Name,
				Version: pkg.VersionInfo,
				License: Info{Category: Unknown},
			})
			continue
		}

		// Normalize the license string
		normalized := Normalize(licenseStr)
		info := LookupSPDX(normalized)

		results = append(results, ComponentLicense{
			Purl:    purlStr,
			Name:    pkg.Name,
			Version: pkg.VersionInfo,
			License: info,
		})
	}

	return results, nil
}

// extractSPDXPurl finds the purl from an SPDX package's external references.
func extractSPDXPurl(pkg spdxPackage) string {
	for _, ref := range pkg.ExternalRefs {
		if ref.ReferenceType == "purl" {
			return ref.ReferenceLocator
		}
	}
	return ""
}
