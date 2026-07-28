package sbom

import (
	"encoding/json"
	"encoding/xml"

	"gopkg.in/yaml.v3"
)

// spdxDocument represents the top-level SPDX 2.3 document (subset).
type spdxDocument struct {
	SpdxVersion string        `json:"spdxVersion" yaml:"spdxVersion"`
	Packages    []spdxPackage `json:"packages" yaml:"packages"`
}

// spdxPackage represents a single package in an SPDX document.
type spdxPackage struct {
	SPDXID       string            `json:"SPDXID" yaml:"SPDXID"`
	Name         string            `json:"name" yaml:"name"`
	VersionInfo  string            `json:"versionInfo" yaml:"versionInfo"`
	ExternalRefs []spdxExternalRef `json:"externalRefs" yaml:"externalRefs"`
}

// spdxExternalRef represents an external reference for an SPDX package.
type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory" yaml:"referenceCategory"`
	ReferenceType     string `json:"referenceType" yaml:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator" yaml:"referenceLocator"`
}

// spdxXMLDocument represents the top-level SPDX XML document.
type spdxXMLDocument struct {
	XMLName     xml.Name         `xml:"Document"`
	SpdxVersion string           `xml:"spdxVersion"`
	Packages    []spdxXMLPackage `xml:"packages>Package"`
}

// spdxXMLPackage represents a single package in an SPDX XML document.
type spdxXMLPackage struct {
	SPDXID       string               `xml:"SPDXID"`
	Name         string               `xml:"name"`
	VersionInfo  string               `xml:"versionInfo"`
	ExternalRefs []spdxXMLExternalRef `xml:"externalRefs>ExternalRef"`
}

// spdxXMLExternalRef represents an external reference in an SPDX XML document.
type spdxXMLExternalRef struct {
	ReferenceCategory string `xml:"referenceCategory"`
	ReferenceType     string `xml:"referenceType"`
	ReferenceLocator  string `xml:"referenceLocator"`
}

// parseSPDX parses an SPDX 2.3 JSON SBOM and returns the normalized SBOM.
// SPDX does not have a standard way to distinguish dev dependencies,
// so all packages are marked as IsDev=false.
func parseSPDX(data []byte) (*SBOM, error) {
	var doc spdxDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	return buildSPDXSBOM(doc), nil
}

// parseSPDXXML parses an SPDX XML SBOM and returns the normalized SBOM.
func parseSPDXXML(data []byte) (*SBOM, error) {
	var xmlDoc spdxXMLDocument
	if err := xml.Unmarshal(data, &xmlDoc); err != nil {
		return nil, err
	}

	// Convert XML structs to the common spdxDocument structure
	doc := spdxDocument{
		SpdxVersion: xmlDoc.SpdxVersion,
	}
	for _, xp := range xmlDoc.Packages {
		pkg := spdxPackage{
			SPDXID:      xp.SPDXID,
			Name:        xp.Name,
			VersionInfo: xp.VersionInfo,
		}
		for _, xr := range xp.ExternalRefs {
			pkg.ExternalRefs = append(pkg.ExternalRefs, spdxExternalRef{
				ReferenceCategory: xr.ReferenceCategory,
				ReferenceType:     xr.ReferenceType,
				ReferenceLocator:  xr.ReferenceLocator,
			})
		}
		doc.Packages = append(doc.Packages, pkg)
	}

	return buildSPDXSBOM(doc), nil
}

// parseSPDXYAML parses an SPDX YAML SBOM and returns the normalized SBOM.
func parseSPDXYAML(data []byte) (*SBOM, error) {
	var doc spdxDocument
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	return buildSPDXSBOM(doc), nil
}

// buildSPDXSBOM converts an spdxDocument into the normalized SBOM structure.
func buildSPDXSBOM(doc spdxDocument) *SBOM {
	var components []Component
	for _, pkg := range doc.Packages {
		purlStr := extractSPDXPurl(pkg)
		if purlStr == "" {
			continue
		}

		// SPDX does not distinguish dev dependencies
		comp := resolveComponent(purlStr, false)
		if comp == nil {
			continue
		}

		components = append(components, *comp)
	}

	return &SBOM{
		Format:     FormatSPDX,
		Components: components,
	}
}

// extractSPDXPurl finds the purl reference from an SPDX package's external references.
func extractSPDXPurl(pkg spdxPackage) string {
	for _, ref := range pkg.ExternalRefs {
		if ref.ReferenceType == "purl" {
			return ref.ReferenceLocator
		}
	}
	return ""
}
