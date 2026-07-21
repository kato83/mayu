package sbom

import "encoding/json"

// spdxDocument represents the top-level SPDX 2.3 JSON document (subset).
type spdxDocument struct {
	SpdxVersion string        `json:"spdxVersion"`
	Packages    []spdxPackage `json:"packages"`
}

// spdxPackage represents a single package in an SPDX document.
type spdxPackage struct {
	SPDXID       string            `json:"SPDXID"`
	Name         string            `json:"name"`
	VersionInfo  string            `json:"versionInfo"`
	ExternalRefs []spdxExternalRef `json:"externalRefs"`
}

// spdxExternalRef represents an external reference for an SPDX package.
type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

// parseSPDX parses an SPDX 2.3 JSON SBOM and returns the normalized SBOM.
// SPDX does not have a standard way to distinguish dev dependencies,
// so all packages are marked as IsDev=false.
func parseSPDX(data []byte) (*SBOM, error) {
	var doc spdxDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

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
	}, nil
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
