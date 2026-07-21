package sbom

import "encoding/json"

// cycloneDXBOM represents the top-level CycloneDX BOM structure (subset).
type cycloneDXBOM struct {
	BomFormat   string               `json:"bomFormat"`
	SpecVersion string               `json:"specVersion"`
	Components  []cycloneDXComponent `json:"components"`
}

// cycloneDXComponent represents a single component in a CycloneDX BOM.
type cycloneDXComponent struct {
	Type       string              `json:"type"`
	Name       string              `json:"name"`
	Version    string              `json:"version"`
	Purl       string              `json:"purl"`
	BomRef     string              `json:"bom-ref"`
	Scope      string              `json:"scope"`
	Group      string              `json:"group"`
	Properties []cycloneDXProperty `json:"properties"`
}

// cycloneDXProperty represents a name-value property in CycloneDX.
type cycloneDXProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// parseCycloneDX parses a CycloneDX 1.7 JSON SBOM and returns the normalized SBOM.
func parseCycloneDX(data []byte) (*SBOM, error) {
	var bom cycloneDXBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, err
	}

	var components []Component
	for _, c := range bom.Components {
		if c.Purl == "" {
			continue
		}

		isDev := isCycloneDXDev(c)
		comp := resolveComponent(c.Purl, isDev)
		if comp == nil {
			continue
		}

		components = append(components, *comp)
	}

	return &SBOM{
		Format:     FormatCycloneDX,
		Components: components,
	}, nil
}

// isCycloneDXDev determines if a CycloneDX component is a development dependency.
// It checks two signals:
//   - scope == "excluded" (pnpm marks dev deps this way)
//   - property cdx:npm:package:development == "true"
func isCycloneDXDev(c cycloneDXComponent) bool {
	if c.Scope == "excluded" {
		return true
	}
	for _, p := range c.Properties {
		if p.Name == "cdx:npm:package:development" && p.Value == "true" {
			return true
		}
	}
	return false
}
