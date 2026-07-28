package sbom

import (
	"encoding/json"
	"encoding/xml"

	"gopkg.in/yaml.v3"
)

// cycloneDXBOM represents the top-level CycloneDX BOM structure (subset).
type cycloneDXBOM struct {
	BomFormat   string               `json:"bomFormat" yaml:"bomFormat"`
	SpecVersion string               `json:"specVersion" yaml:"specVersion"`
	Components  []cycloneDXComponent `json:"components" yaml:"components"`
}

// cycloneDXComponent represents a single component in a CycloneDX BOM.
type cycloneDXComponent struct {
	Type       string              `json:"type" yaml:"type"`
	Name       string              `json:"name" yaml:"name"`
	Version    string              `json:"version" yaml:"version"`
	Purl       string              `json:"purl" yaml:"purl"`
	BomRef     string              `json:"bom-ref" yaml:"bom-ref"`
	Scope      string              `json:"scope" yaml:"scope"`
	Group      string              `json:"group" yaml:"group"`
	Properties []cycloneDXProperty `json:"properties" yaml:"properties"`
}

// cycloneDXProperty represents a name-value property in CycloneDX.
type cycloneDXProperty struct {
	Name  string `json:"name" yaml:"name"`
	Value string `json:"value" yaml:"value"`
}

// cycloneDXXMLBOM represents the top-level CycloneDX XML BOM structure.
type cycloneDXXMLBOM struct {
	XMLName    xml.Name                 `xml:"bom"`
	Components []cycloneDXXMLComponent  `xml:"components>component"`
}

// cycloneDXXMLComponent represents a single component in a CycloneDX XML BOM.
// NOTE: bom-ref is declared as an XML attribute (xml:"bom-ref,attr") which matches
// CycloneDX schema versions 1.4 and later. Older schema versions (< 1.4) may
// represent bom-ref differently; those documents will have this field silently empty.
type cycloneDXXMLComponent struct {
	Type       string                  `xml:"type,attr"`
	Name       string                  `xml:"name"`
	Version    string                  `xml:"version"`
	Purl       string                  `xml:"purl"`
	BomRef     string                  `xml:"bom-ref,attr"`
	Scope      string                  `xml:"scope"`
	Group      string                  `xml:"group"`
	Properties []cycloneDXXMLProperty  `xml:"properties>property"`
}

// cycloneDXXMLProperty represents a property element in CycloneDX XML.
// In CycloneDX XML, the property name is an attribute and the value is character data.
type cycloneDXXMLProperty struct {
	Name  string `xml:"name,attr"`
	Value string `xml:",chardata"`
}

// parseCycloneDX parses a CycloneDX JSON SBOM and returns the normalized SBOM.
func parseCycloneDX(data []byte) (*SBOM, error) {
	var bom cycloneDXBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, err
	}

	return buildCycloneDXSBOM(bom), nil
}

// parseCycloneDXXML parses a CycloneDX XML SBOM and returns the normalized SBOM.
func parseCycloneDXXML(data []byte) (*SBOM, error) {
	var xmlBom cycloneDXXMLBOM
	if err := xml.Unmarshal(data, &xmlBom); err != nil {
		return nil, err
	}

	// Convert XML structs to the common cycloneDXBOM structure
	bom := cycloneDXBOM{}
	for _, xc := range xmlBom.Components {
		c := cycloneDXComponent{
			Type:    xc.Type,
			Name:    xc.Name,
			Version: xc.Version,
			Purl:    xc.Purl,
			BomRef:  xc.BomRef,
			Scope:   xc.Scope,
			Group:   xc.Group,
		}
		for _, xp := range xc.Properties {
			c.Properties = append(c.Properties, cycloneDXProperty(xp))
		}
		bom.Components = append(bom.Components, c)
	}

	return buildCycloneDXSBOM(bom), nil
}

// parseCycloneDXYAML parses a CycloneDX YAML SBOM and returns the normalized SBOM.
func parseCycloneDXYAML(data []byte) (*SBOM, error) {
	var bom cycloneDXBOM
	if err := yaml.Unmarshal(data, &bom); err != nil {
		return nil, err
	}

	return buildCycloneDXSBOM(bom), nil
}

// buildCycloneDXSBOM converts a cycloneDXBOM into the normalized SBOM structure.
func buildCycloneDXSBOM(bom cycloneDXBOM) *SBOM {
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
	}
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
