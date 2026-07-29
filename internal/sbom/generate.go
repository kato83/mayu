package sbom

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// GenerateMetadata holds metadata for SBOM generation.
type GenerateMetadata struct {
	// Name is the project or component name.
	Name string

	// Version is the project version string.
	Version string

	// Timestamp is the SBOM generation time.
	Timestamp time.Time
}

// CycloneDX output structures (generation-specific, separate from parse structs).

type cdxBOM struct {
	BOMFormat    string         `json:"bomFormat"`
	SpecVersion  string         `json:"specVersion"`
	Version      int            `json:"version"`
	SerialNumber string         `json:"serialNumber"`
	Metadata     cdxMetadata    `json:"metadata"`
	Components   []cdxComponent `json:"components"`
}

type cdxMetadata struct {
	Timestamp string        `json:"timestamp"`
	Component *cdxComponent `json:"component,omitempty"`
}

type cdxComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Purl    string `json:"purl,omitempty"`
}

// SPDX output structures (generation-specific).

type spdxDoc struct {
	SPDXVersion       string       `json:"spdxVersion"`
	DataLicense       string       `json:"dataLicense"`
	SPDXID            string       `json:"SPDXID"`
	Name              string       `json:"name"`
	DocumentNamespace string       `json:"documentNamespace"`
	CreationInfo      spdxCreation `json:"creationInfo"`
	Packages          []spdxPkg    `json:"packages"`
}

type spdxCreation struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPkg struct {
	SPDXID           string       `json:"SPDXID"`
	Name             string       `json:"name"`
	VersionInfo      string       `json:"versionInfo"`
	DownloadLocation string       `json:"downloadLocation"`
	ExternalRefs     []spdxExtRef `json:"externalRefs,omitempty"`
}

type spdxExtRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

// GenerateCycloneDX produces a CycloneDX 1.6 JSON SBOM from the given components.
func GenerateCycloneDX(components []Component, metadata GenerateMetadata) ([]byte, error) {
	ts := metadata.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	bom := cdxBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		Version:      1,
		SerialNumber: "urn:uuid:" + generateUUID(),
		Metadata: cdxMetadata{
			Timestamp: ts.Format(time.RFC3339),
		},
		Components: make([]cdxComponent, 0, len(components)),
	}

	if metadata.Name != "" {
		bom.Metadata.Component = &cdxComponent{
			Type:    "application",
			Name:    metadata.Name,
			Version: metadata.Version,
		}
	}

	for _, c := range components {
		comp := cdxComponent{
			Type:    "library",
			Name:    c.Name,
			Version: c.Version,
			Purl:    c.Purl,
		}
		bom.Components = append(bom.Components, comp)
	}

	return json.MarshalIndent(bom, "", "  ")
}

// GenerateSPDX produces an SPDX 2.3 JSON SBOM from the given components.
func GenerateSPDX(components []Component, metadata GenerateMetadata) ([]byte, error) {
	ts := metadata.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	name := metadata.Name
	if name == "" {
		name = "unknown"
	}

	doc := spdxDoc{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              name,
		DocumentNamespace: fmt.Sprintf("https://spdx.org/spdxdocs/%s-%s", name, generateUUID()),
		CreationInfo: spdxCreation{
			Created:  ts.Format(time.RFC3339),
			Creators: []string{"Tool: mayu"},
		},
		Packages: make([]spdxPkg, 0, len(components)),
	}

	for i, c := range components {
		pkg := spdxPkg{
			SPDXID:           fmt.Sprintf("SPDXRef-Package-%d", i+1),
			Name:             c.Name,
			VersionInfo:      c.Version,
			DownloadLocation: "NOASSERTION",
		}
		if c.Purl != "" {
			pkg.ExternalRefs = []spdxExtRef{
				{
					ReferenceCategory: "PACKAGE-MANAGER",
					ReferenceType:     "purl",
					ReferenceLocator:  c.Purl,
				},
			}
		}
		doc.Packages = append(doc.Packages, pkg)
	}

	return json.MarshalIndent(doc, "", "  ")
}

// generateUUID produces a random UUID v4 string.
func generateUUID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		// Fallback: use timestamp-based pseudo-random
		ts := time.Now().UnixNano()
		for i := range b {
			b[i] = byte(ts >> (i * 4))
		}
	}
	// Set version 4 and variant bits
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80

	var sb strings.Builder
	sb.WriteString(hex.EncodeToString(b[0:4]))
	sb.WriteByte('-')
	sb.WriteString(hex.EncodeToString(b[4:6]))
	sb.WriteByte('-')
	sb.WriteString(hex.EncodeToString(b[6:8]))
	sb.WriteByte('-')
	sb.WriteString(hex.EncodeToString(b[8:10]))
	sb.WriteByte('-')
	sb.WriteString(hex.EncodeToString(b[10:16]))
	return sb.String()
}
