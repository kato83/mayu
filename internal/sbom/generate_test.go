package sbom

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestGenerateCycloneDX(t *testing.T) {
	ts := time.Date(2025, 7, 30, 12, 0, 0, 0, time.UTC)
	components := []Component{
		{Purl: "pkg:golang/golang.org/x/crypto@0.23.0", Name: "golang.org/x/crypto", Version: "0.23.0", Ecosystem: "Go"},
		{Purl: "pkg:npm/express@4.18.2", Name: "express", Version: "4.18.2", Ecosystem: "npm"},
	}
	meta := GenerateMetadata{
		Name:      "my-app",
		Version:   "1.0.0",
		Timestamp: ts,
	}

	data, err := GenerateCycloneDX(components, meta)
	if err != nil {
		t.Fatalf("GenerateCycloneDX() error = %v", err)
	}

	// Parse back and verify structure
	var bom cdxBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("failed to unmarshal output: %v", err)
	}

	if bom.BOMFormat != "CycloneDX" {
		t.Errorf("bomFormat = %q, want %q", bom.BOMFormat, "CycloneDX")
	}
	if bom.SpecVersion != "1.6" {
		t.Errorf("specVersion = %q, want %q", bom.SpecVersion, "1.6")
	}
	if bom.Version != 1 {
		t.Errorf("version = %d, want 1", bom.Version)
	}
	if !strings.HasPrefix(bom.SerialNumber, "urn:uuid:") {
		t.Errorf("serialNumber = %q, want prefix %q", bom.SerialNumber, "urn:uuid:")
	}
	if bom.Metadata.Timestamp != "2025-07-30T12:00:00Z" {
		t.Errorf("metadata.timestamp = %q, want %q", bom.Metadata.Timestamp, "2025-07-30T12:00:00Z")
	}
	if bom.Metadata.Component == nil {
		t.Fatal("metadata.component is nil")
	}
	if bom.Metadata.Component.Name != "my-app" {
		t.Errorf("metadata.component.name = %q, want %q", bom.Metadata.Component.Name, "my-app")
	}
	if bom.Metadata.Component.Version != "1.0.0" {
		t.Errorf("metadata.component.version = %q, want %q", bom.Metadata.Component.Version, "1.0.0")
	}
	if bom.Metadata.Component.Type != "application" {
		t.Errorf("metadata.component.type = %q, want %q", bom.Metadata.Component.Type, "application")
	}
	if len(bom.Components) != 2 {
		t.Fatalf("len(components) = %d, want 2", len(bom.Components))
	}

	// Verify first component
	c0 := bom.Components[0]
	if c0.Type != "library" {
		t.Errorf("components[0].type = %q, want %q", c0.Type, "library")
	}
	if c0.Name != "golang.org/x/crypto" {
		t.Errorf("components[0].name = %q, want %q", c0.Name, "golang.org/x/crypto")
	}
	if c0.Version != "0.23.0" {
		t.Errorf("components[0].version = %q, want %q", c0.Version, "0.23.0")
	}
	if c0.Purl != "pkg:golang/golang.org/x/crypto@0.23.0" {
		t.Errorf("components[0].purl = %q, want %q", c0.Purl, "pkg:golang/golang.org/x/crypto@0.23.0")
	}

	// Verify second component
	c1 := bom.Components[1]
	if c1.Name != "express" {
		t.Errorf("components[1].name = %q, want %q", c1.Name, "express")
	}
	if c1.Purl != "pkg:npm/express@4.18.2" {
		t.Errorf("components[1].purl = %q, want %q", c1.Purl, "pkg:npm/express@4.18.2")
	}
}

func TestGenerateCycloneDX_NoMetadataName(t *testing.T) {
	components := []Component{
		{Purl: "pkg:npm/lodash@4.17.21", Name: "lodash", Version: "4.17.21", Ecosystem: "npm"},
	}
	meta := GenerateMetadata{
		Timestamp: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	data, err := GenerateCycloneDX(components, meta)
	if err != nil {
		t.Fatalf("GenerateCycloneDX() error = %v", err)
	}

	var bom cdxBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("failed to unmarshal output: %v", err)
	}

	// When no name is provided, metadata.component should be nil/omitted
	if bom.Metadata.Component != nil {
		t.Errorf("metadata.component should be nil when Name is empty, got %+v", bom.Metadata.Component)
	}
	if len(bom.Components) != 1 {
		t.Fatalf("len(components) = %d, want 1", len(bom.Components))
	}
}

func TestGenerateCycloneDX_EmptyComponents(t *testing.T) {
	meta := GenerateMetadata{
		Name:      "empty-app",
		Version:   "0.0.1",
		Timestamp: time.Date(2025, 6, 15, 10, 30, 0, 0, time.UTC),
	}

	data, err := GenerateCycloneDX(nil, meta)
	if err != nil {
		t.Fatalf("GenerateCycloneDX() error = %v", err)
	}

	var bom cdxBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("failed to unmarshal output: %v", err)
	}

	if bom.Components == nil {
		t.Error("components should be empty array, not nil")
	}
	if len(bom.Components) != 0 {
		t.Errorf("len(components) = %d, want 0", len(bom.Components))
	}
}

func TestGenerateSPDX(t *testing.T) {
	ts := time.Date(2025, 7, 30, 12, 0, 0, 0, time.UTC)
	components := []Component{
		{Purl: "pkg:golang/golang.org/x/crypto@0.23.0", Name: "golang.org/x/crypto", Version: "0.23.0", Ecosystem: "Go"},
		{Purl: "pkg:npm/express@4.18.2", Name: "express", Version: "4.18.2", Ecosystem: "npm"},
	}
	meta := GenerateMetadata{
		Name:      "my-app",
		Version:   "1.0.0",
		Timestamp: ts,
	}

	data, err := GenerateSPDX(components, meta)
	if err != nil {
		t.Fatalf("GenerateSPDX() error = %v", err)
	}

	var doc spdxDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("failed to unmarshal output: %v", err)
	}

	if doc.SPDXVersion != "SPDX-2.3" {
		t.Errorf("spdxVersion = %q, want %q", doc.SPDXVersion, "SPDX-2.3")
	}
	if doc.DataLicense != "CC0-1.0" {
		t.Errorf("dataLicense = %q, want %q", doc.DataLicense, "CC0-1.0")
	}
	if doc.SPDXID != "SPDXRef-DOCUMENT" {
		t.Errorf("SPDXID = %q, want %q", doc.SPDXID, "SPDXRef-DOCUMENT")
	}
	if doc.Name != "my-app" {
		t.Errorf("name = %q, want %q", doc.Name, "my-app")
	}
	if !strings.HasPrefix(doc.DocumentNamespace, "https://spdx.org/spdxdocs/my-app-") {
		t.Errorf("documentNamespace = %q, want prefix %q", doc.DocumentNamespace, "https://spdx.org/spdxdocs/my-app-")
	}
	if doc.CreationInfo.Created != "2025-07-30T12:00:00Z" {
		t.Errorf("creationInfo.created = %q, want %q", doc.CreationInfo.Created, "2025-07-30T12:00:00Z")
	}
	if len(doc.CreationInfo.Creators) != 1 || doc.CreationInfo.Creators[0] != "Tool: mayu" {
		t.Errorf("creationInfo.creators = %v, want [Tool: mayu]", doc.CreationInfo.Creators)
	}
	if len(doc.Packages) != 2 {
		t.Fatalf("len(packages) = %d, want 2", len(doc.Packages))
	}

	// Verify first package
	p0 := doc.Packages[0]
	if p0.SPDXID != "SPDXRef-Package-1" {
		t.Errorf("packages[0].SPDXID = %q, want %q", p0.SPDXID, "SPDXRef-Package-1")
	}
	if p0.Name != "golang.org/x/crypto" {
		t.Errorf("packages[0].name = %q, want %q", p0.Name, "golang.org/x/crypto")
	}
	if p0.VersionInfo != "0.23.0" {
		t.Errorf("packages[0].versionInfo = %q, want %q", p0.VersionInfo, "0.23.0")
	}
	if p0.DownloadLocation != "NOASSERTION" {
		t.Errorf("packages[0].downloadLocation = %q, want %q", p0.DownloadLocation, "NOASSERTION")
	}
	if len(p0.ExternalRefs) != 1 {
		t.Fatalf("len(packages[0].externalRefs) = %d, want 1", len(p0.ExternalRefs))
	}
	if p0.ExternalRefs[0].ReferenceCategory != "PACKAGE-MANAGER" {
		t.Errorf("packages[0].externalRefs[0].referenceCategory = %q, want %q", p0.ExternalRefs[0].ReferenceCategory, "PACKAGE-MANAGER")
	}
	if p0.ExternalRefs[0].ReferenceType != "purl" {
		t.Errorf("packages[0].externalRefs[0].referenceType = %q, want %q", p0.ExternalRefs[0].ReferenceType, "purl")
	}
	if p0.ExternalRefs[0].ReferenceLocator != "pkg:golang/golang.org/x/crypto@0.23.0" {
		t.Errorf("packages[0].externalRefs[0].referenceLocator = %q, want %q", p0.ExternalRefs[0].ReferenceLocator, "pkg:golang/golang.org/x/crypto@0.23.0")
	}

	// Verify second package
	p1 := doc.Packages[1]
	if p1.SPDXID != "SPDXRef-Package-2" {
		t.Errorf("packages[1].SPDXID = %q, want %q", p1.SPDXID, "SPDXRef-Package-2")
	}
	if p1.Name != "express" {
		t.Errorf("packages[1].name = %q, want %q", p1.Name, "express")
	}
}

func TestGenerateSPDX_EmptyComponents(t *testing.T) {
	meta := GenerateMetadata{
		Name:      "empty-app",
		Timestamp: time.Date(2025, 6, 15, 10, 30, 0, 0, time.UTC),
	}

	data, err := GenerateSPDX(nil, meta)
	if err != nil {
		t.Fatalf("GenerateSPDX() error = %v", err)
	}

	var doc spdxDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("failed to unmarshal output: %v", err)
	}

	if doc.Packages == nil {
		t.Error("packages should be empty array, not nil")
	}
	if len(doc.Packages) != 0 {
		t.Errorf("len(packages) = %d, want 0", len(doc.Packages))
	}
}

func TestGenerateSPDX_NoName(t *testing.T) {
	meta := GenerateMetadata{
		Timestamp: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	components := []Component{
		{Purl: "pkg:npm/lodash@4.17.21", Name: "lodash", Version: "4.17.21", Ecosystem: "npm"},
	}

	data, err := GenerateSPDX(components, meta)
	if err != nil {
		t.Fatalf("GenerateSPDX() error = %v", err)
	}

	var doc spdxDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("failed to unmarshal output: %v", err)
	}

	if doc.Name != "unknown" {
		t.Errorf("name = %q, want %q when no name provided", doc.Name, "unknown")
	}
	if !strings.HasPrefix(doc.DocumentNamespace, "https://spdx.org/spdxdocs/unknown-") {
		t.Errorf("documentNamespace = %q, want prefix %q", doc.DocumentNamespace, "https://spdx.org/spdxdocs/unknown-")
	}
}

func TestGenerateSPDX_NoPurl(t *testing.T) {
	meta := GenerateMetadata{
		Name:      "test",
		Timestamp: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	components := []Component{
		{Name: "some-lib", Version: "1.0.0", Ecosystem: "npm"},
	}

	data, err := GenerateSPDX(components, meta)
	if err != nil {
		t.Fatalf("GenerateSPDX() error = %v", err)
	}

	var doc spdxDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("failed to unmarshal output: %v", err)
	}

	if len(doc.Packages) != 1 {
		t.Fatalf("len(packages) = %d, want 1", len(doc.Packages))
	}
	if doc.Packages[0].ExternalRefs != nil {
		t.Errorf("externalRefs should be nil when purl is empty, got %v", doc.Packages[0].ExternalRefs)
	}
}

func TestGenerateCycloneDX_ValidJSON(t *testing.T) {
	// Verify that the output is valid JSON that can be parsed by any JSON parser
	components := []Component{
		{Purl: "pkg:npm/@angular/core@22.0.7", Name: "@angular/core", Version: "22.0.7", Ecosystem: "npm"},
	}
	meta := GenerateMetadata{
		Name:      "angular-app",
		Timestamp: time.Date(2025, 7, 30, 0, 0, 0, 0, time.UTC),
	}

	data, err := GenerateCycloneDX(components, meta)
	if err != nil {
		t.Fatalf("GenerateCycloneDX() error = %v", err)
	}

	if !json.Valid(data) {
		t.Error("output is not valid JSON")
	}
}

func TestGenerateSPDX_ValidJSON(t *testing.T) {
	components := []Component{
		{Purl: "pkg:npm/@angular/core@22.0.7", Name: "@angular/core", Version: "22.0.7", Ecosystem: "npm"},
	}
	meta := GenerateMetadata{
		Name:      "angular-app",
		Timestamp: time.Date(2025, 7, 30, 0, 0, 0, 0, time.UTC),
	}

	data, err := GenerateSPDX(components, meta)
	if err != nil {
		t.Fatalf("GenerateSPDX() error = %v", err)
	}

	if !json.Valid(data) {
		t.Error("output is not valid JSON")
	}
}
