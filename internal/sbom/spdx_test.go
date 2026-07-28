package sbom

import "testing"

func TestParseSPDX(t *testing.T) {
	data := []byte(`{
		"spdxVersion": "SPDX-2.3",
		"dataLicense": "CC0-1.0",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "test-project",
		"packages": [
			{
				"SPDXID": "SPDXRef-Package-express-4.18.2-0",
				"name": "express",
				"versionInfo": "4.18.2",
				"downloadLocation": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
				"externalRefs": [
					{
						"referenceCategory": "PACKAGE-MANAGER",
						"referenceType": "purl",
						"referenceLocator": "pkg:npm/express@4.18.2"
					}
				]
			},
			{
				"SPDXID": "SPDXRef-Package-angular-core-22.0.7-1",
				"name": "@angular/core",
				"versionInfo": "22.0.7",
				"downloadLocation": "https://registry.npmjs.org/@angular/core/-/core-22.0.7.tgz",
				"externalRefs": [
					{
						"referenceCategory": "PACKAGE-MANAGER",
						"referenceType": "purl",
						"referenceLocator": "pkg:npm/%40angular/core@22.0.7"
					}
				]
			},
			{
				"SPDXID": "SPDXRef-Package-no-purl-1.0.0-2",
				"name": "no-purl",
				"versionInfo": "1.0.0",
				"downloadLocation": "NOASSERTION"
			}
		]
	}`)

	sbom, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if sbom.Format != FormatSPDX {
		t.Errorf("Format = %q, want %q", sbom.Format, FormatSPDX)
	}

	// Should have 2 components (no-purl package skipped)
	if len(sbom.Components) != 2 {
		t.Fatalf("len(Components) = %d, want 2", len(sbom.Components))
	}

	// First component
	c1 := sbom.Components[0]
	if c1.Name != "express" {
		t.Errorf("Components[0].Name = %q, want %q", c1.Name, "express")
	}
	if c1.Version != "4.18.2" {
		t.Errorf("Components[0].Version = %q, want %q", c1.Version, "4.18.2")
	}
	if c1.Ecosystem != "npm" {
		t.Errorf("Components[0].Ecosystem = %q, want %q", c1.Ecosystem, "npm")
	}
	if c1.IsDev {
		t.Error("Components[0].IsDev = true, want false (SPDX never marks dev)")
	}

	// Second component (scoped npm package)
	c2 := sbom.Components[1]
	if c2.Name != "@angular/core" {
		t.Errorf("Components[1].Name = %q, want %q", c2.Name, "@angular/core")
	}
	if c2.Version != "22.0.7" {
		t.Errorf("Components[1].Version = %q, want %q", c2.Version, "22.0.7")
	}
}

func TestParseSPDX_SkipNoPurl(t *testing.T) {
	data := []byte(`{
		"spdxVersion": "SPDX-2.3",
		"packages": [
			{
				"SPDXID": "SPDXRef-Package-no-refs",
				"name": "no-refs",
				"versionInfo": "1.0.0"
			},
			{
				"SPDXID": "SPDXRef-Package-non-purl-ref",
				"name": "non-purl-ref",
				"versionInfo": "1.0.0",
				"externalRefs": [
					{
						"referenceCategory": "SECURITY",
						"referenceType": "cpe23Type",
						"referenceLocator": "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"
					}
				]
			},
			{
				"SPDXID": "SPDXRef-Package-has-purl",
				"name": "has-purl",
				"versionInfo": "2.0.0",
				"externalRefs": [
					{
						"referenceCategory": "PACKAGE-MANAGER",
						"referenceType": "purl",
						"referenceLocator": "pkg:npm/has-purl@2.0.0"
					}
				]
			}
		]
	}`)

	sbom, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if len(sbom.Components) != 1 {
		t.Fatalf("len(Components) = %d, want 1", len(sbom.Components))
	}
	if sbom.Components[0].Name != "has-purl" {
		t.Errorf("Components[0].Name = %q, want %q", sbom.Components[0].Name, "has-purl")
	}
}

func TestParseSPDX_DevAlwaysFalse(t *testing.T) {
	// SPDX cannot distinguish dev dependencies, so IsDev should always be false
	data := []byte(`{
		"spdxVersion": "SPDX-2.3",
		"packages": [
			{
				"SPDXID": "SPDXRef-Package-vitest",
				"name": "vitest",
				"versionInfo": "3.2.4",
				"externalRefs": [
					{
						"referenceCategory": "PACKAGE-MANAGER",
						"referenceType": "purl",
						"referenceLocator": "pkg:npm/vitest@3.2.4"
					}
				]
			}
		]
	}`)

	sbom, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if len(sbom.Components) != 1 {
		t.Fatalf("len(Components) = %d, want 1", len(sbom.Components))
	}
	if sbom.Components[0].IsDev {
		t.Error("SPDX component IsDev = true, want false (SPDX cannot distinguish dev deps)")
	}
}

func TestParseSPDXXML(t *testing.T) {
	data := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<Document xmlns="http://spdx.org/rdf/terms#">
  <spdxVersion>SPDX-2.3</spdxVersion>
  <packages>
    <Package>
      <SPDXID>SPDXRef-Package-express</SPDXID>
      <name>express</name>
      <versionInfo>4.18.2</versionInfo>
      <externalRefs>
        <ExternalRef>
          <referenceCategory>PACKAGE-MANAGER</referenceCategory>
          <referenceType>purl</referenceType>
          <referenceLocator>pkg:npm/express@4.18.2</referenceLocator>
        </ExternalRef>
      </externalRefs>
    </Package>
    <Package>
      <SPDXID>SPDXRef-Package-angular-core</SPDXID>
      <name>@angular/core</name>
      <versionInfo>22.0.7</versionInfo>
      <externalRefs>
        <ExternalRef>
          <referenceCategory>PACKAGE-MANAGER</referenceCategory>
          <referenceType>purl</referenceType>
          <referenceLocator>pkg:npm/%40angular/core@22.0.7</referenceLocator>
        </ExternalRef>
      </externalRefs>
    </Package>
    <Package>
      <SPDXID>SPDXRef-Package-no-purl</SPDXID>
      <name>no-purl</name>
      <versionInfo>1.0.0</versionInfo>
    </Package>
  </packages>
</Document>`)

	sbom, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if sbom.Format != FormatSPDX {
		t.Errorf("Format = %q, want %q", sbom.Format, FormatSPDX)
	}

	// Should have 2 components (no-purl skipped)
	if len(sbom.Components) != 2 {
		t.Fatalf("len(Components) = %d, want 2", len(sbom.Components))
	}

	// First component
	c1 := sbom.Components[0]
	if c1.Name != "express" {
		t.Errorf("Components[0].Name = %q, want %q", c1.Name, "express")
	}
	if c1.Version != "4.18.2" {
		t.Errorf("Components[0].Version = %q, want %q", c1.Version, "4.18.2")
	}
	if c1.Ecosystem != "npm" {
		t.Errorf("Components[0].Ecosystem = %q, want %q", c1.Ecosystem, "npm")
	}
	if c1.IsDev {
		t.Error("Components[0].IsDev = true, want false")
	}

	// Second component (scoped npm package)
	c2 := sbom.Components[1]
	if c2.Name != "@angular/core" {
		t.Errorf("Components[1].Name = %q, want %q", c2.Name, "@angular/core")
	}
	if c2.Version != "22.0.7" {
		t.Errorf("Components[1].Version = %q, want %q", c2.Version, "22.0.7")
	}
}

func TestParseSPDXXML_SkipNoPurl(t *testing.T) {
	data := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<Document xmlns="http://spdx.org/rdf/terms#">
  <spdxVersion>SPDX-2.3</spdxVersion>
  <packages>
    <Package>
      <SPDXID>SPDXRef-Package-no-refs</SPDXID>
      <name>no-refs</name>
      <versionInfo>1.0.0</versionInfo>
    </Package>
    <Package>
      <SPDXID>SPDXRef-Package-non-purl-ref</SPDXID>
      <name>non-purl-ref</name>
      <versionInfo>1.0.0</versionInfo>
      <externalRefs>
        <ExternalRef>
          <referenceCategory>SECURITY</referenceCategory>
          <referenceType>cpe23Type</referenceType>
          <referenceLocator>cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*</referenceLocator>
        </ExternalRef>
      </externalRefs>
    </Package>
    <Package>
      <SPDXID>SPDXRef-Package-has-purl</SPDXID>
      <name>has-purl</name>
      <versionInfo>2.0.0</versionInfo>
      <externalRefs>
        <ExternalRef>
          <referenceCategory>PACKAGE-MANAGER</referenceCategory>
          <referenceType>purl</referenceType>
          <referenceLocator>pkg:npm/has-purl@2.0.0</referenceLocator>
        </ExternalRef>
      </externalRefs>
    </Package>
  </packages>
</Document>`)

	sbom, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if len(sbom.Components) != 1 {
		t.Fatalf("len(Components) = %d, want 1", len(sbom.Components))
	}
	if sbom.Components[0].Name != "has-purl" {
		t.Errorf("Components[0].Name = %q, want %q", sbom.Components[0].Name, "has-purl")
	}
}

func TestParseSPDXXML_DevAlwaysFalse(t *testing.T) {
	data := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<Document xmlns="http://spdx.org/rdf/terms#">
  <spdxVersion>SPDX-2.3</spdxVersion>
  <packages>
    <Package>
      <SPDXID>SPDXRef-Package-vitest</SPDXID>
      <name>vitest</name>
      <versionInfo>3.2.4</versionInfo>
      <externalRefs>
        <ExternalRef>
          <referenceCategory>PACKAGE-MANAGER</referenceCategory>
          <referenceType>purl</referenceType>
          <referenceLocator>pkg:npm/vitest@3.2.4</referenceLocator>
        </ExternalRef>
      </externalRefs>
    </Package>
  </packages>
</Document>`)

	sbom, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if len(sbom.Components) != 1 {
		t.Fatalf("len(Components) = %d, want 1", len(sbom.Components))
	}
	if sbom.Components[0].IsDev {
		t.Error("SPDX XML component IsDev = true, want false")
	}
}

func TestParseSPDXYAML(t *testing.T) {
	data := []byte(`spdxVersion: "SPDX-2.3"
dataLicense: "CC0-1.0"
SPDXID: "SPDXRef-DOCUMENT"
name: "test-project"
packages:
  - SPDXID: "SPDXRef-Package-express"
    name: "express"
    versionInfo: "4.18.2"
    externalRefs:
      - referenceCategory: "PACKAGE-MANAGER"
        referenceType: "purl"
        referenceLocator: "pkg:npm/express@4.18.2"
  - SPDXID: "SPDXRef-Package-angular-core"
    name: "@angular/core"
    versionInfo: "22.0.7"
    externalRefs:
      - referenceCategory: "PACKAGE-MANAGER"
        referenceType: "purl"
        referenceLocator: "pkg:npm/%40angular/core@22.0.7"
  - SPDXID: "SPDXRef-Package-no-purl"
    name: "no-purl"
    versionInfo: "1.0.0"
`)

	sbom, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if sbom.Format != FormatSPDX {
		t.Errorf("Format = %q, want %q", sbom.Format, FormatSPDX)
	}

	// Should have 2 components (no-purl skipped)
	if len(sbom.Components) != 2 {
		t.Fatalf("len(Components) = %d, want 2", len(sbom.Components))
	}

	// First component
	c1 := sbom.Components[0]
	if c1.Name != "express" {
		t.Errorf("Components[0].Name = %q, want %q", c1.Name, "express")
	}
	if c1.Version != "4.18.2" {
		t.Errorf("Components[0].Version = %q, want %q", c1.Version, "4.18.2")
	}
	if c1.Ecosystem != "npm" {
		t.Errorf("Components[0].Ecosystem = %q, want %q", c1.Ecosystem, "npm")
	}
	if c1.IsDev {
		t.Error("Components[0].IsDev = true, want false")
	}

	// Second component (scoped npm package)
	c2 := sbom.Components[1]
	if c2.Name != "@angular/core" {
		t.Errorf("Components[1].Name = %q, want %q", c2.Name, "@angular/core")
	}
	if c2.Version != "22.0.7" {
		t.Errorf("Components[1].Version = %q, want %q", c2.Version, "22.0.7")
	}
}

func TestParseSPDXYAML_SkipNoPurl(t *testing.T) {
	data := []byte(`spdxVersion: "SPDX-2.3"
packages:
  - SPDXID: "SPDXRef-Package-no-refs"
    name: "no-refs"
    versionInfo: "1.0.0"
  - SPDXID: "SPDXRef-Package-non-purl-ref"
    name: "non-purl-ref"
    versionInfo: "1.0.0"
    externalRefs:
      - referenceCategory: "SECURITY"
        referenceType: "cpe23Type"
        referenceLocator: "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"
  - SPDXID: "SPDXRef-Package-has-purl"
    name: "has-purl"
    versionInfo: "2.0.0"
    externalRefs:
      - referenceCategory: "PACKAGE-MANAGER"
        referenceType: "purl"
        referenceLocator: "pkg:npm/has-purl@2.0.0"
`)

	sbom, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if len(sbom.Components) != 1 {
		t.Fatalf("len(Components) = %d, want 1", len(sbom.Components))
	}
	if sbom.Components[0].Name != "has-purl" {
		t.Errorf("Components[0].Name = %q, want %q", sbom.Components[0].Name, "has-purl")
	}
}

func TestParseSPDXYAML_DevAlwaysFalse(t *testing.T) {
	data := []byte(`spdxVersion: "SPDX-2.3"
packages:
  - SPDXID: "SPDXRef-Package-vitest"
    name: "vitest"
    versionInfo: "3.2.4"
    externalRefs:
      - referenceCategory: "PACKAGE-MANAGER"
        referenceType: "purl"
        referenceLocator: "pkg:npm/vitest@3.2.4"
`)

	sbom, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if len(sbom.Components) != 1 {
		t.Fatalf("len(Components) = %d, want 1", len(sbom.Components))
	}
	if sbom.Components[0].IsDev {
		t.Error("SPDX YAML component IsDev = true, want false")
	}
}

func TestDetectFormat(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "CycloneDX JSON",
			input: `{"bomFormat": "CycloneDX", "specVersion": "1.7", "components": []}`,
			want:  FormatCycloneDX,
		},
		{
			name:  "SPDX JSON",
			input: `{"spdxVersion": "SPDX-2.3", "packages": []}`,
			want:  FormatSPDX,
		},
		{
			name: "CycloneDX XML",
			input: `<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.6"><components></components></bom>`,
			want: FormatCycloneDX,
		},
		{
			name: "SPDX XML",
			input: `<?xml version="1.0" encoding="UTF-8"?>
<Document xmlns="http://spdx.org/rdf/terms#"><spdxVersion>SPDX-2.3</spdxVersion></Document>`,
			want: FormatSPDX,
		},
		{
			name: "CycloneDX YAML",
			input: `bomFormat: CycloneDX
specVersion: "1.6"
components: []
`,
			want: FormatCycloneDX,
		},
		{
			name: "SPDX YAML",
			input: `spdxVersion: "SPDX-2.3"
packages: []
`,
			want: FormatSPDX,
		},
		{
			name:    "unknown format",
			input:   `{"name": "something", "version": "1.0.0"}`,
			wantErr: true,
		},
		{
			name:    "invalid content",
			input:   `not json or yaml or xml %%%`,
			wantErr: true,
		},
		{
			name:    "unknown XML format",
			input:   `<?xml version="1.0"?><root><unknown>data</unknown></root>`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := detectFormat([]byte(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Error("detectFormat() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("detectFormat() error = %v", err)
			}
			if got.format != tt.want {
				t.Errorf("detectFormat().format = %q, want %q", got.format, tt.want)
			}
		})
	}
}
