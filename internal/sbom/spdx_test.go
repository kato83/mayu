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

func TestDetectFormat(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		want    string
		wantErr bool
	}{
		{
			name: "CycloneDX",
			json: `{"bomFormat": "CycloneDX", "specVersion": "1.7", "components": []}`,
			want: FormatCycloneDX,
		},
		{
			name: "SPDX",
			json: `{"spdxVersion": "SPDX-2.3", "packages": []}`,
			want: FormatSPDX,
		},
		{
			name:    "unknown format",
			json:    `{"name": "something", "version": "1.0.0"}`,
			wantErr: true,
		},
		{
			name:    "invalid JSON",
			json:    `not json`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := detectFormat([]byte(tt.json))
			if tt.wantErr {
				if err == nil {
					t.Error("detectFormat() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("detectFormat() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("detectFormat() = %q, want %q", got, tt.want)
			}
		})
	}
}
