package sbom

import "testing"

func TestParseCycloneDX(t *testing.T) {
	data := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.7",
		"components": [
			{
				"type": "library",
				"name": "core",
				"version": "22.0.7",
				"purl": "pkg:npm/%40angular/core@22.0.7",
				"group": "@angular"
			},
			{
				"type": "library",
				"name": "build",
				"version": "22.0.7",
				"purl": "pkg:npm/%40angular/build@22.0.7",
				"scope": "excluded",
				"group": "@angular",
				"properties": [
					{
						"name": "cdx:npm:package:development",
						"value": "true"
					}
				]
			},
			{
				"type": "library",
				"name": "no-purl",
				"version": "1.0.0"
			}
		]
	}`)

	sbom, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if sbom.Format != FormatCycloneDX {
		t.Errorf("Format = %q, want %q", sbom.Format, FormatCycloneDX)
	}

	// Should have 2 components (no-purl skipped)
	if len(sbom.Components) != 2 {
		t.Fatalf("len(Components) = %d, want 2", len(sbom.Components))
	}

	// First component: production dependency
	c1 := sbom.Components[0]
	if c1.Name != "@angular/core" {
		t.Errorf("Components[0].Name = %q, want %q", c1.Name, "@angular/core")
	}
	if c1.Version != "22.0.7" {
		t.Errorf("Components[0].Version = %q, want %q", c1.Version, "22.0.7")
	}
	if c1.Ecosystem != "npm" {
		t.Errorf("Components[0].Ecosystem = %q, want %q", c1.Ecosystem, "npm")
	}
	if c1.IsDev {
		t.Error("Components[0].IsDev = true, want false")
	}

	// Second component: dev dependency
	c2 := sbom.Components[1]
	if c2.Name != "@angular/build" {
		t.Errorf("Components[1].Name = %q, want %q", c2.Name, "@angular/build")
	}
	if !c2.IsDev {
		t.Error("Components[1].IsDev = false, want true")
	}
}

func TestParseCycloneDX_DevDetection(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantDev bool
	}{
		{
			name: "scope excluded",
			json: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.7",
				"components": [{
					"type": "library",
					"name": "test",
					"version": "1.0.0",
					"purl": "pkg:npm/test@1.0.0",
					"scope": "excluded"
				}]
			}`,
			wantDev: true,
		},
		{
			name: "cdx:npm:package:development property",
			json: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.7",
				"components": [{
					"type": "library",
					"name": "test",
					"version": "1.0.0",
					"purl": "pkg:npm/test@1.0.0",
					"properties": [{"name": "cdx:npm:package:development", "value": "true"}]
				}]
			}`,
			wantDev: true,
		},
		{
			name: "scope required (not dev)",
			json: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.7",
				"components": [{
					"type": "library",
					"name": "test",
					"version": "1.0.0",
					"purl": "pkg:npm/test@1.0.0",
					"scope": "required"
				}]
			}`,
			wantDev: false,
		},
		{
			name: "no scope no properties",
			json: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.7",
				"components": [{
					"type": "library",
					"name": "test",
					"version": "1.0.0",
					"purl": "pkg:npm/test@1.0.0"
				}]
			}`,
			wantDev: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sbom, err := Parse([]byte(tt.json))
			if err != nil {
				t.Fatalf("Parse() error: %v", err)
			}
			if len(sbom.Components) != 1 {
				t.Fatalf("len(Components) = %d, want 1", len(sbom.Components))
			}
			if sbom.Components[0].IsDev != tt.wantDev {
				t.Errorf("IsDev = %v, want %v", sbom.Components[0].IsDev, tt.wantDev)
			}
		})
	}
}

func TestParseCycloneDX_SkipNoPurl(t *testing.T) {
	data := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.7",
		"components": [
			{"type": "library", "name": "has-purl", "version": "1.0.0", "purl": "pkg:npm/has-purl@1.0.0"},
			{"type": "library", "name": "no-purl", "version": "2.0.0"},
			{"type": "library", "name": "empty-purl", "version": "3.0.0", "purl": ""}
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
