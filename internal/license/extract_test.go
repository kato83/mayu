package license

import "testing"

func TestExtractFromCycloneDX(t *testing.T) {
	raw := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"components": [
			{
				"type": "library",
				"name": "express",
				"version": "4.18.2",
				"purl": "pkg:npm/express@4.18.2",
				"licenses": [
					{"license": {"id": "MIT"}}
				]
			},
			{
				"type": "library",
				"name": "lodash",
				"version": "4.17.21",
				"purl": "pkg:npm/lodash@4.17.21",
				"licenses": [
					{"license": {"name": "MIT License"}}
				]
			},
			{
				"type": "library",
				"name": "dual-licensed",
				"version": "1.0.0",
				"purl": "pkg:npm/dual-licensed@1.0.0",
				"licenses": [
					{"expression": "MIT OR Apache-2.0"}
				]
			},
			{
				"type": "library",
				"name": "no-license",
				"version": "0.0.1",
				"purl": "pkg:npm/no-license@0.0.1"
			}
		]
	}`)

	results, err := ExtractFromCycloneDX(raw)
	if err != nil {
		t.Fatalf("ExtractFromCycloneDX: %v", err)
	}

	if len(results) != 4 {
		t.Fatalf("expected 4 results, got %d", len(results))
	}

	// express: MIT via id
	if results[0].Name != "express" || results[0].License.SPDXID != "MIT" {
		t.Errorf("result[0] = %+v, expected express/MIT", results[0])
	}

	// lodash: MIT via name normalization
	if results[1].Name != "lodash" || results[1].License.SPDXID != "MIT" {
		t.Errorf("result[1] = %+v, expected lodash/MIT", results[1])
	}

	// dual-licensed: expression "MIT OR Apache-2.0" (kept as-is since it's a compound expression)
	if results[2].Name != "dual-licensed" {
		t.Errorf("result[2].Name = %q, expected dual-licensed", results[2].Name)
	}

	// no-license: unknown
	if results[3].Name != "no-license" || results[3].License.Category != Unknown {
		t.Errorf("result[3] = %+v, expected no-license/Unknown", results[3])
	}
}

func TestExtractFromCycloneDX_MultiLicense(t *testing.T) {
	raw := []byte(`{
		"bomFormat": "CycloneDX",
		"components": [
			{
				"type": "library",
				"name": "multi-pkg",
				"version": "1.0.0",
				"purl": "pkg:npm/multi-pkg@1.0.0",
				"licenses": [
					{"license": {"id": "MIT"}},
					{"license": {"id": "Apache-2.0"}}
				]
			}
		]
	}`)

	results, err := ExtractFromCycloneDX(raw)
	if err != nil {
		t.Fatalf("ExtractFromCycloneDX: %v", err)
	}

	// Multi-license produces multiple entries
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	if results[0].License.SPDXID != "MIT" {
		t.Errorf("result[0].License.SPDXID = %q, want MIT", results[0].License.SPDXID)
	}
	if results[1].License.SPDXID != "Apache-2.0" {
		t.Errorf("result[1].License.SPDXID = %q, want Apache-2.0", results[1].License.SPDXID)
	}
}

func TestExtractFromSPDX(t *testing.T) {
	raw := []byte(`{
		"spdxVersion": "SPDX-2.3",
		"packages": [
			{
				"name": "express",
				"versionInfo": "4.18.2",
				"licenseConcluded": "MIT",
				"licenseDeclared": "MIT",
				"externalRefs": [
					{
						"referenceCategory": "PACKAGE-MANAGER",
						"referenceType": "purl",
						"referenceLocator": "pkg:npm/express@4.18.2"
					}
				]
			},
			{
				"name": "gpl-pkg",
				"versionInfo": "1.0.0",
				"licenseConcluded": "GPL-3.0-only",
				"licenseDeclared": "GPL-3.0-only",
				"externalRefs": [
					{
						"referenceCategory": "PACKAGE-MANAGER",
						"referenceType": "purl",
						"referenceLocator": "pkg:npm/gpl-pkg@1.0.0"
					}
				]
			},
			{
				"name": "unknown-pkg",
				"versionInfo": "0.1.0",
				"licenseConcluded": "NOASSERTION",
				"licenseDeclared": "NOASSERTION",
				"externalRefs": [
					{
						"referenceCategory": "PACKAGE-MANAGER",
						"referenceType": "purl",
						"referenceLocator": "pkg:npm/unknown-pkg@0.1.0"
					}
				]
			}
		]
	}`)

	results, err := ExtractFromSPDX(raw)
	if err != nil {
		t.Fatalf("ExtractFromSPDX: %v", err)
	}

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	// express: MIT
	if results[0].License.SPDXID != "MIT" {
		t.Errorf("result[0].License.SPDXID = %q, want MIT", results[0].License.SPDXID)
	}
	if results[0].Purl != "pkg:npm/express@4.18.2" {
		t.Errorf("result[0].Purl = %q, want pkg:npm/express@4.18.2", results[0].Purl)
	}

	// gpl-pkg: GPL-3.0-only
	if results[1].License.SPDXID != "GPL-3.0-only" {
		t.Errorf("result[1].License.SPDXID = %q, want GPL-3.0-only", results[1].License.SPDXID)
	}

	// unknown-pkg: NOASSERTION -> Unknown
	if results[2].License.Category != Unknown {
		t.Errorf("result[2].License.Category = %q, want Unknown", results[2].License.Category)
	}
}

func TestExtractFromSPDX_FallbackToDeclared(t *testing.T) {
	raw := []byte(`{
		"spdxVersion": "SPDX-2.3",
		"packages": [
			{
				"name": "fallback-pkg",
				"versionInfo": "1.0.0",
				"licenseConcluded": "NOASSERTION",
				"licenseDeclared": "Apache-2.0",
				"externalRefs": [
					{
						"referenceCategory": "PACKAGE-MANAGER",
						"referenceType": "purl",
						"referenceLocator": "pkg:npm/fallback-pkg@1.0.0"
					}
				]
			}
		]
	}`)

	results, err := ExtractFromSPDX(raw)
	if err != nil {
		t.Fatalf("ExtractFromSPDX: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if results[0].License.SPDXID != "Apache-2.0" {
		t.Errorf("result[0].License.SPDXID = %q, want Apache-2.0", results[0].License.SPDXID)
	}
}

func TestExtractFromCycloneDX_InvalidJSON(t *testing.T) {
	_, err := ExtractFromCycloneDX([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

func TestExtractFromSPDX_InvalidJSON(t *testing.T) {
	_, err := ExtractFromSPDX([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}
