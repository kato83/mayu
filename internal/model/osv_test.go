package model

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestVulnerabilityRoundtrip verifies that OSV JSON can be unmarshaled into
// our Go structs and marshaled back without losing any data.
// Test data is sourced from the GCS bucket: gs://osv-vulnerabilities/Go/
func TestVulnerabilityRoundtrip(t *testing.T) {
	testFiles, err := filepath.Glob(filepath.Join("..", "..", "testdata", "GO-*.json"))
	if err != nil {
		t.Fatalf("failed to glob testdata: %v", err)
	}
	if len(testFiles) == 0 {
		t.Fatal("no test files found in testdata/")
	}

	for _, file := range testFiles {
		name := filepath.Base(file)
		t.Run(name, func(t *testing.T) {
			// Read original JSON
			original, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("failed to read %s: %v", file, err)
			}

			// Unmarshal into our struct
			var vuln Vulnerability
			if err := json.Unmarshal(original, &vuln); err != nil {
				t.Fatalf("failed to unmarshal %s: %v", name, err)
			}

			// Verify required fields are populated
			if vuln.ID == "" {
				t.Error("ID is empty after unmarshal")
			}
			if vuln.Modified.IsZero() {
				t.Error("Modified is zero after unmarshal")
			}

			// Marshal back to JSON
			marshaled, err := json.Marshal(&vuln)
			if err != nil {
				t.Fatalf("failed to marshal %s: %v", name, err)
			}

			// Compare by unmarshaling both into generic maps
			var originalMap, marshaledMap map[string]interface{}
			if err := json.Unmarshal(original, &originalMap); err != nil {
				t.Fatalf("failed to unmarshal original to map: %v", err)
			}
			if err := json.Unmarshal(marshaled, &marshaledMap); err != nil {
				t.Fatalf("failed to unmarshal marshaled to map: %v", err)
			}

			// Re-marshal both maps with sorted keys for stable comparison
			originalNorm, _ := json.Marshal(originalMap)
			marshaledNorm, _ := json.Marshal(marshaledMap)

			if string(originalNorm) != string(marshaledNorm) {
				t.Errorf("roundtrip mismatch for %s", name)
				t.Logf("original length: %d, marshaled length: %d", len(originalNorm), len(marshaledNorm))

				// Find divergence point for debugging
				minLen := len(originalNorm)
				if len(marshaledNorm) < minLen {
					minLen = len(marshaledNorm)
				}
				for i := 0; i < minLen; i++ {
					if originalNorm[i] != marshaledNorm[i] {
						start := i - 50
						if start < 0 {
							start = 0
						}
						end := i + 50
						if end > minLen {
							end = minLen
						}
						t.Logf("first diff at byte %d", i)
						t.Logf("original:  ...%s...", string(originalNorm[start:end]))
						t.Logf("marshaled: ...%s...", string(marshaledNorm[start:end]))
						break
					}
				}
			}
		})
	}
}

// TestParseVulnerability verifies that ParseVulnerability correctly parses
// OSV JSON and preserves the raw source in the RawJSON field.
func TestParseVulnerability(t *testing.T) {
	testFiles, err := filepath.Glob(filepath.Join("..", "..", "testdata", "GO-*.json"))
	if err != nil {
		t.Fatalf("failed to glob testdata: %v", err)
	}

	for _, file := range testFiles {
		name := filepath.Base(file)
		t.Run(name, func(t *testing.T) {
			original, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("failed to read %s: %v", file, err)
			}

			vuln, err := ParseVulnerability(original)
			if err != nil {
				t.Fatalf("ParseVulnerability failed: %v", err)
			}

			// Verify struct fields are populated
			if vuln.ID == "" {
				t.Error("ID is empty")
			}
			if vuln.Modified.IsZero() {
				t.Error("Modified is zero")
			}

			// Verify RawJSON is populated and is valid JSON
			if vuln.RawJSON == nil {
				t.Fatal("RawJSON is nil")
			}

			var rawMap map[string]interface{}
			if err := json.Unmarshal(vuln.RawJSON, &rawMap); err != nil {
				t.Fatalf("RawJSON is not valid JSON: %v", err)
			}

			// Verify RawJSON preserves all original data
			var originalMap map[string]interface{}
			if err := json.Unmarshal(original, &originalMap); err != nil {
				t.Fatalf("failed to unmarshal original: %v", err)
			}

			// Compare normalized forms (key order may differ but content must match)
			originalNorm, _ := json.Marshal(originalMap)
			rawNorm, _ := json.Marshal(rawMap)

			if string(originalNorm) != string(rawNorm) {
				t.Error("RawJSON does not preserve original data")
				t.Logf("original keys: %v", sortedKeys(originalMap))
				t.Logf("rawJSON keys:  %v", sortedKeys(rawMap))
			}

			// Verify RawJSON is excluded from JSON marshaling of the struct
			marshaled, err := json.Marshal(vuln)
			if err != nil {
				t.Fatalf("failed to marshal vuln: %v", err)
			}
			var marshaledMap map[string]interface{}
			if err := json.Unmarshal(marshaled, &marshaledMap); err != nil {
				t.Fatalf("failed to unmarshal marshaled: %v", err)
			}
			if _, exists := marshaledMap["raw_json"]; exists {
				t.Error("RawJSON should not appear in JSON output (json:\"-\" tag)")
			}
		})
	}
}

// TestVulnerabilityFields verifies specific field parsing for a known entry.
func TestVulnerabilityFields(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "GO-2024-2687.json"))
	if err != nil {
		t.Fatalf("failed to read test file: %v", err)
	}

	var vuln Vulnerability
	if err := json.Unmarshal(data, &vuln); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	// Check top-level fields
	if vuln.ID != "GO-2024-2687" {
		t.Errorf("ID = %q, want %q", vuln.ID, "GO-2024-2687")
	}
	if vuln.SchemaVersion == "" {
		t.Error("SchemaVersion is empty")
	}
	if vuln.Summary == "" {
		t.Error("Summary is empty")
	}
	if vuln.Details == "" {
		t.Error("Details is empty")
	}
	if len(vuln.Aliases) == 0 {
		t.Error("Aliases is empty")
	}
	if len(vuln.References) == 0 {
		t.Error("References is empty")
	}
	if len(vuln.Credits) == 0 {
		t.Error("Credits is empty")
	}

	// Check affected
	if len(vuln.Affected) == 0 {
		t.Fatal("Affected is empty")
	}
	affected := vuln.Affected[0]
	if affected.Package.Ecosystem != "Go" {
		t.Errorf("Package.Ecosystem = %q, want %q", affected.Package.Ecosystem, "Go")
	}
	if affected.Package.Name == "" {
		t.Error("Package.Name is empty")
	}
	if len(affected.Ranges) == 0 {
		t.Error("Ranges is empty")
	}

	// Check ranges and events
	r := affected.Ranges[0]
	if r.Type != RangeTypeSemVer && r.Type != RangeTypeEcosystem {
		t.Errorf("Range.Type = %q, want SEMVER or ECOSYSTEM", r.Type)
	}
	if len(r.Events) == 0 {
		t.Error("Events is empty")
	}
	// First event should be "introduced"
	if r.Events[0].Introduced == "" {
		t.Error("First event should have Introduced set")
	}

	// Check database_specific is preserved as raw JSON (reversibility)
	if vuln.DatabaseSpecific == nil {
		t.Error("DatabaseSpecific is nil")
	}
	var dbSpecific map[string]interface{}
	if err := json.Unmarshal(vuln.DatabaseSpecific, &dbSpecific); err != nil {
		t.Errorf("DatabaseSpecific is not valid JSON: %v", err)
	}

	// Check ecosystem_specific is preserved as raw JSON (reversibility)
	if affected.EcosystemSpecific == nil {
		t.Error("EcosystemSpecific is nil")
	}
	var ecoSpecific map[string]interface{}
	if err := json.Unmarshal(affected.EcosystemSpecific, &ecoSpecific); err != nil {
		t.Errorf("EcosystemSpecific is not valid JSON: %v", err)
	}
}

// sortedKeys returns the keys of a map in sorted order (for test output).
func sortedKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
