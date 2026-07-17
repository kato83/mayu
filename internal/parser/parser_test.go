package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParse_ValidData(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "testdata", "GO-*.json"))
	if err != nil {
		t.Fatalf("failed to glob testdata: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no test files found")
	}

	p := New()

	for _, file := range files {
		name := filepath.Base(file)
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("failed to read %s: %v", file, err)
			}

			vuln, err := p.Parse(data)
			if err != nil {
				t.Fatalf("Parse failed: %v", err)
			}

			// Verify required fields
			if vuln.ID == "" {
				t.Error("ID is empty")
			}
			if vuln.Modified.IsZero() {
				t.Error("Modified is zero")
			}

			// Verify RawJSON is preserved
			if vuln.RawJSON == nil {
				t.Error("RawJSON is nil")
			}

			// Verify affected packages are parsed
			if len(vuln.Affected) == 0 {
				t.Error("Affected is empty")
			}
			for i, a := range vuln.Affected {
				if a.Package.Ecosystem == "" {
					t.Errorf("Affected[%d].Package.Ecosystem is empty", i)
				}
				if a.Package.Name == "" {
					t.Errorf("Affected[%d].Package.Name is empty", i)
				}
			}
		})
	}
}

func TestParse_EmptyData(t *testing.T) {
	p := New()
	_, err := p.Parse([]byte{})
	if err == nil {
		t.Error("expected error for empty data, got nil")
	}
}

func TestParse_InvalidJSON(t *testing.T) {
	p := New()
	_, err := p.Parse([]byte(`{invalid json`))
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

func TestParse_MissingID(t *testing.T) {
	p := New()
	data := []byte(`{"modified":"2024-01-01T00:00:00Z","summary":"no id"}`)
	_, err := p.Parse(data)
	if err == nil {
		t.Error("expected error for missing id, got nil")
	}
}

func TestParse_MissingModified(t *testing.T) {
	p := New()
	data := []byte(`{"id":"TEST-0001","summary":"no modified"}`)
	_, err := p.Parse(data)
	if err == nil {
		t.Error("expected error for missing modified, got nil")
	}
}

func TestParse_MinimalValid(t *testing.T) {
	p := New()
	data := []byte(`{"id":"TEST-0001","modified":"2024-01-01T00:00:00Z"}`)
	vuln, err := p.Parse(data)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if vuln.ID != "TEST-0001" {
		t.Errorf("ID = %q, want TEST-0001", vuln.ID)
	}
}

func TestParseBatch_MixedValidity(t *testing.T) {
	p := New()

	files := map[string][]byte{
		"valid1.json":  []byte(`{"id":"TEST-0001","modified":"2024-01-01T00:00:00Z","summary":"valid"}`),
		"valid2.json":  []byte(`{"id":"TEST-0002","modified":"2024-02-01T00:00:00Z","summary":"also valid"}`),
		"invalid.json": []byte(`{not valid json`),
		"no_id.json":   []byte(`{"modified":"2024-01-01T00:00:00Z"}`),
		"empty.json":   []byte(``),
	}

	result, err := p.ParseBatch(files)
	if err != nil {
		t.Fatalf("ParseBatch failed: %v", err)
	}

	if len(result.Vulnerabilities) != 2 {
		t.Errorf("expected 2 valid vulnerabilities, got %d", len(result.Vulnerabilities))
	}
	if len(result.Errors) != 3 {
		t.Errorf("expected 3 errors, got %d", len(result.Errors))
	}
}

func TestParseBatch_StrictMode(t *testing.T) {
	p := New()
	p.Strict = true

	files := map[string][]byte{
		"valid.json":   []byte(`{"id":"TEST-0001","modified":"2024-01-01T00:00:00Z"}`),
		"invalid.json": []byte(`{not valid`),
	}

	_, err := p.ParseBatch(files)
	if err == nil {
		t.Error("expected error in strict mode, got nil")
	}
}

func TestParseBatch_WithRealData(t *testing.T) {
	testFiles, err := filepath.Glob(filepath.Join("..", "..", "testdata", "GO-*.json"))
	if err != nil {
		t.Fatalf("failed to glob testdata: %v", err)
	}

	files := make(map[string][]byte)
	for _, f := range testFiles {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("failed to read %s: %v", f, err)
		}
		files[filepath.Base(f)] = data
	}

	p := New()
	result, err := p.ParseBatch(files)
	if err != nil {
		t.Fatalf("ParseBatch failed: %v", err)
	}

	if len(result.Vulnerabilities) != len(testFiles) {
		t.Errorf("expected %d vulnerabilities, got %d", len(testFiles), len(result.Vulnerabilities))
	}
	if len(result.Errors) != 0 {
		t.Errorf("expected 0 errors, got %d", len(result.Errors))
		for _, e := range result.Errors {
			t.Logf("  %s: %v", e.ID, e.Error)
		}
	}
}
