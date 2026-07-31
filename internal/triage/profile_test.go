package triage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultProfile(t *testing.T) {
	p := DefaultProfile()
	if p.Name != "default" {
		t.Errorf("expected name 'default', got %q", p.Name)
	}
	if p.Weights == nil {
		t.Fatal("expected non-nil weights")
	}
	if p.Thresholds == nil {
		t.Fatal("expected non-nil thresholds")
	}
}

func TestBuiltinTemplates(t *testing.T) {
	templates := BuiltinTemplates()
	if len(templates) != 4 {
		t.Errorf("expected 4 templates, got %d", len(templates))
	}

	expectedNames := []string{"default", "internet-facing", "internal-only", "air-gapped"}
	for i, tmpl := range templates {
		if tmpl.Name != expectedNames[i] {
			t.Errorf("expected template[%d] name %q, got %q", i, expectedNames[i], tmpl.Name)
		}
	}
}

func TestLoadProfile(t *testing.T) {
	yamlContent := `
name: "test-profile"
description: "Test profile"
weights:
  cvss: 0.20
  epss: 0.20
  lev: 0.15
  kev: 0.15
  patch: 0.08
  age: 0.05
  exploitdb: 0.10
  reachability: 0.07
thresholds:
  critical: 0.85
  high: 0.65
  medium: 0.40
`

	dir := t.TempDir()
	path := filepath.Join(dir, "test-profile.yaml")
	if err := os.WriteFile(path, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	profile, err := LoadProfile(path)
	if err != nil {
		t.Fatalf("LoadProfile failed: %v", err)
	}

	if profile.Name != "test-profile" {
		t.Errorf("expected name 'test-profile', got %q", profile.Name)
	}
	if profile.Weights.CVSS != 0.20 {
		t.Errorf("expected CVSS weight 0.20, got %f", profile.Weights.CVSS)
	}
	if profile.Thresholds.Critical != 0.85 {
		t.Errorf("expected critical threshold 0.85, got %f", profile.Thresholds.Critical)
	}
}

func TestParseProfile_InvalidYAML(t *testing.T) {
	_, err := ParseProfile([]byte("invalid: [yaml"))
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestParseProfile_WithBaseTemplate(t *testing.T) {
	yamlContent := `
name: "custom"
description: "Custom profile based on default"
base: "default"
`
	profile, err := ParseProfile([]byte(yamlContent))
	if err != nil {
		t.Fatalf("ParseProfile failed: %v", err)
	}

	// Should inherit weights and thresholds from default
	if profile.Weights == nil {
		t.Fatal("expected inherited weights from base")
	}
	if profile.Thresholds == nil {
		t.Fatal("expected inherited thresholds from base")
	}
}

func TestParseProfile_UnknownBase(t *testing.T) {
	yamlContent := `
name: "custom"
base: "nonexistent"
`
	_, err := ParseProfile([]byte(yamlContent))
	if err == nil {
		t.Error("expected error for unknown base template")
	}
}
