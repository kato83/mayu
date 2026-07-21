package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultPath(t *testing.T) {
	path := DefaultPath()
	if path == "" {
		t.Skip("cannot determine home directory")
	}
	// Should end with the expected suffix
	expected := filepath.Join(".config", "mayu", "config.yaml")
	if !containsSuffix(path, expected) {
		t.Errorf("DefaultPath() = %q, want suffix %q", path, expected)
	}
}

func containsSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

func TestLoad_ValidFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	content := []byte("database_url: postgres://user:pass@host:5432/db?sslmode=require\n")
	if err := os.WriteFile(cfgPath, content, 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath, true)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.DatabaseURL != "postgres://user:pass@host:5432/db?sslmode=require" {
		t.Errorf("DatabaseURL = %q, want %q", cfg.DatabaseURL, "postgres://user:pass@host:5432/db?sslmode=require")
	}
}

func TestLoad_MissingFile_NotExplicit(t *testing.T) {
	// When explicit=false, a missing file should not cause an error.
	cfg, err := Load("/nonexistent/path/config.yaml", false)
	if err != nil {
		t.Fatalf("Load() error = %v, want nil for non-explicit missing file", err)
	}
	if cfg.DatabaseURL != "" {
		t.Errorf("DatabaseURL = %q, want empty", cfg.DatabaseURL)
	}
}

func TestLoad_MissingFile_Explicit(t *testing.T) {
	// When explicit=true, a missing file should cause an error.
	_, err := Load("/nonexistent/path/config.yaml", true)
	if err == nil {
		t.Fatal("Load() error = nil, want error for explicit missing file")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	// Invalid YAML (tab indentation with bad structure)
	content := []byte("database_url: [invalid\n")
	if err := os.WriteFile(cfgPath, content, 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(cfgPath, false)
	if err == nil {
		t.Fatal("Load() error = nil, want error for invalid YAML")
	}
}

func TestLoad_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath, true)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.DatabaseURL != "" {
		t.Errorf("DatabaseURL = %q, want empty for empty file", cfg.DatabaseURL)
	}
}

func TestLoad_ExtraFields(t *testing.T) {
	// Unknown fields should be silently ignored.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	content := []byte("database_url: postgres://localhost/test\nunknown_field: value\n")
	if err := os.WriteFile(cfgPath, content, 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath, true)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.DatabaseURL != "postgres://localhost/test" {
		t.Errorf("DatabaseURL = %q, want %q", cfg.DatabaseURL, "postgres://localhost/test")
	}
}
