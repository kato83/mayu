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

func TestLoad_AuthModeLocal(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	content := []byte(`database_url: postgres://localhost/test
auth:
  mode: local
  session_secret: my-secret-key
  session_max_age: 3600
`)
	if err := os.WriteFile(cfgPath, content, 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath, true)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Auth.Mode != "local" {
		t.Errorf("Auth.Mode = %q, want %q", cfg.Auth.Mode, "local")
	}
	if cfg.Auth.SessionSecret != "my-secret-key" {
		t.Errorf("Auth.SessionSecret = %q, want %q", cfg.Auth.SessionSecret, "my-secret-key")
	}
	if cfg.Auth.SessionMaxAge != 3600 {
		t.Errorf("Auth.SessionMaxAge = %d, want %d", cfg.Auth.SessionMaxAge, 3600)
	}
}

func TestLoad_AuthModeOIDC(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	content := []byte(`database_url: postgres://localhost/test
auth:
  mode: oidc
  session_secret: oidc-secret
  session_max_age: 7200
  oidc:
    issuer: https://accounts.example.com
    client_id: my-client-id
    client_secret: my-client-secret
    redirect_url: http://localhost:8080/auth/callback
    scopes:
      - openid
      - profile
      - email
`)
	if err := os.WriteFile(cfgPath, content, 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath, true)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Auth.Mode != "oidc" {
		t.Errorf("Auth.Mode = %q, want %q", cfg.Auth.Mode, "oidc")
	}
	if cfg.Auth.OIDC.Issuer != "https://accounts.example.com" {
		t.Errorf("Auth.OIDC.Issuer = %q, want %q", cfg.Auth.OIDC.Issuer, "https://accounts.example.com")
	}
	if cfg.Auth.OIDC.ClientID != "my-client-id" {
		t.Errorf("Auth.OIDC.ClientID = %q, want %q", cfg.Auth.OIDC.ClientID, "my-client-id")
	}
	if cfg.Auth.OIDC.ClientSecret != "my-client-secret" {
		t.Errorf("Auth.OIDC.ClientSecret = %q, want %q", cfg.Auth.OIDC.ClientSecret, "my-client-secret")
	}
	if cfg.Auth.OIDC.RedirectURL != "http://localhost:8080/auth/callback" {
		t.Errorf("Auth.OIDC.RedirectURL = %q, want %q", cfg.Auth.OIDC.RedirectURL, "http://localhost:8080/auth/callback")
	}
	expectedScopes := []string{"openid", "profile", "email"}
	if len(cfg.Auth.OIDC.Scopes) != len(expectedScopes) {
		t.Fatalf("Auth.OIDC.Scopes length = %d, want %d", len(cfg.Auth.OIDC.Scopes), len(expectedScopes))
	}
	for i, s := range cfg.Auth.OIDC.Scopes {
		if s != expectedScopes[i] {
			t.Errorf("Auth.OIDC.Scopes[%d] = %q, want %q", i, s, expectedScopes[i])
		}
	}
}

func TestLoad_AuthModeNone(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	content := []byte(`database_url: postgres://localhost/test
auth:
  mode: none
`)
	if err := os.WriteFile(cfgPath, content, 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath, true)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Auth.Mode != "none" {
		t.Errorf("Auth.Mode = %q, want %q", cfg.Auth.Mode, "none")
	}
}

func TestLoad_AuthModeEmpty(t *testing.T) {
	// When auth mode is not specified, the zero value (empty string) is returned.
	// Callers should treat empty as "none".
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	content := []byte(`database_url: postgres://localhost/test
`)
	if err := os.WriteFile(cfgPath, content, 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath, true)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Auth.Mode != "" {
		t.Errorf("Auth.Mode = %q, want empty string (treated as none)", cfg.Auth.Mode)
	}
	if cfg.Auth.SessionMaxAge != 0 {
		t.Errorf("Auth.SessionMaxAge = %d, want 0 (zero value)", cfg.Auth.SessionMaxAge)
	}
}
