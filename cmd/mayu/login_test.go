package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kato83/mayu/internal/credentials"
)

func TestRunLogin_OIDCWithoutConfig(t *testing.T) {
	cfg := makeTestConfig()
	cfg.Auth.Mode = "local"

	err := runLogin([]string{"--oidc"}, cfg)
	if err == nil {
		t.Fatal("expected error for OIDC login without oidc mode, got nil")
	}
	want := "OIDC login requires auth.mode to be 'oidc' in config"
	if err.Error() != want {
		t.Errorf("got error %q, want %q", err.Error(), want)
	}
}

func TestRunLogin_OIDCMissingIssuer(t *testing.T) {
	cfg := makeTestConfig()
	cfg.Auth.Mode = "oidc"
	cfg.Auth.OIDC.Issuer = ""

	err := runLogin([]string{"--oidc"}, cfg)
	if err == nil {
		t.Fatal("expected error for OIDC login without issuer, got nil")
	}
	want := "OIDC issuer is not configured (set auth.oidc.issuer in config)"
	if err.Error() != want {
		t.Errorf("got error %q, want %q", err.Error(), want)
	}
}

func TestRunLogin_OIDCMissingClientID(t *testing.T) {
	cfg := makeTestConfig()
	cfg.Auth.Mode = "oidc"
	cfg.Auth.OIDC.Issuer = "https://example.com"
	cfg.Auth.OIDC.ClientID = ""

	err := runLogin([]string{"--oidc"}, cfg)
	if err == nil {
		t.Fatal("expected error for OIDC login without client_id, got nil")
	}
	want := "OIDC client_id is not configured (set auth.oidc.client_id in config)"
	if err.Error() != want {
		t.Errorf("got error %q, want %q", err.Error(), want)
	}
}

func TestRunLogout_NoCredentials(t *testing.T) {
	dir := t.TempDir()
	credentials.SetDir(dir)
	defer credentials.SetDir("")

	cfg := makeTestConfig()

	err := runLogout([]string{}, cfg)
	if err != nil {
		t.Fatalf("runLogout() with no credentials error: %v", err)
	}
}

func TestRunLogout_WithCredentials(t *testing.T) {
	dir := t.TempDir()
	credentials.SetDir(dir)
	defer credentials.SetDir("")

	// Save some credentials first
	creds := &credentials.Credentials{
		ServerURL:    "http://localhost:8080",
		SessionToken: "test-session-token",
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	if err := credentials.Save(creds); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	cfg := makeTestConfig()

	err := runLogout([]string{}, cfg)
	if err != nil {
		t.Fatalf("runLogout() error: %v", err)
	}

	// Verify credentials file is gone
	credPath := filepath.Join(dir, "credentials.json")
	if _, err := os.Stat(credPath); !os.IsNotExist(err) {
		t.Error("credentials file still exists after logout")
	}
}

func TestResolveAuthUser_NoAuthAvailable(t *testing.T) {
	dir := t.TempDir()
	credentials.SetDir(dir)
	defer credentials.SetDir("")

	// Ensure MAYU_API_KEY is not set
	old := os.Getenv("MAYU_API_KEY")
	os.Unsetenv("MAYU_API_KEY")
	defer func() {
		if old != "" {
			os.Setenv("MAYU_API_KEY", old)
		}
	}()

	cfg := makeTestConfig()
	ctx := t.Context()

	_, _, err := resolveAuthUser(ctx, cfg)
	if err == nil {
		t.Fatal("expected error when no auth available, got nil")
	}
	want := "authentication required: set MAYU_API_KEY environment variable or run 'mayu login'"
	if err.Error() != want {
		t.Errorf("got error %q, want %q", err.Error(), want)
	}
}

func TestResolveAuthUser_ExpiredCredentials(t *testing.T) {
	dir := t.TempDir()
	credentials.SetDir(dir)
	defer credentials.SetDir("")

	// Save expired credentials
	creds := &credentials.Credentials{
		ServerURL:    "http://localhost:8080",
		SessionToken: "expired-token",
		ExpiresAt:    time.Now().Add(-time.Hour),
	}
	if err := credentials.Save(creds); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	// Ensure MAYU_API_KEY is not set
	old := os.Getenv("MAYU_API_KEY")
	os.Unsetenv("MAYU_API_KEY")
	defer func() {
		if old != "" {
			os.Setenv("MAYU_API_KEY", old)
		}
	}()

	cfg := makeTestConfig()
	ctx := t.Context()

	_, _, err := resolveAuthUser(ctx, cfg)
	if err == nil {
		t.Fatal("expected error with expired credentials, got nil")
	}
	want := "authentication required: set MAYU_API_KEY environment variable or run 'mayu login'"
	if err.Error() != want {
		t.Errorf("got error %q, want %q", err.Error(), want)
	}
}
