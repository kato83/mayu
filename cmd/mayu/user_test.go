package main

import (
	"testing"

	"github.com/kato83/mayu/internal/config"
)

// makeTestConfig returns a minimal config for testing CLI argument parsing.
// It uses localhost with a port that should not have PostgreSQL running,
// so DB connection attempts fail quickly rather than hanging.
func makeTestConfig() *config.Config {
	return &config.Config{
		DatabaseURL: "postgres://test:test@localhost:59999/test?sslmode=disable&connect_timeout=1",
	}
}

func TestRunUserCreate_MissingEmail(t *testing.T) {
	cfg := makeTestConfig()

	err := runUserCreate([]string{"--password", "secret"}, cfg)
	if err == nil {
		t.Fatal("expected error for missing --email, got nil")
	}
	if want := "--email is required"; err.Error() != want {
		t.Errorf("got error %q, want %q", err.Error(), want)
	}
}

func TestRunUserCreate_InvalidRole(t *testing.T) {
	cfg := makeTestConfig()

	err := runUserCreate([]string{
		"--email", "test@example.com",
		"--role", "superuser",
		"--password", "secret",
	}, cfg)
	if err == nil {
		t.Fatal("expected error for invalid role, got nil")
	}
	if want := `invalid role "superuser": must be 'admin' or 'viewer'`; err.Error() != want {
		t.Errorf("got error %q, want %q", err.Error(), want)
	}
}

func TestRunUserCreate_MissingPassword(t *testing.T) {
	cfg := makeTestConfig()

	err := runUserCreate([]string{
		"--email", "test@example.com",
		"--role", "admin",
	}, cfg)
	if err == nil {
		t.Fatal("expected error for missing --password, got nil")
	}
	if want := "--password is required"; err.Error() != want {
		t.Errorf("got error %q, want %q", err.Error(), want)
	}
}

func TestRunUserCreate_ValidRoles(t *testing.T) {
	// Valid roles (case-insensitive) should not produce a role validation error.
	// We verify by checking the error message is NOT about role validation.
	// These will fail at DB connection which is expected.
	cfg := makeTestConfig()

	for _, role := range []string{"admin", "viewer", "Admin", "VIEWER"} {
		err := runUserCreate([]string{
			"--email", "test@example.com",
			"--role", role,
			"--password", "secret",
		}, cfg)
		// We expect an error (DB connection), but it should NOT be a role error
		if err != nil {
			got := err.Error()
			if containsSubstr(got, "invalid role") {
				t.Errorf("role %q incorrectly rejected", role)
			}
		}
	}
}

func TestRunUser_NoSubcommand(t *testing.T) {
	cfg := makeTestConfig()

	err := runUser([]string{}, cfg)
	if err == nil {
		t.Fatal("expected error for no subcommand, got nil")
	}
	if want := "no subcommand specified (use 'create', 'list', 'update', or 'reset-password')"; err.Error() != want {
		t.Errorf("got error %q, want %q", err.Error(), want)
	}
}

func TestRunUser_UnknownSubcommand(t *testing.T) {
	cfg := makeTestConfig()

	err := runUser([]string{"delete"}, cfg)
	if err == nil {
		t.Fatal("expected error for unknown subcommand, got nil")
	}
	if want := `unknown user subcommand: "delete" (use 'create', 'list', 'update', or 'reset-password')`; err.Error() != want {
		t.Errorf("got error %q, want %q", err.Error(), want)
	}
}

func TestRunUserUpdate_MissingEmail(t *testing.T) {
	cfg := makeTestConfig()

	err := runUserUpdate([]string{"--role", "admin"}, cfg)
	if err == nil {
		t.Fatal("expected error for missing --email, got nil")
	}
	if want := "--email is required"; err.Error() != want {
		t.Errorf("got error %q, want %q", err.Error(), want)
	}
}

func TestRunUserUpdate_MissingRole(t *testing.T) {
	cfg := makeTestConfig()

	err := runUserUpdate([]string{"--email", "test@example.com"}, cfg)
	if err == nil {
		t.Fatal("expected error for missing --role, got nil")
	}
	if want := "--role is required"; err.Error() != want {
		t.Errorf("got error %q, want %q", err.Error(), want)
	}
}

func TestRunUserUpdate_InvalidRole(t *testing.T) {
	cfg := makeTestConfig()

	err := runUserUpdate([]string{
		"--email", "test@example.com",
		"--role", "superuser",
	}, cfg)
	if err == nil {
		t.Fatal("expected error for invalid role, got nil")
	}
	if want := `invalid role "superuser": must be 'admin' or 'viewer'`; err.Error() != want {
		t.Errorf("got error %q, want %q", err.Error(), want)
	}
}

func TestRunUserResetPassword_NonLocalMode(t *testing.T) {
	tests := []struct {
		name string
		mode string
		want string
	}{
		{"none mode", "", "reset-password is only available when auth.mode=local (current mode: none)"},
		{"none explicit", "none", "reset-password is only available when auth.mode=local (current mode: none)"},
		{"oidc mode", "oidc", "reset-password is only available when auth.mode=local (current mode: oidc)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := makeTestConfig()
			cfg.Auth.Mode = tt.mode

			err := runUserResetPassword([]string{"--email", "test@example.com", "--password", "newpass"}, cfg)
			if err == nil {
				t.Fatal("expected error for non-local mode, got nil")
			}
			if err.Error() != tt.want {
				t.Errorf("got error %q, want %q", err.Error(), tt.want)
			}
		})
	}
}

func TestRunUserResetPassword_MissingEmail(t *testing.T) {
	cfg := makeTestConfig()
	cfg.Auth.Mode = "local"

	err := runUserResetPassword([]string{"--password", "newpass"}, cfg)
	if err == nil {
		t.Fatal("expected error for missing --email, got nil")
	}
	if want := "--email is required"; err.Error() != want {
		t.Errorf("got error %q, want %q", err.Error(), want)
	}
}

func TestRunUserResetPassword_MissingPassword(t *testing.T) {
	cfg := makeTestConfig()
	cfg.Auth.Mode = "local"

	err := runUserResetPassword([]string{"--email", "test@example.com"}, cfg)
	if err == nil {
		t.Fatal("expected error for missing --password, got nil")
	}
	if want := "--password is required"; err.Error() != want {
		t.Errorf("got error %q, want %q", err.Error(), want)
	}
}

func TestRunAPIKey_NoSubcommand(t *testing.T) {
	cfg := makeTestConfig()

	err := runAPIKey([]string{}, cfg)
	if err == nil {
		t.Fatal("expected error for no subcommand, got nil")
	}
	if want := "no subcommand specified (use 'create')"; err.Error() != want {
		t.Errorf("got error %q, want %q", err.Error(), want)
	}
}

func TestRunAPIKey_UnknownSubcommand(t *testing.T) {
	cfg := makeTestConfig()

	err := runAPIKey([]string{"revoke"}, cfg)
	if err == nil {
		t.Fatal("expected error for unknown subcommand, got nil")
	}
	if want := `unknown apikey subcommand: "revoke" (use 'create')`; err.Error() != want {
		t.Errorf("got error %q, want %q", err.Error(), want)
	}
}

func TestRunAPIKeyCreate_MissingUserEmail(t *testing.T) {
	cfg := makeTestConfig()

	err := runAPIKeyCreate([]string{"--name", "CI"}, cfg)
	if err == nil {
		t.Fatal("expected error for missing --user-email, got nil")
	}
	if want := "--user-email is required"; err.Error() != want {
		t.Errorf("got error %q, want %q", err.Error(), want)
	}
}

func TestRunAPIKeyCreate_InvalidExpires(t *testing.T) {
	cfg := makeTestConfig()

	err := runAPIKeyCreate([]string{
		"--user-email", "test@example.com",
		"--expires", "abc",
	}, cfg)
	if err == nil {
		t.Fatal("expected error for invalid --expires, got nil")
	}
	// Should contain "invalid --expires"
	if got := err.Error(); !contains(got, "invalid --expires") {
		t.Errorf("got error %q, expected it to contain 'invalid --expires'", got)
	}
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		wantH   float64 // approximate hours
	}{
		{"days", "90d", false, 90 * 24},
		{"year", "1y", false, 365 * 24},
		{"hours", "24h", false, 24},
		{"minutes", "30m", false, 0.5},
		{"empty", "", true, 0},
		{"invalid suffix", "90x", true, 0},
		{"no number", "d", true, 0},
		{"negative", "-5d", true, 0},
		{"zero", "0d", true, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := parseDuration(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseDuration(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				gotH := d.Hours()
				if gotH != tt.wantH {
					t.Errorf("parseDuration(%q) = %v hours, want %v hours", tt.input, gotH, tt.wantH)
				}
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
