package credentials

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	SetDir(dir)
	defer SetDir("")

	creds := &Credentials{
		ServerURL:    "http://localhost:8080",
		SessionToken: "test-session-token-123",
		ExpiresAt:    time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC),
	}

	if err := Save(creds); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	// Verify file permissions
	info, err := os.Stat(Path())
	if err != nil {
		t.Fatalf("Stat() error: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("file permissions = %o, want 0600", perm)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if loaded == nil {
		t.Fatal("Load() returned nil")
	}
	if loaded.ServerURL != creds.ServerURL {
		t.Errorf("ServerURL = %q, want %q", loaded.ServerURL, creds.ServerURL)
	}
	if loaded.SessionToken != creds.SessionToken {
		t.Errorf("SessionToken = %q, want %q", loaded.SessionToken, creds.SessionToken)
	}
	if !loaded.ExpiresAt.Equal(creds.ExpiresAt) {
		t.Errorf("ExpiresAt = %v, want %v", loaded.ExpiresAt, creds.ExpiresAt)
	}
}

func TestLoadMissingFile(t *testing.T) {
	dir := t.TempDir()
	SetDir(dir)
	defer SetDir("")

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if loaded != nil {
		t.Errorf("Load() = %v, want nil for missing file", loaded)
	}
}

func TestDelete(t *testing.T) {
	dir := t.TempDir()
	SetDir(dir)
	defer SetDir("")

	creds := &Credentials{
		ServerURL:    "http://localhost:8080",
		SessionToken: "to-delete",
		ExpiresAt:    time.Now().Add(time.Hour),
	}

	if err := Save(creds); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	if err := Delete(); err != nil {
		t.Fatalf("Delete() error: %v", err)
	}

	// Verify file is gone
	if _, err := os.Stat(Path()); !os.IsNotExist(err) {
		t.Error("credentials file still exists after Delete()")
	}

	// Load should return nil after delete
	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load() after Delete() error: %v", err)
	}
	if loaded != nil {
		t.Errorf("Load() after Delete() = %v, want nil", loaded)
	}
}

func TestDeleteMissingFile(t *testing.T) {
	dir := t.TempDir()
	SetDir(dir)
	defer SetDir("")

	// Deleting when file doesn't exist should succeed
	if err := Delete(); err != nil {
		t.Fatalf("Delete() on missing file error: %v", err)
	}
}

func TestPath(t *testing.T) {
	dir := t.TempDir()
	SetDir(dir)
	defer SetDir("")

	want := filepath.Join(dir, "credentials.json")
	got := Path()
	if got != want {
		t.Errorf("Path() = %q, want %q", got, want)
	}
}

func TestSaveCreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "nested", "dir")
	SetDir(nested)
	defer SetDir("")

	creds := &Credentials{
		ServerURL:    "http://localhost:8080",
		SessionToken: "test",
		ExpiresAt:    time.Now().Add(time.Hour),
	}

	if err := Save(creds); err != nil {
		t.Fatalf("Save() with nested dir error: %v", err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if loaded == nil {
		t.Fatal("Load() returned nil")
	}
	if loaded.SessionToken != "test" {
		t.Errorf("SessionToken = %q, want %q", loaded.SessionToken, "test")
	}
}
