// Package credentials provides local credential storage for the mayu CLI.
// Credentials are stored at ~/.config/mayu/credentials.json with restricted
// file permissions (0600) to protect session tokens.
package credentials

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// Credentials holds the stored authentication information for the CLI.
type Credentials struct {
	ServerURL    string    `json:"server_url"`
	SessionToken string    `json:"session_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// credentialsDir is the directory name under the user's config path.
// This can be overridden in tests.
var credentialsDir string

// SetDir overrides the credentials directory (for testing).
// Pass an empty string to reset to the default.
func SetDir(dir string) {
	credentialsDir = dir
}

// Path returns the path to the credentials file.
func Path() string {
	if credentialsDir != "" {
		return filepath.Join(credentialsDir, "credentials.json")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "mayu", "credentials.json")
}

// Load reads the credentials file and returns the stored credentials.
// Returns nil and no error if the file does not exist.
func Load() (*Credentials, error) {
	p := Path()
	if p == "" {
		return nil, errors.New("cannot determine credentials path")
	}

	data, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	var creds Credentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, err
	}
	return &creds, nil
}

// Save writes the credentials to the credentials file with restricted permissions.
func Save(creds *Credentials) error {
	p := Path()
	if p == "" {
		return errors.New("cannot determine credentials path")
	}

	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(p, data, 0600)
}

// Delete removes the credentials file.
// Returns nil if the file does not exist.
func Delete() error {
	p := Path()
	if p == "" {
		return errors.New("cannot determine credentials path")
	}

	err := os.Remove(p)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
