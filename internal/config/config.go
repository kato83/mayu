// Package config provides configuration file loading for mayu.
// It supports YAML config files with a priority system:
// CLI flags > environment variables > config file > defaults.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// DefaultPath returns the default configuration file path.
// It resolves to $HOME/.config/mayu/config.yaml.
func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "mayu", "config.yaml")
}

// OIDCConfig holds OpenID Connect configuration for OIDC auth mode.
type OIDCConfig struct {
	Issuer       string   `yaml:"issuer"`
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	RedirectURL  string   `yaml:"redirect_url"`
	Scopes       []string `yaml:"scopes"`
}

// AuthConfig holds authentication configuration.
type AuthConfig struct {
	// Mode is the authentication mode: "none", "local", or "oidc".
	// An empty value is treated as "none".
	Mode string `yaml:"mode"`
	// OIDC holds OpenID Connect settings (used when Mode is "oidc").
	OIDC OIDCConfig `yaml:"oidc"`
	// SessionSecret is reserved for future use (e.g., HMAC-based session signing).
	// Currently unused - sessions use random database-stored tokens.
	SessionSecret string `yaml:"session_secret"`
	// SessionMaxAge is the session lifetime in seconds (default: 86400).
	SessionMaxAge int `yaml:"session_max_age"`
}

// Config represents the mayu configuration file structure.
type Config struct {
	// DatabaseURL is the PostgreSQL connection string.
	DatabaseURL string `yaml:"database_url"`
	// Auth holds authentication and session configuration.
	Auth AuthConfig `yaml:"auth"`
}

// Load reads and parses a YAML configuration file from the given path.
// If the file does not exist and explicit is false, it returns a zero-value
// Config without error (silent fallback). If explicit is true (user specified
// --config), a missing file is treated as an error.
func Load(path string, explicit bool) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !explicit {
			// Config file doesn't exist but was not explicitly requested — ignore.
			return &Config{}, nil
		}
		return nil, fmt.Errorf("read config file %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config file %s: %w", path, err)
	}
	return &cfg, nil
}
