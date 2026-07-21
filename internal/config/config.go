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

// Config represents the mayu configuration file structure.
type Config struct {
	// DatabaseURL is the PostgreSQL connection string.
	DatabaseURL string `yaml:"database_url"`
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
