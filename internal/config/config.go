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

// TranslationConfig holds LLM-based translation configuration.
// Supports OpenAI API-compatible endpoints (OpenAI, Azure, AWS Bedrock via gateway, Ollama, etc.).
type TranslationConfig struct {
	// Enabled controls whether translation features are available.
	// When false, translation endpoints return 503.
	Enabled bool `yaml:"enabled"`

	// Provider is a human-readable provider name for logging (e.g., "openai", "ollama", "bedrock").
	// This does not affect behavior — all providers use the OpenAI-compatible chat completions API.
	Provider string `yaml:"provider"`

	// Endpoint is the base URL of the OpenAI-compatible API (e.g., "https://api.openai.com/v1").
	// For Ollama: "http://localhost:11434/v1"
	// For AWS Bedrock via LiteLLM proxy: "http://localhost:4000/v1"
	Endpoint string `yaml:"endpoint"`

	// Model is the model identifier to use (e.g., "gpt-4o-mini", "llama3.1", "anthropic.claude-3-haiku").
	Model string `yaml:"model"`

	// APIKey is the API key/token for authentication. Leave empty for local models (Ollama).
	APIKey string `yaml:"api_key"`

	// MaxTokens is the maximum number of tokens for the translation response (default: 4096).
	MaxTokens int `yaml:"max_tokens"`

	// Temperature controls randomness (0.0-2.0, default: 0.3 for translation).
	Temperature *float64 `yaml:"temperature"`

	// Timeout is the HTTP request timeout in seconds (default: 120).
	Timeout int `yaml:"timeout"`

	// SystemPrompt allows overriding the default translation system prompt.
	// If empty, a built-in prompt optimized for vulnerability text translation is used.
	SystemPrompt string `yaml:"system_prompt"`

	// Chunking configures text splitting for small models that struggle with long inputs.
	// When enabled, texts are split into smaller chunks before being sent to the LLM.
	Chunking ChunkingConfig `yaml:"chunking"`

	// RateLimit is the maximum number of translation requests allowed per user (or IP)
	// within the RateLimitWindow. This prevents EDoS (Economic Denial of Sustainability)
	// attacks where excessive LLM API calls could lead to unexpected cost spikes.
	// Default: 20 requests per window (enough to translate ~20 CVEs/hour).
	// Set to -1 to disable rate limiting entirely.
	RateLimit int `yaml:"rate_limit"`

	// RateLimitWindow is the time window (in seconds) for the rate limit counter.
	// After this window elapses, the counter resets for the user/IP.
	// Default: 3600 (1 hour).
	RateLimitWindow int `yaml:"rate_limit_window"`

	// RateLimitBurst allows a short burst of requests above the rate limit.
	// This is the maximum number of requests that can be made in quick succession
	// before rate limiting kicks in. Must be >= RateLimit.
	// Default: same as RateLimit (no burst allowance beyond the base limit).
	RateLimitBurst int `yaml:"rate_limit_burst"`
}

// ChunkingConfig controls how translation input texts are split into smaller pieces.
// This is useful for small/local models that time out or produce poor results on long texts.
type ChunkingConfig struct {
	// Enabled controls whether chunking is active. Default: false.
	Enabled bool `yaml:"enabled"`

	// Strategy determines how text is split into chunks.
	// "auto" (default): detect markdown and use markdown splitting, otherwise sentence splitting.
	// "sentence": always split on sentence boundaries (period + space/newline).
	// "markdown": always parse as markdown and split on block boundaries.
	Strategy string `yaml:"strategy"`

	// MaxChars is the target maximum character count per chunk (default: 500).
	// Chunks may exceed this slightly to avoid splitting mid-sentence.
	MaxChars int `yaml:"max_chars"`
}

// EPSSConfig holds EPSS data retention configuration.
type EPSSConfig struct {
	// RetentionDays is the number of days of EPSS historical data to retain.
	// After each EPSS ingest, scores older than this are deleted.
	// Default: 365. Set to 0 or "full" equivalent (negative value) to retain all data indefinitely.
	RetentionDays int `yaml:"retention_days"`
}

// Config represents the mayu configuration file structure.
type Config struct {
	// DatabaseURL is the PostgreSQL connection string.
	DatabaseURL string `yaml:"database_url"`
	// Auth holds authentication and session configuration.
	Auth AuthConfig `yaml:"auth"`
	// Translation holds LLM-based translation configuration.
	Translation TranslationConfig `yaml:"translation"`
	// EPSS holds EPSS data retention configuration.
	EPSS EPSSConfig `yaml:"epss"`
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

// DefaultEPSSRetentionDays is the default number of days to retain EPSS historical data.
const DefaultEPSSRetentionDays = 365

// EffectiveRetentionDays returns the EPSS retention period in days.
// Returns DefaultEPSSRetentionDays (365) if not configured (zero value).
// Returns -1 (retain all) if explicitly set to a negative value.
func (c *EPSSConfig) EffectiveRetentionDays() int {
	if c.RetentionDays == 0 {
		return DefaultEPSSRetentionDays
	}
	return c.RetentionDays
}
