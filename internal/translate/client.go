// Package translate provides LLM-based translation for vulnerability text fields.
// It uses the OpenAI Chat Completions API format, which is compatible with:
//   - OpenAI (GPT-4o, GPT-4o-mini, etc.)
//   - Ollama (local LLMs via /v1/chat/completions)
//   - AWS Bedrock via LiteLLM proxy or API gateway
//   - Azure OpenAI
//   - Any OpenAI-compatible endpoint
package translate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kato83/mayu/internal/config"
)

const (
	defaultMaxTokens   = 4096
	defaultTemperature = 0.3
	defaultTimeout     = 120 // seconds

	defaultSystemPrompt = `You are a professional translator specializing in cybersecurity and software vulnerability documentation.
Translate the following text accurately into the target language.
Preserve all technical terms, CVE IDs, product names, version numbers, and code snippets as-is (do not translate them).
Maintain the original formatting (markdown, bullet points, etc.).
Output ONLY the translated text without any explanations, preamble, or surrounding quotes.`
)

// Client is an OpenAI-compatible LLM client for translation.
type Client struct {
	endpoint     string
	model        string
	apiKey       string
	maxTokens    int
	temperature  float64
	timeout      time.Duration
	systemPrompt string
	httpClient   *http.Client
	provider     string
}

// Option configures a Client.
type Option func(*Client)

// NewClient creates a new translation client from configuration.
func NewClient(cfg config.TranslationConfig, opts ...Option) (*Client, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("translation endpoint is required")
	}
	if cfg.Model == "" {
		return nil, fmt.Errorf("translation model is required")
	}

	maxTokens := cfg.MaxTokens
	if maxTokens <= 0 {
		maxTokens = defaultMaxTokens
	}

	temperature := defaultTemperature
	if cfg.Temperature != nil {
		temperature = *cfg.Temperature
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	systemPrompt := cfg.SystemPrompt
	if systemPrompt == "" {
		systemPrompt = defaultSystemPrompt
	}

	c := &Client{
		endpoint:     strings.TrimRight(cfg.Endpoint, "/"),
		model:        cfg.Model,
		apiKey:       cfg.APIKey,
		maxTokens:    maxTokens,
		temperature:  temperature,
		timeout:      time.Duration(timeout) * time.Second,
		systemPrompt: systemPrompt,
		provider:     cfg.Provider,
		httpClient:   &http.Client{Timeout: time.Duration(timeout) * time.Second},
	}

	for _, opt := range opts {
		opt(c)
	}

	return c, nil
}

// Provider returns the configured provider name for logging.
func (c *Client) Provider() string {
	return c.provider
}

// chatRequest is the OpenAI Chat Completions API request body.
type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
	Temperature float64       `json:"temperature"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// chatResponse is the OpenAI Chat Completions API response body.
type chatResponse struct {
	Choices []chatChoice `json:"choices"`
	Error   *apiError    `json:"error,omitempty"`
}

type chatChoice struct {
	Message chatMessage `json:"message"`
}

type apiError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
}

// Translate translates the given text into the target locale using the LLM.
// It returns the translated text or an error.
func (c *Client) Translate(ctx context.Context, text, targetLocale string) (string, error) {
	if text == "" {
		return "", nil
	}

	userPrompt := fmt.Sprintf("Translate the following text into %s:\n\n%s", localeToLanguageName(targetLocale), text)

	reqBody := chatRequest{
		Model: c.model,
		Messages: []chatMessage{
			{Role: "system", Content: c.systemPrompt},
			{Role: "user", Content: userPrompt},
		},
		MaxTokens:   c.maxTokens,
		Temperature: c.temperature,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	url := c.endpoint + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("send request to %s: %w", c.provider, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB limit
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("LLM API returned %d: %s", resp.StatusCode, string(respBytes))
	}

	var chatResp chatResponse
	if err := json.Unmarshal(respBytes, &chatResp); err != nil {
		return "", fmt.Errorf("unmarshal response: %w", err)
	}

	if chatResp.Error != nil {
		return "", fmt.Errorf("LLM API error: %s (%s)", chatResp.Error.Message, chatResp.Error.Type)
	}

	if len(chatResp.Choices) == 0 {
		return "", fmt.Errorf("LLM API returned no choices")
	}

	translated := strings.TrimSpace(chatResp.Choices[0].Message.Content)
	return translated, nil
}

// TranslateBatch translates multiple texts into the target locale.
// Returns a slice of translated texts in the same order as the input.
// Empty input strings produce empty output strings.
func (c *Client) TranslateBatch(ctx context.Context, texts []string, targetLocale string) ([]string, error) {
	results := make([]string, len(texts))

	for i, text := range texts {
		if text == "" {
			continue
		}
		translated, err := c.Translate(ctx, text, targetLocale)
		if err != nil {
			return nil, fmt.Errorf("translate item %d: %w", i, err)
		}
		results[i] = translated
	}

	return results, nil
}

// TranslateChunked translates text by splitting it into chunks using the provided Chunker,
// translating each translatable chunk individually, and reassembling the result.
// This is designed for small/local models that struggle with long inputs.
func (c *Client) TranslateChunked(ctx context.Context, text, targetLocale string, chunker *Chunker) (string, error) {
	if text == "" {
		return "", nil
	}

	chunks := chunker.Split(text)
	if len(chunks) == 0 {
		return "", nil
	}

	// If only one translatable chunk, just translate directly
	translatableCount := 0
	for i := range chunks {
		if chunks[i].Translatable {
			translatableCount++
		}
	}
	if translatableCount <= 1 && len(text) <= chunker.maxChars {
		return c.Translate(ctx, text, targetLocale)
	}

	// Translate each chunk individually
	for i := range chunks {
		if !chunks[i].Translatable {
			continue
		}
		translated, err := c.Translate(ctx, chunks[i].Text, targetLocale)
		if err != nil {
			return "", fmt.Errorf("translate chunk %d: %w", i, err)
		}
		chunks[i].Text = translated
	}

	return Join(chunks), nil
}

// localeToLanguageName converts a BCP 47 locale tag to a human-readable language name
// for use in prompts. This helps the LLM understand the target language clearly.
func localeToLanguageName(locale string) string {
	lower := strings.ToLower(locale)
	switch {
	case lower == "ja" || strings.HasPrefix(lower, "ja-"):
		return "Japanese (日本語)"
	case lower == "ko" || strings.HasPrefix(lower, "ko-"):
		return "Korean (한국어)"
	case lower == "zh-hans" || lower == "zh-cn":
		return "Simplified Chinese (简体中文)"
	case lower == "zh-hant" || lower == "zh-tw":
		return "Traditional Chinese (繁體中文)"
	case lower == "zh":
		return "Chinese (中文)"
	case lower == "fr" || strings.HasPrefix(lower, "fr-"):
		return "French (Français)"
	case lower == "de" || strings.HasPrefix(lower, "de-"):
		return "German (Deutsch)"
	case lower == "es" || strings.HasPrefix(lower, "es-"):
		return "Spanish (Español)"
	case lower == "pt" || strings.HasPrefix(lower, "pt-"):
		return "Portuguese (Português)"
	case lower == "ru" || strings.HasPrefix(lower, "ru-"):
		return "Russian (Русский)"
	case lower == "ar" || strings.HasPrefix(lower, "ar-"):
		return "Arabic (العربية)"
	case lower == "hi" || strings.HasPrefix(lower, "hi-"):
		return "Hindi (हिन्दी)"
	case lower == "it" || strings.HasPrefix(lower, "it-"):
		return "Italian (Italiano)"
	case lower == "vi" || strings.HasPrefix(lower, "vi-"):
		return "Vietnamese (Tiếng Việt)"
	case lower == "th" || strings.HasPrefix(lower, "th-"):
		return "Thai (ไทย)"
	default:
		return locale
	}
}
