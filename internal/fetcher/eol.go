// Package fetcher provides data download functionality for endoflife.date API v1.
package fetcher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	eolBaseURL = "https://endoflife.date/api/v1"
)

// EOLProduct represents a product from the endoflife.date API.
type EOLProduct struct {
	Name           string          `json:"name"`
	Aliases        []string        `json:"aliases"`
	Label          string          `json:"label"`
	Category       string          `json:"category"`
	Tags           []string        `json:"tags"`
	VersionCommand string          `json:"versionCommand"`
	Identifiers    []EOLIdentifier `json:"identifiers"`
	Labels         json.RawMessage `json:"labels"`
	Links          json.RawMessage `json:"links"`
	Releases       []EOLRelease    `json:"releases"`
	URI            string          `json:"uri"`
}

// EOLIdentifier represents a product identifier (purl, cpe, repology).
type EOLIdentifier struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// EOLRelease represents a release cycle from endoflife.date.
type EOLRelease struct {
	Name         string          `json:"name"`
	Codename     *string         `json:"codename"`
	Label        string          `json:"label"`
	ReleaseDate  string          `json:"releaseDate"`
	IsLts        *bool           `json:"isLts"`
	LtsFrom      *string         `json:"ltsFrom"`
	IsEoas       *bool           `json:"isEoas"`
	EoasFrom     *string         `json:"eoasFrom"`
	IsEol        *bool           `json:"isEol"`
	EolFrom      *string         `json:"eolFrom"`
	IsEoes       *bool           `json:"isEoes"`
	EoesFrom     *string         `json:"eoesFrom"`
	IsMaintained *bool           `json:"isMaintained"`
	Latest       *EOLLatest      `json:"latest"`
	Custom       json.RawMessage `json:"custom"`
}

// EOLLatest represents the latest version info for a release.
type EOLLatest struct {
	Name string `json:"name"`
	Date string `json:"date"`
	Link string `json:"link"`
}

// EOLProductSummary is a summary item from the /products listing.
type EOLProductSummary struct {
	Name     string   `json:"name"`
	Aliases  []string `json:"aliases"`
	Label    string   `json:"label"`
	Category string   `json:"category"`
	Tags     []string `json:"tags"`
	URI      string   `json:"uri"`
}

// EOLProductListResponse is the response from /api/v1/products.
type EOLProductListResponse struct {
	SchemaVersion string              `json:"schema_version"`
	GeneratedAt   string              `json:"generated_at"`
	Total         int                 `json:"total"`
	Result        []EOLProductSummary `json:"result"`
}

// EOLProductDetailResponse is the response from /api/v1/products/{product}.
type EOLProductDetailResponse struct {
	SchemaVersion string     `json:"schema_version"`
	GeneratedAt   string     `json:"generated_at"`
	LastModified  string     `json:"last_modified"`
	Result        EOLProduct `json:"result"`
}

// FetchEOLProducts fetches the full list of products from endoflife.date.
func FetchEOLProducts(ctx context.Context) ([]EOLProductSummary, error) {
	url := eolBaseURL + "/products"
	body, err := eolGet(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("fetch EOL products: %w", err)
	}

	var resp EOLProductListResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse EOL products: %w", err)
	}
	return resp.Result, nil
}

// FetchEOLProductDetail fetches detailed product info including releases.
// Returns the parsed response and the raw JSON body for storage.
func FetchEOLProductDetail(ctx context.Context, product string) (*EOLProductDetailResponse, []byte, error) {
	url := eolBaseURL + "/products/" + product
	body, err := eolGet(ctx, url)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch EOL product %s: %w", product, err)
	}

	var resp EOLProductDetailResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil, fmt.Errorf("parse EOL product %s: %w", product, err)
	}
	return &resp, body, nil
}

// eolGet performs a GET request to the endoflife.date API with rate limiting.
func eolGet(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "mayu/1.0 (https://github.com/kato83/mayu)")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("rate limited by endoflife.date (429)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d from %s", resp.StatusCode, url)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	return body, nil
}
