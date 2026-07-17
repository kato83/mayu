package fetcher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	// gcsJSONAPIBaseURL is the base URL for the GCS JSON API.
	gcsJSONAPIBaseURL = "https://storage.googleapis.com/storage/v1/b"

	// osvBucketName is the GCS bucket name for OSV vulnerabilities.
	osvBucketName = "osv-vulnerabilities"
)

// gcsListResponse represents the JSON response from the GCS Objects: list API.
type gcsListResponse struct {
	Prefixes      []string `json:"prefixes"`
	NextPageToken string   `json:"nextPageToken"`
}

// excludedPrefixes are GCS prefixes that do not represent real ecosystems.
var excludedPrefixes = map[string]bool{
	"all/":     true,
	"icons/":   true,
	"[EMPTY]/": true,
}

// ListEcosystems fetches the list of ecosystems from the OSV GCS bucket
// using the GCS JSON API. It returns all directory prefixes (with trailing
// slash removed) that represent actual ecosystems, excluding non-ecosystem
// directories like "all/", "icons/", "[EMPTY]/".
//
// The listBaseURL parameter allows overriding the GCS JSON API base URL for
// testing. If empty, the default GCS JSON API URL is used.
func (f *Fetcher) ListEcosystems(ctx context.Context) ([]string, error) {
	return f.listEcosystems(ctx, "")
}

// listEcosystems is the internal implementation that accepts an optional
// override URL for testing.
func (f *Fetcher) listEcosystems(ctx context.Context, listBaseURL string) ([]string, error) {
	baseURL := listBaseURL
	if baseURL == "" {
		baseURL = fmt.Sprintf("%s/%s/o", gcsJSONAPIBaseURL, osvBucketName)
	}

	var ecosystems []string
	pageToken := ""

	for {
		reqURL := baseURL + "?delimiter=/"
		if pageToken != "" {
			reqURL += "&pageToken=" + pageToken
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, fmt.Errorf("create request: %w", err)
		}

		resp, err := f.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("execute request: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("unexpected status %d from GCS listing API", resp.StatusCode)
		}

		// Limit response body to 10MB (listing should be small).
		const maxListResponseSize = 10 * 1024 * 1024
		limited := io.LimitReader(resp.Body, maxListResponseSize+1)
		body, err := io.ReadAll(limited)
		_ = resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("read response: %w", err)
		}
		if int64(len(body)) > maxListResponseSize {
			return nil, fmt.Errorf("listing response exceeds maximum size")
		}

		var listResp gcsListResponse
		if err := json.Unmarshal(body, &listResp); err != nil {
			return nil, fmt.Errorf("parse listing response: %w", err)
		}

		for _, prefix := range listResp.Prefixes {
			if excludedPrefixes[prefix] {
				continue
			}
			// Remove trailing slash to get the ecosystem name.
			eco := strings.TrimSuffix(prefix, "/")
			if eco != "" {
				ecosystems = append(ecosystems, eco)
			}
		}

		if listResp.NextPageToken == "" {
			break
		}
		pageToken = listResp.NextPageToken
	}

	return ecosystems, nil
}
