package fetcher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

const (
	// GitHubAPIBaseURL is the base URL for the GitHub REST API.
	GitHubAPIBaseURL = "https://api.github.com"

	// ghsaDefaultPerPage is the default number of advisories per page.
	ghsaDefaultPerPage = 100

	// ghsaMaxResponseSize is the maximum response body size for GHSA API (50 MB).
	ghsaMaxResponseSize = 50 * 1024 * 1024
)

// linkRelNext matches the "next" relation in a Link header.
// Example: <https://api.github.com/...?after=xyz>; rel="next"
var linkRelNext = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// FetchGitHubAdvisories fetches all published security advisories from a
// GitHub repository using the REST API with cursor-based pagination.
//
// For public repositories with published advisories, no authentication is required.
// If a token is provided, it will be included as a Bearer token for rate limit benefits
// or access to private/unpublished advisories.
//
// Returns the raw JSON bytes of each advisory (suitable for parser.ConvertGitHubToOSV).
func (f *Fetcher) FetchGitHubAdvisories(ctx context.Context, owner, repo, token string) ([][]byte, error) {
	if owner == "" {
		return nil, fmt.Errorf("owner must not be empty")
	}
	if repo == "" {
		return nil, fmt.Errorf("repo must not be empty")
	}

	baseURL := fmt.Sprintf("%s/repos/%s/%s/security-advisories?state=published&per_page=%d&sort=updated&direction=desc",
		GitHubAPIBaseURL, owner, repo, ghsaDefaultPerPage)

	var allAdvisories [][]byte
	nextURL := baseURL

	for nextURL != "" {
		advisories, next, err := f.fetchGHSAPage(ctx, nextURL, token)
		if err != nil {
			return nil, err
		}
		allAdvisories = append(allAdvisories, advisories...)
		nextURL = next
	}

	return allAdvisories, nil
}

// fetchGHSAPage fetches a single page of advisories and returns the individual
// advisory JSON blobs plus the URL for the next page (empty string if none).
func (f *Fetcher) fetchGHSAPage(ctx context.Context, url, token string) ([][]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("execute request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, "", fmt.Errorf("GitHub API returned status %d for %s: %s", resp.StatusCode, url, string(body))
	}

	// Read response body with size limit
	limited := io.LimitReader(resp.Body, ghsaMaxResponseSize+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, "", fmt.Errorf("read response body: %w", err)
	}
	if int64(len(data)) > ghsaMaxResponseSize {
		return nil, "", fmt.Errorf("response body exceeds maximum size of %d bytes", ghsaMaxResponseSize)
	}

	// Parse JSON array of advisories
	var rawAdvisories []json.RawMessage
	if err := json.Unmarshal(data, &rawAdvisories); err != nil {
		return nil, "", fmt.Errorf("parse advisory list: %w", err)
	}

	advisories := make([][]byte, len(rawAdvisories))
	for i, raw := range rawAdvisories {
		advisories[i] = []byte(raw)
	}

	// Extract next page URL from Link header
	nextURL := extractNextLink(resp.Header.Get("Link"))

	return advisories, nextURL, nil
}

// extractNextLink parses the GitHub Link header to find the "next" page URL.
func extractNextLink(linkHeader string) string {
	if linkHeader == "" {
		return ""
	}

	// Split on comma in case there are multiple links
	for _, part := range strings.Split(linkHeader, ",") {
		matches := linkRelNext.FindStringSubmatch(strings.TrimSpace(part))
		if len(matches) == 2 {
			return matches[1]
		}
	}

	return ""
}
