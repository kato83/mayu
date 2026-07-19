package fetcher

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	// ecosystemsTxtPath is the path to ecosystems.txt within the OSV bucket.
	ecosystemsTxtPath = "ecosystems.txt"

	// maxEcosystemsTxtSize is the maximum allowed size for ecosystems.txt (1 MB).
	maxEcosystemsTxtSize = 1 * 1024 * 1024
)

// ListEcosystems fetches the list of ecosystems from the OSV GCS bucket
// by downloading ecosystems.txt (gs://osv-vulnerabilities/ecosystems.txt).
//
// This file is maintained by the OSV team and contains one ecosystem name
// per line. Sub-ecosystem directories (e.g., Debian:11) were deprecated
// in October 2024 and are no longer included.
//
// See: https://google.github.io/osv.dev/data/
func (f *Fetcher) ListEcosystems(ctx context.Context) ([]string, error) {
	return f.listEcosystems(ctx, "")
}

// listEcosystems is the internal implementation that accepts an optional
// override URL for testing.
func (f *Fetcher) listEcosystems(ctx context.Context, overrideURL string) ([]string, error) {
	u := overrideURL
	if u == "" {
		u = fmt.Sprintf("%s/%s", f.baseURL, ecosystemsTxtPath)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d fetching ecosystems.txt", resp.StatusCode)
	}

	// Limit response body to prevent memory exhaustion.
	limited := io.LimitReader(resp.Body, maxEcosystemsTxtSize+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if int64(len(body)) > maxEcosystemsTxtSize {
		return nil, fmt.Errorf("ecosystems.txt exceeds maximum size of %d bytes", maxEcosystemsTxtSize)
	}

	return parseEcosystemsTxt(body), nil
}

// parseEcosystemsTxt parses the content of ecosystems.txt into a list of
// ecosystem names. It skips empty lines and trims whitespace from each line.
func parseEcosystemsTxt(data []byte) []string {
	var ecosystems []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		ecosystems = append(ecosystems, line)
	}
	return ecosystems
}
