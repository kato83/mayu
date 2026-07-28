package fetcher

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

const cvelistV5BaseURL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/refs/heads/main/cves"

// FetchCVEFromCvelistV5 fetches a single CVE record from the cvelistV5 GitHub repository.
// The URL pattern is:
//
//	https://raw.githubusercontent.com/CVEProject/cvelistV5/refs/heads/main/cves/{year}/{nnn}xxx/{CVE-ID}.json
//
// where {nnn}xxx is derived from the numeric suffix: for CVE-2026-52101, suffix is 52101,
// so the directory is "52xxx" (first digits up to thousands + "xxx").
//
// Returns the raw JSON bytes, or an error. Returns nil, nil if the CVE is not found (404).
func (f *Fetcher) FetchCVEFromCvelistV5(ctx context.Context, cveID string) ([]byte, error) {
	url, err := cvelistV5URL(cveID)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // CVE not found in cvelistV5
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: HTTP %d", url, resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("read body from %s: %w", url, err)
	}

	return data, nil
}

// cvelistV5URL constructs the raw GitHub URL for a given CVE ID.
// Example: CVE-2026-52101 → .../cves/2026/52xxx/CVE-2026-52101.json
func cvelistV5URL(cveID string) (string, error) {
	// Parse CVE-YYYY-NNNNN
	parts := strings.SplitN(cveID, "-", 3)
	if len(parts) != 3 || parts[0] != "CVE" {
		return "", fmt.Errorf("invalid CVE ID format: %s", cveID)
	}

	year := parts[1]
	numStr := parts[2]

	// Validate numeric suffix
	if _, err := strconv.Atoi(numStr); err != nil {
		return "", fmt.Errorf("invalid CVE ID numeric suffix: %s", cveID)
	}

	// Directory: take all digits except the last 3, append "xxx"
	// e.g., 52101 → "52xxx", 1234 → "1xxx", 123 → "0xxx"
	var dir string
	if len(numStr) <= 3 {
		dir = "0xxx"
	} else {
		dir = numStr[:len(numStr)-3] + "xxx"
	}

	return fmt.Sprintf("%s/%s/%s/%s.json", cvelistV5BaseURL, year, dir, cveID), nil
}
