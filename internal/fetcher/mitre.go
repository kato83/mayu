package fetcher

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	// mitreReleasesURL is the GitHub API endpoint for CVEProject/cvelistV5 releases.
	mitreReleasesURL = "https://api.github.com/repos/CVEProject/cvelistV5/releases"

	// mitreDownloadBaseURL is the base URL for downloading release assets.
	mitreDownloadBaseURL = "https://github.com/CVEProject/cvelistV5/releases/download"

	// MaxMITREZipSize is the maximum allowed size for a MITRE baseline zip (2 GB).
	// The baseline zip containing all CVEs can be 500MB+.
	MaxMITREZipSize int64 = 2 * 1024 * 1024 * 1024

	// mitreReleasesPerPage is the number of releases to request per GitHub API page.
	// MITRE publishes hourly releases (24/day), so 100 covers ~4 days.
	mitreReleasesPerPage = 100
)

// mitreRelease represents a GitHub release from the CVEProject/cvelistV5 repository.
type mitreRelease struct {
	TagName     string              `json:"tag_name"`
	PublishedAt time.Time           `json:"published_at"`
	Assets      []mitreReleaseAsset `json:"assets"`
}

// mitreReleaseAsset represents an asset attached to a GitHub release.
type mitreReleaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// mitreBaselineTag returns the release tag for a midnight baseline release on the given date.
// Format: cve_{YYYY-MM-DD}_0000Z
func mitreBaselineTag(date string) string {
	return fmt.Sprintf("cve_%s_0000Z", date)
}

// mitreBaselineAssetName returns the asset filename for the midnight baseline zip.
// Format: {YYYY-MM-DD}_all_CVEs_at_midnight.zip
func mitreBaselineAssetName(date string) string {
	return fmt.Sprintf("%s_all_CVEs_at_midnight.zip", date)
}

// mitreBaselineURL returns the full download URL for a midnight baseline zip.
func mitreBaselineURL(date string) string {
	tag := mitreBaselineTag(date)
	asset := mitreBaselineAssetName(date)
	return fmt.Sprintf("%s/%s/%s", mitreDownloadBaseURL, tag, asset)
}

// mitreDeltaTag returns the release tag for a delta release at the given hour.
// Format: cve_{YYYY-MM-DD}_{HH}00Z
func mitreDeltaTag(date string, hour int) string {
	return fmt.Sprintf("cve_%s_%02d00Z", date, hour)
}

// mitreDeltaAssetName returns the asset filename for a delta zip at the given hour.
// Format: {YYYY-MM-DD}_delta_CVEs_at_{HH}00Z.zip
func mitreDeltaAssetName(date string, hour int) string {
	return fmt.Sprintf("%s_delta_CVEs_at_%02d00Z.zip", date, hour)
}

// mitreDeltaURL returns the full download URL for a delta zip.
func mitreDeltaURL(date string, hour int) string {
	tag := mitreDeltaTag(date, hour)
	asset := mitreDeltaAssetName(date, hour)
	return fmt.Sprintf("%s/%s/%s", mitreDownloadBaseURL, tag, asset)
}

// isMITRECVEEntry checks if a zip entry path matches the expected MITRE CVE JSON
// pattern: cves/{YYYY}/{NNNNxxx}/CVE-{YYYY}-{NNNN}.json
func isMITRECVEEntry(name string) bool {
	return strings.HasPrefix(name, "cves/") && strings.HasSuffix(name, ".json")
}

// FindMITRELatestMidnightTag queries the GitHub Releases API to find the most
// recent midnight (0000Z) release tag from CVEProject/cvelistV5.
// Returns the full tag name and the date portion (YYYY-MM-DD).
func (f *Fetcher) FindMITRELatestMidnightTag(ctx context.Context) (tag string, date string, err error) {
	releases, err := f.fetchMITREReleases(ctx)
	if err != nil {
		return "", "", fmt.Errorf("fetch MITRE releases: %w", err)
	}

	for _, rel := range releases {
		// Look for midnight tags: cve_{YYYY-MM-DD}_0000Z
		if strings.HasSuffix(rel.TagName, "_0000Z") && strings.HasPrefix(rel.TagName, "cve_") {
			// Extract date from tag: cve_YYYY-MM-DD_0000Z -> YYYY-MM-DD
			parts := strings.Split(rel.TagName, "_")
			if len(parts) >= 3 {
				date = parts[1]
				return rel.TagName, date, nil
			}
		}
	}

	return "", "", fmt.Errorf("no midnight release found in recent releases")
}

// FindMITREBaselineURL queries the GitHub Releases API and returns the download
// URL for the baseline zip (all_CVEs_at_midnight) from the most recent release.
// Every hourly release includes the baseline zip asset, so we simply use the latest.
func (f *Fetcher) FindMITREBaselineURL(ctx context.Context) (downloadURL string, err error) {
	releases, err := f.fetchMITREReleases(ctx)
	if err != nil {
		return "", fmt.Errorf("fetch MITRE releases: %w", err)
	}

	for _, rel := range releases {
		for _, asset := range rel.Assets {
			if strings.Contains(asset.Name, "all_CVEs_at_midnight") {
				return asset.BrowserDownloadURL, nil
			}
		}
	}

	return "", fmt.Errorf("no baseline zip asset found in recent releases")
}

// StreamMITREBaselineZip downloads the latest midnight baseline zip from
// CVEProject/cvelistV5 and streams CVE JSON entries through a channel.
//
// It determines today's date (UTC) and attempts to download that day's baseline.
// If today's release is not yet available (e.g., early morning before it's published),
// it falls back to yesterday's release.
//
// Only entries matching the cves/**/*.json pattern are emitted.
// The caller should consume entries from the returned channel.
// The channel is closed when all entries have been sent or an error occurs.
// Check the error channel for any errors after the entries channel is closed.
func (f *Fetcher) StreamMITREBaselineZip(ctx context.Context) (<-chan ZipEntry, <-chan error, error) {
	// Find the baseline zip URL from the latest release via the API.
	u, err := f.FindMITREBaselineURL(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("find MITRE baseline zip: %w", err)
	}

	// Use a longer timeout for the large baseline download.
	// Create a dedicated client to avoid mutating the shared httpClient (thread-safety).
	largeClient := &http.Client{
		Timeout:   LargeFileHTTPTimeout,
		Transport: f.httpClient.Transport,
	}
	tmpFile, fileSize, err := f.downloadMITREToTempFileWith(ctx, u, largeClient)
	if err != nil {
		return nil, nil, fmt.Errorf("download MITRE baseline zip: %w", err)
	}

	// Open zip reader from the temporary file.
	reader, err := zip.NewReader(tmpFile, fileSize)
	if err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		return nil, nil, fmt.Errorf("open zip: %w", err)
	}

	// Count CVE JSON entries and enforce entry limit.
	jsonCount := 0
	for _, file := range reader.File {
		if isMITRECVEEntry(file.Name) {
			jsonCount++
		}
	}
	if jsonCount > MaxZipEntries {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		return nil, nil, fmt.Errorf("zip contains %d CVE entries, exceeding maximum of %d", jsonCount, MaxZipEntries)
	}

	entries := make(chan ZipEntry, 100)
	errCh := make(chan error, 1)

	go func() {
		defer close(entries)
		defer close(errCh)
		defer func() {
			_ = tmpFile.Close()
			_ = os.Remove(tmpFile.Name())
		}()

		var totalSize int64

		for _, file := range reader.File {
			if !isMITRECVEEntry(file.Name) {
				continue
			}

			select {
			case <-ctx.Done():
				errCh <- ctx.Err()
				return
			default:
			}

			content, err := readZipFile(file)
			if err != nil {
				errCh <- fmt.Errorf("read %s: %w", file.Name, err)
				return
			}

			totalSize += int64(len(content))
			if totalSize > MaxZipTotalSize {
				errCh <- fmt.Errorf("zip total extracted size exceeds maximum of %d bytes", MaxZipTotalSize)
				return
			}

			// Extract CVE ID from path: cves/YYYY/NNNNxxx/CVE-YYYY-NNNN.json -> CVE-YYYY-NNNN
			name := strings.TrimSuffix(file.Name, ".json")
			if idx := strings.LastIndex(name, "/"); idx >= 0 {
				name = name[idx+1:]
			}

			select {
			case entries <- ZipEntry{Name: name, Data: content}:
			case <-ctx.Done():
				errCh <- ctx.Err()
				return
			}
		}
	}()

	return entries, errCh, nil
}

// FetchMITREDeltaZips fetches all delta zip archives published after the given
// time. It queries the GitHub Releases API to find hourly delta releases that
// were published after `since`, downloads each delta zip, and returns the raw
// zip bytes for each.
//
// Delta releases have tags like cve_{YYYY-MM-DD}_{HH}00Z where HH > 00,
// and contain only CVEs modified since the day's midnight baseline.
func (f *Fetcher) FetchMITREDeltaZips(ctx context.Context, since time.Time) ([][]byte, error) {
	releases, err := f.fetchMITREReleases(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch MITRE releases: %w", err)
	}

	var deltaZips [][]byte

	for _, rel := range releases {
		// Skip midnight (baseline) releases.
		if strings.HasSuffix(rel.TagName, "_0000Z") {
			continue
		}

		// Only include releases published after 'since'.
		if !rel.PublishedAt.After(since) {
			continue
		}

		// Must be a valid MITRE tag format: cve_{YYYY-MM-DD}_{HH}00Z
		if !strings.HasPrefix(rel.TagName, "cve_") {
			continue
		}

		// Find the delta zip asset.
		var downloadURL string
		for _, asset := range rel.Assets {
			if strings.Contains(asset.Name, "_delta_CVEs_at_") {
				downloadURL = asset.BrowserDownloadURL
				break
			}
		}
		if downloadURL == "" {
			continue
		}

		data, err := f.download(ctx, downloadURL)
		if err != nil {
			return nil, fmt.Errorf("download delta zip %s: %w", rel.TagName, err)
		}
		deltaZips = append(deltaZips, data)
	}

	return deltaZips, nil
}

// fetchMITREReleases fetches the list of recent releases from the GitHub API.
func (f *Fetcher) fetchMITREReleases(ctx context.Context) ([]mitreRelease, error) {
	u := fmt.Sprintf("%s?per_page=%d", mitreReleasesURL, mitreReleasesPerPage)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	// Limit response body size.
	limited := io.LimitReader(resp.Body, MaxResponseSize+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if int64(len(data)) > MaxResponseSize {
		return nil, fmt.Errorf("response body exceeds maximum size")
	}

	var releases []mitreRelease
	if err := json.Unmarshal(data, &releases); err != nil {
		return nil, fmt.Errorf("unmarshal releases: %w", err)
	}

	return releases, nil
}

// downloadMITREToTempFileWith downloads the MITRE zip to a temporary file using
// the provided HTTP client with the larger MaxMITREZipSize limit.
// Returns the open file (seeked to beginning) and its size.
func (f *Fetcher) downloadMITREToTempFileWith(ctx context.Context, url string, client *http.Client) (*os.File, int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("execute request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return nil, 0, fmt.Errorf("MITRE zip not found at %s: %w", url, ErrNotFound)
		}
		return nil, 0, fmt.Errorf("unexpected status %d for %s", resp.StatusCode, url)
	}

	// Create temp file with restricted permissions (0600).
	tmpFile, err := os.CreateTemp("", "mayu-mitre-*.tmp")
	if err != nil {
		return nil, 0, fmt.Errorf("create temp file: %w", err)
	}

	// Ensure cleanup on error paths.
	success := false
	defer func() {
		if !success {
			_ = tmpFile.Close()
			_ = os.Remove(tmpFile.Name())
		}
	}()

	// Stream response body to the temp file with the MITRE-specific size limit.
	limited := io.LimitReader(resp.Body, MaxMITREZipSize+1)
	written, err := io.Copy(tmpFile, limited)
	if err != nil {
		return nil, 0, fmt.Errorf("write to temp file: %w", err)
	}
	if written > MaxMITREZipSize {
		return nil, 0, fmt.Errorf("response body exceeds maximum MITRE zip size of %d bytes for %s", MaxMITREZipSize, url)
	}

	// Seek back to the beginning for reading.
	if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
		return nil, 0, fmt.Errorf("seek temp file: %w", err)
	}

	success = true
	return tmpFile, written, nil
}

// StreamMITREDeltaZip takes raw delta zip bytes and streams CVE JSON entries
// through a channel. This is a convenience method for processing the output
// of FetchMITREDeltaZips. The context can be used to cancel streaming.
func (f *Fetcher) StreamMITREDeltaZip(ctx context.Context, data []byte) (<-chan ZipEntry, <-chan error, error) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, nil, fmt.Errorf("open zip: %w", err)
	}

	// Count CVE entries.
	jsonCount := 0
	for _, file := range reader.File {
		if isMITRECVEEntry(file.Name) {
			jsonCount++
		}
	}
	if jsonCount > MaxZipEntries {
		return nil, nil, fmt.Errorf("zip contains %d CVE entries, exceeding maximum of %d", jsonCount, MaxZipEntries)
	}

	entries := make(chan ZipEntry, 100)
	errCh := make(chan error, 1)

	go func() {
		defer close(entries)
		defer close(errCh)

		var totalSize int64

		for _, file := range reader.File {
			select {
			case <-ctx.Done():
				errCh <- ctx.Err()
				return
			default:
			}

			if !isMITRECVEEntry(file.Name) {
				continue
			}

			content, err := readZipFile(file)
			if err != nil {
				errCh <- fmt.Errorf("read %s: %w", file.Name, err)
				return
			}

			totalSize += int64(len(content))
			if totalSize > MaxZipTotalSize {
				errCh <- fmt.Errorf("zip total extracted size exceeds maximum of %d bytes", MaxZipTotalSize)
				return
			}

			// Extract CVE ID from path.
			name := strings.TrimSuffix(file.Name, ".json")
			if idx := strings.LastIndex(name, "/"); idx >= 0 {
				name = name[idx+1:]
			}

			select {
			case entries <- ZipEntry{Name: name, Data: content}:
			case <-ctx.Done():
				errCh <- ctx.Err()
				return
			}
		}
	}()

	return entries, errCh, nil
}
