// Package fetcher handles downloading OSV vulnerability data from the
// Google Cloud Storage bucket (gs://osv-vulnerabilities/).
//
// It supports:
//   - Full ecosystem download (all.zip)
//   - Individual vulnerability JSON download
//   - Delta sync via modified_id.csv
package fetcher

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"time"
)

const (
	// DefaultBaseURL is the base URL for the OSV GCS bucket.
	DefaultBaseURL = "https://storage.googleapis.com/osv-vulnerabilities"

	// DefaultHTTPTimeout is the default timeout for HTTP requests.
	DefaultHTTPTimeout = 5 * time.Minute

	// LargeFileHTTPTimeout is the timeout for large file downloads (e.g., top-level all.zip ~1.3GB).
	LargeFileHTTPTimeout = 60 * time.Minute

	// MaxResponseSize is the maximum allowed HTTP response body size (2 GB).
	// This prevents memory exhaustion from unexpectedly large responses.
	MaxResponseSize = 2 * 1024 * 1024 * 1024 // 2 GB

	// MaxZipTotalSize is the maximum total extracted size from a zip archive (16 GB).
	MaxZipTotalSize = 16 * 1024 * 1024 * 1024 // 16 GB

	// MaxZipEntries is the maximum number of entries allowed in a zip archive.
	MaxZipEntries = 1_000_000
)

// Fetcher downloads OSV vulnerability data from the GCS bucket.
type Fetcher struct {
	baseURL    string
	httpClient *http.Client
}

// validPathSegment matches safe path segment characters (alphanumeric, dash, dot, underscore, space).
// This prevents path traversal and SSRF via malicious ecosystem or ID values.
var validPathSegment = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9\-._: ]*$`)

// validatePathSegment checks that a string is safe to use as a URL path segment.
func validatePathSegment(name, value string) error {
	if value == "" {
		return fmt.Errorf("%s must not be empty", name)
	}
	if strings.Contains(value, "..") {
		return fmt.Errorf("%s contains path traversal sequence", name)
	}
	if !validPathSegment.MatchString(value) {
		return fmt.Errorf("%s contains invalid characters: %q", name, value)
	}
	return nil
}

// Option configures a Fetcher.
type Option func(*Fetcher)

// WithBaseURL sets a custom base URL (useful for testing).
func WithBaseURL(url string) Option {
	return func(f *Fetcher) {
		f.baseURL = strings.TrimRight(url, "/")
	}
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(client *http.Client) Option {
	return func(f *Fetcher) {
		f.httpClient = client
	}
}

// WithTimeout sets a custom HTTP timeout.
func WithTimeout(d time.Duration) Option {
	return func(f *Fetcher) {
		f.httpClient.Timeout = d
	}
}

// New creates a new Fetcher with the given options.
func New(opts ...Option) *Fetcher {
	f := &Fetcher{
		baseURL: DefaultBaseURL,
		httpClient: &http.Client{
			Timeout: DefaultHTTPTimeout,
		},
	}
	for _, opt := range opts {
		opt(f)
	}
	return f
}

// FetchAllZip downloads and extracts the all.zip for a given ecosystem.
// It returns a map of filename → JSON content for each vulnerability file.
// The callback (if non-nil) is called with progress info: (current, total).
//
// The ZIP is downloaded to a temporary file to avoid holding the entire archive
// in memory, then extracted entry-by-entry.
func (f *Fetcher) FetchAllZip(ctx context.Context, ecosystem string, progress func(current, total int)) (map[string][]byte, error) {
	if err := validatePathSegment("ecosystem", ecosystem); err != nil {
		return nil, err
	}

	u := fmt.Sprintf("%s/%s/all.zip", f.baseURL, url.PathEscape(ecosystem))

	tmpFile, fileSize, err := f.downloadToTempFile(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", u, err)
	}
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
	}()

	return f.extractZipFromFile(tmpFile, fileSize, progress)
}

// FetchVulnerability downloads a single vulnerability JSON by ecosystem and ID.
func (f *Fetcher) FetchVulnerability(ctx context.Context, ecosystem, id string) ([]byte, error) {
	if err := validatePathSegment("ecosystem", ecosystem); err != nil {
		return nil, err
	}
	if err := validatePathSegment("id", id); err != nil {
		return nil, err
	}

	u := fmt.Sprintf("%s/%s/%s.json", f.baseURL, url.PathEscape(ecosystem), url.PathEscape(id))

	data, err := f.download(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", u, err)
	}

	return data, nil
}

// FetchModifiedCSV downloads the modified_id.csv for a given ecosystem.
// Returns the raw CSV content.
func (f *Fetcher) FetchModifiedCSV(ctx context.Context, ecosystem string) ([]byte, error) {
	if err := validatePathSegment("ecosystem", ecosystem); err != nil {
		return nil, err
	}

	u := fmt.Sprintf("%s/%s/modified_id.csv", f.baseURL, url.PathEscape(ecosystem))

	data, err := f.download(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", u, err)
	}

	return data, nil
}

// FetchTopLevelModifiedCSV downloads the top-level modified_id.csv
// that spans all ecosystems.
func (f *Fetcher) FetchTopLevelModifiedCSV(ctx context.Context) ([]byte, error) {
	u := fmt.Sprintf("%s/modified_id.csv", f.baseURL)

	data, err := f.download(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", u, err)
	}

	return data, nil
}

// download performs an HTTP GET and returns the response body.
func (f *Fetcher) download(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d for %s", resp.StatusCode, url)
	}

	// Limit response body to MaxResponseSize to prevent memory exhaustion.
	limited := io.LimitReader(resp.Body, MaxResponseSize+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if int64(len(data)) > MaxResponseSize {
		return nil, fmt.Errorf("response body exceeds maximum size of %d bytes for %s", MaxResponseSize, url)
	}

	return data, nil
}

// extractZip extracts JSON files from a zip archive in memory.
// Returns a map of filename (without extension) → file content.
// This method is retained for backward compatibility with tests and small archives.
func (f *Fetcher) extractZip(data []byte, progress func(current, total int)) (map[string][]byte, error) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}

	return f.extractZipEntries(reader, progress)
}

// extractZipFromFile extracts JSON files from a zip archive stored in a file.
// Uses os.File for random access without loading the entire ZIP into memory.
func (f *Fetcher) extractZipFromFile(file *os.File, size int64, progress func(current, total int)) (map[string][]byte, error) {
	reader, err := zip.NewReader(file, size)
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}

	return f.extractZipEntries(reader, progress)
}

// extractZipEntries is the shared implementation for extracting JSON entries from a zip.Reader.
func (f *Fetcher) extractZipEntries(reader *zip.Reader, progress func(current, total int)) (map[string][]byte, error) {
	// Count JSON files for progress and enforce entry limit
	total := 0
	for _, file := range reader.File {
		if strings.HasSuffix(file.Name, ".json") {
			total++
		}
	}
	if total > MaxZipEntries {
		return nil, fmt.Errorf("zip contains %d entries, exceeding maximum of %d", total, MaxZipEntries)
	}

	results := make(map[string][]byte, total)
	current := 0
	var totalSize int64

	for _, file := range reader.File {
		if !strings.HasSuffix(file.Name, ".json") {
			continue
		}

		content, err := readZipFile(file)
		if err != nil {
			return nil, fmt.Errorf("read %s from zip: %w", file.Name, err)
		}

		totalSize += int64(len(content))
		if totalSize > MaxZipTotalSize {
			return nil, fmt.Errorf("zip total extracted size exceeds maximum of %d bytes", MaxZipTotalSize)
		}

		// Use filename without path and extension as key
		name := strings.TrimSuffix(path.Base(file.Name), ".json")
		results[name] = content

		current++
		if progress != nil {
			progress(current, total)
		}
	}

	return results, nil
}

// readZipFile reads the content of a single file from a zip archive.
func readZipFile(file *zip.File) ([]byte, error) {
	rc, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()

	// Guard against zip bombs: limit to 100MB per file
	const maxFileSize = 100 * 1024 * 1024
	limited := io.LimitReader(rc, maxFileSize+1)

	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileSize {
		return nil, fmt.Errorf("file %s exceeds maximum size of %d bytes", file.Name, maxFileSize)
	}

	return data, nil
}
