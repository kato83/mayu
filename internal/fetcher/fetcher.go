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
	"path"
	"strings"
)

const (
	// DefaultBaseURL is the base URL for the OSV GCS bucket.
	DefaultBaseURL = "https://storage.googleapis.com/osv-vulnerabilities"
)

// Fetcher downloads OSV vulnerability data from the GCS bucket.
type Fetcher struct {
	baseURL    string
	httpClient *http.Client
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

// New creates a new Fetcher with the given options.
func New(opts ...Option) *Fetcher {
	f := &Fetcher{
		baseURL:    DefaultBaseURL,
		httpClient: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(f)
	}
	return f
}

// FetchAllZip downloads and extracts the all.zip for a given ecosystem.
// It returns a map of filename → JSON content for each vulnerability file.
// The callback (if non-nil) is called with progress info: (current, total).
func (f *Fetcher) FetchAllZip(ctx context.Context, ecosystem string, progress func(current, total int)) (map[string][]byte, error) {
	url := fmt.Sprintf("%s/%s/all.zip", f.baseURL, ecosystem)

	data, err := f.download(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}

	return f.extractZip(data, progress)
}

// FetchVulnerability downloads a single vulnerability JSON by ecosystem and ID.
func (f *Fetcher) FetchVulnerability(ctx context.Context, ecosystem, id string) ([]byte, error) {
	url := fmt.Sprintf("%s/%s/%s.json", f.baseURL, ecosystem, id)

	data, err := f.download(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}

	return data, nil
}

// FetchModifiedCSV downloads the modified_id.csv for a given ecosystem.
// Returns the raw CSV content.
func (f *Fetcher) FetchModifiedCSV(ctx context.Context, ecosystem string) ([]byte, error) {
	url := fmt.Sprintf("%s/%s/modified_id.csv", f.baseURL, ecosystem)

	data, err := f.download(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}

	return data, nil
}

// FetchTopLevelModifiedCSV downloads the top-level modified_id.csv
// that spans all ecosystems.
func (f *Fetcher) FetchTopLevelModifiedCSV(ctx context.Context) ([]byte, error) {
	url := fmt.Sprintf("%s/modified_id.csv", f.baseURL)

	data, err := f.download(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
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
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d for %s", resp.StatusCode, url)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	return data, nil
}

// extractZip extracts JSON files from a zip archive in memory.
// Returns a map of filename (without extension) → file content.
func (f *Fetcher) extractZip(data []byte, progress func(current, total int)) (map[string][]byte, error) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}

	// Count JSON files for progress
	total := 0
	for _, file := range reader.File {
		if strings.HasSuffix(file.Name, ".json") {
			total++
		}
	}

	results := make(map[string][]byte, total)
	current := 0

	for _, file := range reader.File {
		if !strings.HasSuffix(file.Name, ".json") {
			continue
		}

		content, err := readZipFile(file)
		if err != nil {
			return nil, fmt.Errorf("read %s from zip: %w", file.Name, err)
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
	defer rc.Close()

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
