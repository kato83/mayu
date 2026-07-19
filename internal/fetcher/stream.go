package fetcher

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// ZipEntry represents a single JSON file entry from a zip archive.
type ZipEntry struct {
	Name string // Filename without .json extension
	Data []byte // Raw JSON content
}

// StreamAllZip downloads the all.zip for a given ecosystem to a temporary file
// and streams entries through a channel. The ZIP is written directly to disk
// to avoid holding the entire archive in memory, then read via random access.
//
// The caller should consume entries from the returned channel.
// The channel is closed when all entries have been sent or an error occurs.
// Check the error channel for any errors after the entries channel is closed.
//
// The temporary file is automatically cleaned up when streaming completes or
// an error occurs.
func (f *Fetcher) StreamAllZip(ctx context.Context, ecosystem string) (<-chan ZipEntry, <-chan error, error) {
	if err := validatePathSegment("ecosystem", ecosystem); err != nil {
		return nil, nil, err
	}

	u := fmt.Sprintf("%s/%s/all.zip", f.baseURL, url.PathEscape(ecosystem))

	// Download the zip to a temporary file instead of memory.
	tmpFile, fileSize, err := f.downloadToTempFile(ctx, u)
	if err != nil {
		return nil, nil, fmt.Errorf("download %s: %w", u, err)
	}

	// Open zip reader from the temporary file (random access via *os.File).
	reader, err := zip.NewReader(tmpFile, fileSize)
	if err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		return nil, nil, fmt.Errorf("open zip: %w", err)
	}

	// Check entry count limit.
	jsonCount := 0
	for _, file := range reader.File {
		if strings.HasSuffix(file.Name, ".json") {
			jsonCount++
		}
	}
	if jsonCount > MaxZipEntries {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		return nil, nil, fmt.Errorf("zip contains %d entries, exceeding maximum of %d", jsonCount, MaxZipEntries)
	}

	entries := make(chan ZipEntry, 100) // Buffer to allow some read-ahead
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
			if !strings.HasSuffix(file.Name, ".json") {
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

// StreamTopLevelAllZip downloads the top-level all.zip (which contains
// vulnerabilities from ALL ecosystems, ~1.3GB) to a temporary file and
// streams entries through a channel. Each entry's filename in the zip has
// the format "ecosystem/vuln_id.json".
//
// This uses a longer timeout appropriate for large file downloads.
// The temporary file is automatically cleaned up when streaming completes.
func (f *Fetcher) StreamTopLevelAllZip(ctx context.Context) (<-chan ZipEntry, <-chan error, error) {
	u := fmt.Sprintf("%s/all.zip", f.baseURL)

	// Use a longer timeout for the large download.
	// Create a dedicated client to avoid mutating the shared httpClient (thread-safety).
	largeClient := &http.Client{
		Timeout:   LargeFileHTTPTimeout,
		Transport: f.httpClient.Transport,
	}
	tmpFile, fileSize, err := f.downloadToTempFileWith(ctx, u, largeClient, MaxResponseSize)
	if err != nil {
		return nil, nil, fmt.Errorf("download top-level all.zip: %w", err)
	}

	// Open zip reader from the temporary file.
	reader, err := zip.NewReader(tmpFile, fileSize)
	if err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		return nil, nil, fmt.Errorf("open zip: %w", err)
	}

	// Check entry count limit.
	jsonCount := 0
	for _, file := range reader.File {
		if strings.HasSuffix(file.Name, ".json") {
			jsonCount++
		}
	}
	if jsonCount > MaxZipEntries {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		return nil, nil, fmt.Errorf("zip contains %d entries, exceeding maximum of %d", jsonCount, MaxZipEntries)
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
			if !strings.HasSuffix(file.Name, ".json") {
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

			// For top-level all.zip, the filename is "ecosystem/vuln_id.json"
			// Extract just the vuln_id part.
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

// downloadToTempFile downloads the URL content directly to a temporary file,
// avoiding loading the entire response into memory. It returns the open file
// (seeked to beginning) and its size.
//
// Security considerations:
//   - The temp file is created with mode 0600 (owner-only read/write).
//   - The file is created in the OS default temp directory.
//   - MaxResponseSize is enforced to prevent disk exhaustion.
//   - The caller is responsible for closing and removing the file.
func (f *Fetcher) downloadToTempFile(ctx context.Context, url string) (*os.File, int64, error) {
	return f.downloadToTempFileWith(ctx, url, f.httpClient, MaxResponseSize)
}

// downloadToTempFileWith downloads a URL to a temporary file using the provided
// HTTP client and size limit. This avoids mutating shared state on the Fetcher.
func (f *Fetcher) downloadToTempFileWith(ctx context.Context, url string, client *http.Client, maxSize int64) (*os.File, int64, error) {
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
		return nil, 0, fmt.Errorf("unexpected status %d for %s", resp.StatusCode, url)
	}

	// Create temp file with restricted permissions (0600).
	tmpFile, err := os.CreateTemp("", "mayu-zip-*.tmp")
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

	// Stream response body to the temp file with a size limit.
	limited := io.LimitReader(resp.Body, maxSize+1)
	written, err := io.Copy(tmpFile, limited)
	if err != nil {
		return nil, 0, fmt.Errorf("write to temp file: %w", err)
	}
	if written > maxSize {
		return nil, 0, fmt.Errorf("response body exceeds maximum size of %d bytes for %s", maxSize, url)
	}

	// Seek back to the beginning for reading.
	if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
		return nil, 0, fmt.Errorf("seek temp file: %w", err)
	}

	success = true
	return tmpFile, written, nil
}

// CountZipEntriesFromFile returns the total number of JSON files in a zip file on disk.
// Used for progress reporting before streaming.
func CountZipEntriesFromFile(f *os.File, size int64) (int, error) {
	reader, err := zip.NewReader(f, size)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, file := range reader.File {
		if strings.HasSuffix(file.Name, ".json") {
			count++
		}
	}
	return count, nil
}
