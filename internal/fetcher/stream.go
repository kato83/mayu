package fetcher

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"strings"
)

// ZipEntry represents a single JSON file entry from a zip archive.
type ZipEntry struct {
	Name string // Filename without .json extension
	Data []byte // Raw JSON content
}

// StreamAllZip downloads the all.zip for a given ecosystem and streams
// entries through a channel. This avoids loading the entire zip contents
// into memory at once - only the zip archive itself is held in memory,
// and entries are read one at a time.
//
// The caller should consume entries from the returned channel.
// The channel is closed when all entries have been sent or an error occurs.
// Check the error channel for any errors after the entries channel is closed.
func (f *Fetcher) StreamAllZip(ctx context.Context, ecosystem string) (<-chan ZipEntry, <-chan error, error) {
	url := fmt.Sprintf("%s/%s/all.zip", f.baseURL, ecosystem)

	// We still need to download the full zip to memory (zip requires random access),
	// but we stream the extraction - reading one file at a time and sending it
	// through the channel so the consumer can process and release each entry.
	data, err := f.download(ctx, url)
	if err != nil {
		return nil, nil, fmt.Errorf("download %s: %w", url, err)
	}

	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, nil, fmt.Errorf("open zip: %w", err)
	}

	entries := make(chan ZipEntry, 100) // Buffer to allow some read-ahead
	errCh := make(chan error, 1)

	go func() {
		defer close(entries)
		defer close(errCh)

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

// CountZipEntries returns the total number of JSON files in the zip
// (used for progress reporting). This is called before streaming.
func CountZipEntries(data []byte) (int, error) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
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
