package fetcher

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// NVDFeedMeta contains metadata parsed from an NVD feed .meta file.
type NVDFeedMeta struct {
	LastModifiedDate time.Time
	Size             int64
	ZipSize          int64
	GzSize           int64
	SHA256           string
}

const (
	// nvdFeedBaseURL is the base URL for NVD JSON Feed 2.0 files.
	nvdFeedBaseURL = "https://nvd.nist.gov/feeds/json/cve/2.0"

	// nvdFeedFirstYear is the first year for which NVD provides feed data.
	nvdFeedFirstYear = 2002
)

// NVDFeedYears returns a slice of years from nvdFeedFirstYear to the current year (inclusive).
func NVDFeedYears() []int {
	currentYear := time.Now().Year()
	years := make([]int, 0, currentYear-nvdFeedFirstYear+1)
	for y := nvdFeedFirstYear; y <= currentYear; y++ {
		years = append(years, y)
	}
	return years
}

// FetchNVDMeta downloads and parses the META file for the given year's NVD feed.
func (f *Fetcher) FetchNVDMeta(ctx context.Context, year int) (*NVDFeedMeta, error) {
	u := nvdMetaURL(year)
	data, err := f.download(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("download NVD meta for %d: %w", year, err)
	}
	return parseNVDMeta(data)
}

// FetchNVDModifiedMeta downloads and parses the META file for the NVD modified feed.
func (f *Fetcher) FetchNVDModifiedMeta(ctx context.Context) (*NVDFeedMeta, error) {
	u := fmt.Sprintf("%s/nvdcve-2.0-modified.meta", nvdFeedBaseURL)
	data, err := f.download(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("download NVD modified meta: %w", err)
	}
	return parseNVDMeta(data)
}

// FetchNVDFeed downloads the gzipped NVD JSON feed for the given year and returns
// the decompressed JSON bytes.
func (f *Fetcher) FetchNVDFeed(ctx context.Context, year int) ([]byte, error) {
	u := nvdFeedURL(year)
	return f.downloadAndGunzip(ctx, u)
}

// FetchNVDModifiedFeed downloads the gzipped NVD modified feed and returns
// the decompressed JSON bytes.
func (f *Fetcher) FetchNVDModifiedFeed(ctx context.Context) ([]byte, error) {
	u := fmt.Sprintf("%s/nvdcve-2.0-modified.json.gz", nvdFeedBaseURL)
	return f.downloadAndGunzip(ctx, u)
}

// FetchNVDRecentFeed downloads the gzipped NVD recent feed and returns
// the decompressed JSON bytes.
func (f *Fetcher) FetchNVDRecentFeed(ctx context.Context) ([]byte, error) {
	u := fmt.Sprintf("%s/nvdcve-2.0-recent.json.gz", nvdFeedBaseURL)
	return f.downloadAndGunzip(ctx, u)
}

// downloadAndGunzip downloads gzipped data from the given URL and decompresses it.
func (f *Fetcher) downloadAndGunzip(ctx context.Context, url string) ([]byte, error) {
	compressed, err := f.download(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}

	gr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("create gzip reader for %s: %w", url, err)
	}
	defer func() { _ = gr.Close() }()

	// Limit decompressed size to MaxResponseSize to prevent decompression bombs.
	limited := io.LimitReader(gr, MaxResponseSize+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("decompress %s: %w", url, err)
	}
	if int64(len(data)) > MaxResponseSize {
		return nil, fmt.Errorf("decompressed data exceeds maximum size of %d bytes for %s", MaxResponseSize, url)
	}

	return data, nil
}

// nvdFeedURL returns the URL for the year's gzipped NVD JSON feed.
func nvdFeedURL(year int) string {
	return fmt.Sprintf("%s/nvdcve-2.0-%d.json.gz", nvdFeedBaseURL, year)
}

// nvdMetaURL returns the URL for the year's NVD META file.
func nvdMetaURL(year int) string {
	return fmt.Sprintf("%s/nvdcve-2.0-%d.meta", nvdFeedBaseURL, year)
}

// parseNVDMeta parses NVD META file content into an NVDFeedMeta struct.
// The META file format is line-based key:value pairs:
//
//	lastModifiedDate:2026-07-19T10:00:00-04:00
//	size:14108373
//	zipSize:1002849
//	gzSize:1002709
//	sha256:D7F1385C8423826AA903B78BCA5AD29B33253B47C093CC3E3BA0F5DB49BD2D2A
func parseNVDMeta(data []byte) (*NVDFeedMeta, error) {
	meta := &NVDFeedMeta{}
	scanner := bufio.NewScanner(bytes.NewReader(data))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Split on first colon only (value may contain colons, e.g., timestamps)
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		key := line[:idx]
		value := strings.TrimSpace(line[idx+1:])

		switch strings.ToLower(key) {
		case "lastmodifieddate":
			t, err := time.Parse(time.RFC3339, value)
			if err != nil {
				// Try alternative format without timezone offset (ISO 8601 basic)
				t, err = time.Parse("2006-01-02T15:04:05.000", value)
				if err != nil {
					return nil, fmt.Errorf("parse lastModifiedDate %q: %w", value, err)
				}
			}
			meta.LastModifiedDate = t
		case "size":
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("parse size %q: %w", value, err)
			}
			meta.Size = n
		case "zipsize":
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("parse zipSize %q: %w", value, err)
			}
			meta.ZipSize = n
		case "gzsize":
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("parse gzSize %q: %w", value, err)
			}
			meta.GzSize = n
		case "sha256":
			meta.SHA256 = strings.ToUpper(value)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan meta file: %w", err)
	}

	// Validate that at least SHA256 was found (required field)
	if meta.SHA256 == "" {
		return nil, fmt.Errorf("meta file missing sha256 field")
	}

	return meta, nil
}
