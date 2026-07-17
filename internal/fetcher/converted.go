package fetcher

import (
	"context"
	"encoding/xml"
	"fmt"
	"strings"
)

// ConvertedSource defines a converted data source with its GCS bucket and prefix.
type ConvertedSource struct {
	Name   string // Human-readable name (e.g., "NVD", "Debian")
	Bucket string // GCS bucket name (e.g., "cve-osv-conversion")
	Prefix string // Object prefix (e.g., "osv-output/")
}

// Known converted data sources maintained by the OSV.dev team.
var (
	SourceNVD = ConvertedSource{
		Name:   "NVD",
		Bucket: "cve-osv-conversion",
		Prefix: "osv-output/",
	}
	SourceDebian = ConvertedSource{
		Name:   "Debian",
		Bucket: "debian-osv",
		Prefix: "debian-cve-osv/",
	}
)

// gcsListResult represents the XML response from GCS bucket listing.
type gcsListResult struct {
	XMLName     xml.Name    `xml:"ListBucketResult"`
	Contents    []gcsObject `xml:"Contents"`
	IsTruncated bool        `xml:"IsTruncated"`
	NextMarker  string      `xml:"NextMarker"`
}

type gcsObject struct {
	Key          string `xml:"Key"`
	Size         int64  `xml:"Size"`
	LastModified string `xml:"LastModified"`
}

// FetchConvertedSource downloads all JSON files from a converted data source bucket.
// It lists objects via GCS XML API and downloads each .json file.
// Returns a map of ID (filename without .json) → JSON content.
func (f *Fetcher) FetchConvertedSource(ctx context.Context, source ConvertedSource, progress func(current, total int)) (map[string][]byte, error) {
	// Phase 1: List all .json files
	keys, err := f.listBucketObjects(ctx, source.Bucket, source.Prefix)
	if err != nil {
		return nil, fmt.Errorf("list bucket %s: %w", source.Bucket, err)
	}

	// Filter to only .json files (skip .placeholder, etc.)
	var jsonKeys []string
	for _, key := range keys {
		if strings.HasSuffix(key, ".json") {
			jsonKeys = append(jsonKeys, key)
		}
	}

	total := len(jsonKeys)
	results := make(map[string][]byte, total)

	// Phase 2: Download each file
	for i, key := range jsonKeys {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		url := fmt.Sprintf("https://storage.googleapis.com/%s/%s", source.Bucket, key)
		data, err := f.download(ctx, url)
		if err != nil {
			// Skip individual file errors, log and continue
			continue
		}

		// Extract ID from key: "prefix/CVE-2024-1234.json" → "CVE-2024-1234"
		name := key
		if idx := strings.LastIndex(name, "/"); idx >= 0 {
			name = name[idx+1:]
		}
		name = strings.TrimSuffix(name, ".json")
		results[name] = data

		if progress != nil && ((i+1)%100 == 0 || i+1 == total) {
			progress(i+1, total)
		}
	}

	return results, nil
}

// listBucketObjects lists all object keys in a GCS bucket with the given prefix.
// Handles pagination via marker.
func (f *Fetcher) listBucketObjects(ctx context.Context, bucket, prefix string) ([]string, error) {
	var allKeys []string
	marker := ""

	for {
		url := fmt.Sprintf("https://storage.googleapis.com/%s/?prefix=%s&max-keys=1000", bucket, prefix)
		if marker != "" {
			url += "&marker=" + marker
		}

		data, err := f.download(ctx, url)
		if err != nil {
			return nil, fmt.Errorf("list objects: %w", err)
		}

		var result gcsListResult
		if err := xml.Unmarshal(data, &result); err != nil {
			return nil, fmt.Errorf("parse XML response: %w", err)
		}

		for _, obj := range result.Contents {
			allKeys = append(allKeys, obj.Key)
		}

		if !result.IsTruncated {
			break
		}

		// Use NextMarker if available, otherwise use the last key
		if result.NextMarker != "" {
			marker = result.NextMarker
		} else if len(result.Contents) > 0 {
			marker = result.Contents[len(result.Contents)-1].Key
		} else {
			break
		}
	}

	return allKeys, nil
}

// FetchConvertedVulnerability downloads a single vulnerability JSON from a converted source.
func (f *Fetcher) FetchConvertedVulnerability(ctx context.Context, source ConvertedSource, id string) ([]byte, error) {
	url := fmt.Sprintf("https://storage.googleapis.com/%s/%s%s.json", source.Bucket, source.Prefix, id)
	data, err := f.download(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", id, err)
	}
	return data, nil
}
