package fetcher

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/url"
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

		// Server-provided key: reject traversal and escape each path segment
		// while preserving "/" separators, to prevent URL escape / injection.
		safeKey, err := sanitizeObjectKey(key)
		if err != nil {
			// Skip malicious/malformed keys and continue.
			continue
		}

		u := fmt.Sprintf("https://storage.googleapis.com/%s/%s", source.Bucket, safeKey)
		data, err := f.download(ctx, u)
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

	// maxPages prevents infinite loops if the server returns the same marker repeatedly.
	const maxPages = 10000
	pages := 0

	for {
		pages++
		if pages > maxPages {
			return nil, fmt.Errorf("listing exceeded maximum of %d pages (possible infinite loop)", maxPages)
		}

		params := url.Values{}
		params.Set("prefix", prefix)
		params.Set("max-keys", "1000")
		if marker != "" {
			params.Set("marker", marker)
		}

		u := fmt.Sprintf("https://storage.googleapis.com/%s/?%s", bucket, params.Encode())

		data, err := f.download(ctx, u)
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
		newMarker := ""
		if result.NextMarker != "" {
			newMarker = result.NextMarker
		} else if len(result.Contents) > 0 {
			newMarker = result.Contents[len(result.Contents)-1].Key
		}

		// Detect stuck pagination (same marker returned)
		if newMarker == "" || newMarker == marker {
			break
		}
		marker = newMarker
	}

	return allKeys, nil
}

// sanitizeObjectKey validates a server-provided GCS object key and escapes
// each path segment while preserving "/" separators. It rejects keys that
// contain path-traversal sequences, absolute paths, or empty segments so a
// tampered bucket listing cannot escape the intended path or inject query
// parameters.
func sanitizeObjectKey(key string) (string, error) {
	if key == "" {
		return "", fmt.Errorf("empty object key")
	}
	if strings.HasPrefix(key, "/") {
		return "", fmt.Errorf("object key must not be absolute: %q", key)
	}

	segments := strings.Split(key, "/")
	escaped := make([]string, len(segments))
	for i, seg := range segments {
		if seg == "" {
			return "", fmt.Errorf("object key has empty segment: %q", key)
		}
		if seg == "." || seg == ".." {
			return "", fmt.Errorf("object key contains traversal sequence: %q", key)
		}
		escaped[i] = url.PathEscape(seg)
	}
	return strings.Join(escaped, "/"), nil
}

// FetchConvertedVulnerability downloads a single vulnerability JSON from a converted source.
func (f *Fetcher) FetchConvertedVulnerability(ctx context.Context, source ConvertedSource, id string) ([]byte, error) {
	if err := validatePathSegment("id", id); err != nil {
		return nil, err
	}

	u := fmt.Sprintf("https://storage.googleapis.com/%s/%s%s.json", source.Bucket, source.Prefix, url.PathEscape(id))
	data, err := f.download(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", id, err)
	}
	return data, nil
}
