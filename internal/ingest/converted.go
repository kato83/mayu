package ingest

import (
	"context"
	"fmt"
	"time"

	"github.com/kato83/mayu/internal/fetcher"
	"github.com/kato83/mayu/internal/parser"
	"github.com/kato83/mayu/internal/store"
)

// ImportConvertedSource performs a full import from a converted data source
// (e.g., NVD CVEs, Debian Security Advisories) that uses a separate GCS bucket.
func (ing *Ingester) ImportConvertedSource(ctx context.Context, source fetcher.ConvertedSource) (*Stats, error) {
	start := time.Now()
	stats := &Stats{
		Ecosystem:  source.Name,
		IsFullSync: true,
	}

	// Phase 1: Download all files from the bucket
	ing.progress(Progress{Phase: "download", Message: fmt.Sprintf("Listing and downloading %s data from gs://%s/%s...", source.Name, source.Bucket, source.Prefix)})

	files, err := ing.fetcher.FetchConvertedSource(ctx, source, func(current, total int) {
		ing.progress(Progress{Phase: "download", Current: current, Total: total})
	})
	if err != nil {
		return nil, fmt.Errorf("fetch converted source %s: %w", source.Name, err)
	}

	stats.Total = len(files)
	ing.progress(Progress{Phase: "download", Current: stats.Total, Total: stats.Total, Message: fmt.Sprintf("Downloaded %d files", stats.Total)})

	// Phase 2: Parse
	ing.progress(Progress{Phase: "parse", Message: fmt.Sprintf("Parsing %d entries...", stats.Total)})

	result, err := ing.parser.ParseBatch(files)
	if err != nil {
		return nil, fmt.Errorf("parse batch: %w", err)
	}

	stats.Skipped = len(result.Errors)
	stats.Errors = len(result.Errors)
	for _, e := range result.Errors {
		ing.logger.Printf("parse error: %s: %v", e.ID, e.Error)
	}

	ing.progress(Progress{Phase: "parse", Current: len(result.Vulnerabilities), Total: stats.Total, Message: fmt.Sprintf("Parsed %d entries (%d errors)", len(result.Vulnerabilities), stats.Errors)})

	// Phase 3: Store in batches
	ing.progress(Progress{Phase: "store", Message: fmt.Sprintf("Storing %d vulnerabilities...", len(result.Vulnerabilities))})

	inserted, err := ing.storeBatches(ctx, result.Vulnerabilities)
	if err != nil {
		return nil, fmt.Errorf("store vulnerabilities: %w", err)
	}
	stats.Inserted = inserted

	// Update sync state
	lastModified := findLatestModified(result.Vulnerabilities)
	if !lastModified.IsZero() {
		syncState := &store.SyncState{
			Ecosystem:      source.Name,
			LastModifiedAt: lastModified.Format(time.RFC3339),
			RecordCount:    int64(stats.Inserted),
		}
		if err := ing.store.UpdateSyncState(ctx, syncState); err != nil {
			ing.logger.Printf("warning: failed to update sync state: %v", err)
		}
	}

	stats.Duration = time.Since(start)
	ing.progress(Progress{Phase: "store", Current: stats.Inserted, Total: len(result.Vulnerabilities), Message: fmt.Sprintf("Done: %d inserted in %s", stats.Inserted, stats.Duration.Round(time.Millisecond))})

	return stats, nil
}

// ConvertedSources returns the list of known converted data sources.
func ConvertedSources() []fetcher.ConvertedSource {
	return []fetcher.ConvertedSource{
		fetcher.SourceNVD,
		fetcher.SourceDebian,
	}
}

// GetConvertedSource returns a converted source by name, or nil if not found.
func GetConvertedSource(name string) *fetcher.ConvertedSource {
	sources := map[string]fetcher.ConvertedSource{
		"nvd":    fetcher.SourceNVD,
		"debian": fetcher.SourceDebian,
	}
	// Case-insensitive lookup
	for key, src := range sources {
		if key == name || src.Name == name {
			return &src
		}
	}
	return nil
}

// Ensure Ingester uses the parser and fetcher fields (avoid unused import in converted.go)
var _ = (*Ingester)(nil)
var _ = (*parser.Parser)(nil)
