// Package ingest orchestrates the data ingestion pipeline:
// Fetcher → Parser → Store, supporting both full and delta imports.
package ingest

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/kato83/mayu/internal/fetcher"
	"github.com/kato83/mayu/internal/model"
	"github.com/kato83/mayu/internal/parser"
	"github.com/kato83/mayu/internal/store"
)

// Stats contains statistics about an ingestion run.
type Stats struct {
	Ecosystem  string
	Total      int
	Inserted   int
	Skipped    int
	Errors     int
	Duration   time.Duration
	IsFullSync bool
}

// Progress reports current ingestion progress.
type Progress struct {
	Phase   string // "download", "parse", "store"
	Current int
	Total   int
	Message string
}

// Option configures the Ingester.
type Option func(*Ingester)

// WithLogger sets a custom logger.
func WithLogger(logger *log.Logger) Option {
	return func(ing *Ingester) {
		ing.logger = logger
	}
}

// WithBatchSize sets the number of vulnerabilities to insert per batch.
func WithBatchSize(size int) Option {
	return func(ing *Ingester) {
		ing.batchSize = size
	}
}

// WithProgress sets a progress callback.
func WithProgress(fn func(Progress)) Option {
	return func(ing *Ingester) {
		ing.progressFn = fn
	}
}

// Ingester orchestrates the full ingestion pipeline.
type Ingester struct {
	fetcher    *fetcher.Fetcher
	parser     *parser.Parser
	store      store.Store
	logger     *log.Logger
	batchSize  int
	progressFn func(Progress)
}

// New creates a new Ingester.
func New(f *fetcher.Fetcher, p *parser.Parser, s store.Store, opts ...Option) *Ingester {
	ing := &Ingester{
		fetcher:   f,
		parser:    p,
		store:     s,
		logger:    log.Default(),
		batchSize: 100,
	}
	for _, opt := range opts {
		opt(ing)
	}
	return ing
}

// FullImport performs a full import for the given ecosystem by downloading
// the all.zip, parsing entries in streaming fashion, and storing them in
// batches to minimize memory usage.
func (ing *Ingester) FullImport(ctx context.Context, ecosystem string) (*Stats, error) {
	start := time.Now()
	stats := &Stats{
		Ecosystem:  ecosystem,
		IsFullSync: true,
	}

	// Phase 1: Download and start streaming
	ing.progress(Progress{Phase: "download", Message: fmt.Sprintf("Downloading %s/all.zip...", ecosystem)})

	entries, errCh, err := ing.fetcher.StreamAllZip(ctx, ecosystem)
	if err != nil {
		return nil, fmt.Errorf("fetch all.zip for %s: %w", ecosystem, err)
	}

	// Phase 2+3: Stream parse and store in batches
	ing.progress(Progress{Phase: "store", Message: "Processing entries..."})

	batch := make([]*model.Vulnerability, 0, ing.batchSize)
	processed := 0

	for entry := range entries {
		vuln, err := ing.parser.Parse(entry.Data)
		if err != nil {
			stats.Errors++
			ing.logger.Printf("parse error: %s: %v", entry.Name, err)
			continue
		}

		batch = append(batch, vuln)
		processed++

		// Flush batch when full
		if len(batch) >= ing.batchSize {
			if err := ing.store.UpsertBatch(ctx, batch); err != nil {
				return nil, fmt.Errorf("upsert batch: %w", err)
			}
			stats.Inserted += len(batch)
			batch = batch[:0] // Reset slice, reuse backing array

			ing.progress(Progress{Phase: "store", Current: stats.Inserted, Total: 0, Message: fmt.Sprintf("Stored %d entries...", stats.Inserted)})
		}
	}

	// Check for streaming errors
	if streamErr := <-errCh; streamErr != nil {
		return nil, fmt.Errorf("stream zip: %w", streamErr)
	}

	// Flush remaining batch
	if len(batch) > 0 {
		if err := ing.store.UpsertBatch(ctx, batch); err != nil {
			return nil, fmt.Errorf("upsert final batch: %w", err)
		}
		stats.Inserted += len(batch)
	}

	stats.Total = processed + stats.Errors
	stats.Skipped = stats.Errors

	// Update sync state
	syncState := &store.SyncState{
		Source:         ecosystem,
		LastModifiedAt: time.Now().UTC().Format(time.RFC3339),
		RecordCount:    int64(stats.Inserted),
	}
	if err := ing.store.UpdateSyncState(ctx, syncState); err != nil {
		ing.logger.Printf("warning: failed to update sync state: %v", err)
	}

	stats.Duration = time.Since(start)
	ing.progress(Progress{Phase: "store", Current: stats.Inserted, Total: stats.Total, Message: fmt.Sprintf("Done: %d inserted in %s", stats.Inserted, stats.Duration.Round(time.Millisecond))})

	return stats, nil
}

// DeltaImport performs a delta import for the given ecosystem by checking
// modified_id.csv for entries newer than the last sync, then fetching and
// storing only those entries.
func (ing *Ingester) DeltaImport(ctx context.Context, ecosystem string) (*Stats, error) {
	start := time.Now()
	stats := &Stats{
		Ecosystem:  ecosystem,
		IsFullSync: false,
	}

	// Get last sync state
	syncState, err := ing.store.GetSyncState(ctx, ecosystem)
	if err != nil {
		return nil, fmt.Errorf("get sync state: %w", err)
	}
	if syncState == nil {
		// No previous sync — fall back to full import
		ing.logger.Printf("no previous sync state for %s, performing full import", ecosystem)
		return ing.FullImport(ctx, ecosystem)
	}

	since, err := time.Parse(time.RFC3339, syncState.LastModifiedAt)
	if err != nil {
		return nil, fmt.Errorf("parse last_modified_at: %w", err)
	}

	// Phase 1: Download and parse CSV
	ing.progress(Progress{Phase: "download", Message: fmt.Sprintf("Fetching modified_id.csv for %s...", ecosystem)})

	csvData, err := ing.fetcher.FetchModifiedCSV(ctx, ecosystem)
	if err != nil {
		return nil, fmt.Errorf("fetch modified_id.csv: %w", err)
	}

	entries, err := fetcher.ParseModifiedCSV(csvData, ecosystem)
	if err != nil {
		return nil, fmt.Errorf("parse modified_id.csv: %w", err)
	}

	// Filter to only entries modified since last sync
	updated := fetcher.FilterModifiedSince(entries, since)
	stats.Total = len(updated)

	if stats.Total == 0 {
		stats.Duration = time.Since(start)
		ing.progress(Progress{Phase: "download", Message: "No new updates found"})
		return stats, nil
	}

	ing.progress(Progress{Phase: "download", Message: fmt.Sprintf("Found %d updated entries since %s", stats.Total, since.Format(time.RFC3339))})

	// Phase 2: Fetch individual vulnerabilities
	var vulns []*model.Vulnerability
	for i, entry := range updated {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		data, err := ing.fetcher.FetchVulnerability(ctx, ecosystem, entry.ID)
		if err != nil {
			ing.logger.Printf("fetch %s: %v (skipping)", entry.ID, err)
			stats.Errors++
			continue
		}

		vuln, err := ing.parser.Parse(data)
		if err != nil {
			ing.logger.Printf("parse %s: %v (skipping)", entry.ID, err)
			stats.Errors++
			continue
		}

		vulns = append(vulns, vuln)

		if (i+1)%10 == 0 || i+1 == stats.Total {
			ing.progress(Progress{Phase: "download", Current: i + 1, Total: stats.Total})
		}
	}

	stats.Skipped = stats.Errors

	// Phase 3: Store in batches
	ing.progress(Progress{Phase: "store", Message: fmt.Sprintf("Storing %d vulnerabilities...", len(vulns))})

	inserted, err := ing.storeBatches(ctx, vulns)
	if err != nil {
		return nil, fmt.Errorf("store vulnerabilities: %w", err)
	}
	stats.Inserted = inserted

	// Update sync state with the latest modified timestamp from the CSV
	if len(updated) > 0 {
		newSyncState := &store.SyncState{
			Source:         ecosystem,
			LastModifiedAt: updated[0].ModifiedAt.Format(time.RFC3339), // First entry is the newest
			RecordCount:    syncState.RecordCount + int64(stats.Inserted),
		}
		if err := ing.store.UpdateSyncState(ctx, newSyncState); err != nil {
			ing.logger.Printf("warning: failed to update sync state: %v", err)
		}
	}

	stats.Duration = time.Since(start)
	ing.progress(Progress{Phase: "store", Current: stats.Inserted, Total: len(vulns), Message: fmt.Sprintf("Done: %d inserted in %s", stats.Inserted, stats.Duration.Round(time.Millisecond))})

	return stats, nil
}

// BulkImportAll performs a bulk import from the top-level all.zip, which
// contains vulnerabilities from all ecosystems in a single archive (~1.3GB).
// This is more efficient than importing each ecosystem separately when doing
// a complete fresh import.
func (ing *Ingester) BulkImportAll(ctx context.Context) (*Stats, error) {
	start := time.Now()
	stats := &Stats{
		Ecosystem:  "all",
		IsFullSync: true,
	}

	// Phase 1: Download the top-level all.zip.
	ing.progress(Progress{Phase: "download", Message: "Downloading top-level all.zip (~1.3GB)... this may take a while."})

	entries, errCh, err := ing.fetcher.StreamTopLevelAllZip(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch top-level all.zip: %w", err)
	}

	// Phase 2+3: Stream parse and store in batches.
	ing.progress(Progress{Phase: "store", Message: "Processing entries..."})

	batch := make([]*model.Vulnerability, 0, ing.batchSize)
	processed := 0

	for entry := range entries {
		vuln, err := ing.parser.Parse(entry.Data)
		if err != nil {
			stats.Errors++
			ing.logger.Printf("parse error: %s: %v", entry.Name, err)
			continue
		}

		batch = append(batch, vuln)
		processed++

		// Flush batch when full.
		if len(batch) >= ing.batchSize {
			if err := ing.store.UpsertBatch(ctx, batch); err != nil {
				return nil, fmt.Errorf("upsert batch: %w", err)
			}
			stats.Inserted += len(batch)
			batch = batch[:0]

			ing.progress(Progress{Phase: "store", Current: stats.Inserted, Total: 0, Message: fmt.Sprintf("Stored %d entries...", stats.Inserted)})
		}
	}

	// Check for streaming errors.
	if streamErr := <-errCh; streamErr != nil {
		return nil, fmt.Errorf("stream zip: %w", streamErr)
	}

	// Flush remaining batch.
	if len(batch) > 0 {
		if err := ing.store.UpsertBatch(ctx, batch); err != nil {
			return nil, fmt.Errorf("upsert final batch: %w", err)
		}
		stats.Inserted += len(batch)
	}

	stats.Total = processed + stats.Errors
	stats.Skipped = stats.Errors

	// Update sync state for "all".
	syncState := &store.SyncState{
		Source:         "all",
		LastModifiedAt: time.Now().UTC().Format(time.RFC3339),
		RecordCount:    int64(stats.Inserted),
	}
	if err := ing.store.UpdateSyncState(ctx, syncState); err != nil {
		ing.logger.Printf("warning: failed to update sync state: %v", err)
	}

	stats.Duration = time.Since(start)
	ing.progress(Progress{Phase: "store", Current: stats.Inserted, Total: stats.Total, Message: fmt.Sprintf("Done: %d inserted in %s", stats.Inserted, stats.Duration.Round(time.Millisecond))})

	return stats, nil
}

// storeBatches inserts vulnerabilities in batches, returning the total count inserted.
func (ing *Ingester) storeBatches(ctx context.Context, vulns []*model.Vulnerability) (int, error) {
	inserted := 0
	for i := 0; i < len(vulns); i += ing.batchSize {
		select {
		case <-ctx.Done():
			return inserted, ctx.Err()
		default:
		}

		end := i + ing.batchSize
		if end > len(vulns) {
			end = len(vulns)
		}

		batch := vulns[i:end]
		if err := ing.store.UpsertBatch(ctx, batch); err != nil {
			return inserted, fmt.Errorf("upsert batch [%d:%d]: %w", i, end, err)
		}

		inserted += len(batch)
		ing.progress(Progress{Phase: "store", Current: inserted, Total: len(vulns)})
	}
	return inserted, nil
}

// findLatestModified returns the most recent Modified time from a slice of vulnerabilities.
func findLatestModified(vulns []*model.Vulnerability) time.Time {
	var latest time.Time
	for _, v := range vulns {
		if v.Modified.After(latest) {
			latest = v.Modified
		}
	}
	return latest
}

// progress reports progress if a callback is set.
func (ing *Ingester) progress(p Progress) {
	if ing.progressFn != nil {
		ing.progressFn(p)
	}
}
