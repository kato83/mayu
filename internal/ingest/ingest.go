// Package ingest orchestrates the data ingestion pipeline:
// Fetcher → Parser → Store, supporting both full and delta imports.
package ingest

import (
	"context"
	"errors"
	"fmt"
	"log"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"

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

// WithStoreWorkers sets the number of parallel store workers for batch writes.
func WithStoreWorkers(n int) Option {
	return func(ing *Ingester) {
		if n > 0 {
			ing.storeWorkers = n
		}
	}
}

// WithJobRecorder enables job logging via the provided store.
func WithJobRecorder(s store.Store) Option {
	return func(ing *Ingester) {
		ing.jobStore = s
	}
}

// Ingester orchestrates the full ingestion pipeline.
type Ingester struct {
	fetcher      *fetcher.Fetcher
	parser       *parser.Parser
	store        store.Store
	logger       *log.Logger
	batchSize    int
	storeWorkers int
	progressFn   func(Progress)
	jobStore     store.Store // optional: enables ingest job recording
}

// DefaultStoreWorkers returns the default number of parallel store workers
// based on the number of CPU cores (NumCPU - 1, minimum 1).
func DefaultStoreWorkers() int {
	n := runtime.NumCPU() - 1
	if n < 1 {
		return 1
	}
	return n
}

// New creates a new Ingester.
func New(f *fetcher.Fetcher, p *parser.Parser, s store.Store, opts ...Option) *Ingester {
	ing := &Ingester{
		fetcher:      f,
		parser:       p,
		store:        s,
		logger:       log.Default(),
		batchSize:    100,
		storeWorkers: DefaultStoreWorkers(),
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

	// Start job recording
	recorder := ing.startJob(ctx, "osv", map[string]interface{}{
		"ecosystem": ecosystem,
		"update":    false,
	})
	defer func() {
		if recorder != nil {
			status := "success"
			var jobErr error
			if stats.Errors > 0 && stats.Inserted > 0 {
				status = "partial"
			} else if stats.Inserted == 0 && stats.Errors > 0 {
				status = "failed"
			}
			if ctx.Err() != nil {
				status = "failed"
				jobErr = ctx.Err()
			}
			recorder.Finish(ctx, status, stats.Total, stats.Inserted, stats.Errors, jobErr)
		}
	}()

	// Phase 1: Download and start streaming
	ing.progress(Progress{Phase: "download", Message: fmt.Sprintf("Downloading %s/all.zip...", ecosystem)})

	entries, errCh, totalEntries, err := ing.fetcher.StreamAllZip(ctx, ecosystem)
	if err != nil {
		return nil, fmt.Errorf("fetch all.zip for %s: %w", ecosystem, err)
	}

	// Phase 2+3: Parallel parse and store with multiple workers.
	ing.progress(Progress{Phase: "store", Message: fmt.Sprintf("Processing %d entries...", totalEntries)})

	inserted, processed, parseErrors, err := ing.streamParseAndStore(ctx, entries, errCh, totalEntries)
	if err != nil {
		return nil, err
	}

	stats.Inserted = inserted
	stats.Total = processed + parseErrors
	stats.Errors = parseErrors
	stats.Skipped = parseErrors

	// Update sync state
	syncState := &store.SyncState{
		Source:         ecosystem,
		SourceType:     "osv",
		LastModifiedAt: time.Now().UTC().Format(time.RFC3339),
		RecordCount:    int64(stats.Inserted),
	}
	if err := ing.store.UpdateSyncState(ctx, syncState); err != nil {
		ing.logger.Printf("warning: failed to update sync state: %v", err)
	}

	// Register ecosystem in osv_ecosystems
	if err := ing.store.UpsertOSVEcosystems(ctx, []string{ecosystem}); err != nil {
		ing.logger.Printf("warning: failed to upsert ecosystem: %v", err)
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

	// Start job recording
	recorder := ing.startJob(ctx, "osv", map[string]interface{}{
		"ecosystem": ecosystem,
		"update":    true,
	})
	defer func() {
		if recorder != nil {
			status := "success"
			var jobErr error
			if stats.Errors > 0 && stats.Inserted > 0 {
				status = "partial"
			} else if stats.Inserted == 0 && stats.Errors > 0 {
				status = "failed"
			}
			if ctx.Err() != nil {
				status = "failed"
				jobErr = ctx.Err()
			}
			recorder.Finish(ctx, status, stats.Total, stats.Inserted, stats.Errors, jobErr)
		}
	}()

	// Get last sync state
	syncState, err := ing.store.GetSyncState(ctx, ecosystem)
	if err != nil {
		return nil, fmt.Errorf("get sync state: %w", err)
	}
	if syncState == nil {
		// No previous sync — fall back to full import
		ing.logger.Printf("no previous sync state for %s, performing full import", ecosystem)
		// Cancel this job recorder; FullImport will create its own.
		if recorder != nil {
			recorder.Finish(ctx, "success", 0, 0, 0, nil)
			recorder = nil
		}
		return ing.FullImport(ctx, ecosystem)
	}

	since, err := time.Parse(time.RFC3339Nano, syncState.LastModifiedAt)
	if err != nil {
		since, err = time.Parse(time.RFC3339, syncState.LastModifiedAt)
		if err != nil {
			return nil, fmt.Errorf("parse last_modified_at: %w", err)
		}
	}

	// Phase 1: Download and parse CSV
	ing.progress(Progress{Phase: "download", Message: fmt.Sprintf("Fetching modified_id.csv for %s...", ecosystem)})

	csvData, err := ing.fetcher.FetchModifiedCSV(ctx, ecosystem)
	if err != nil {
		if errors.Is(err, fetcher.ErrNotFound) {
			// modified_id.csv does not exist for this ecosystem — fall back to full import
			ing.logger.Printf("modified_id.csv not found for %s, falling back to full import", ecosystem)
			ing.progress(Progress{Phase: "download", Message: fmt.Sprintf("modified_id.csv not found for %s, falling back to full import...", ecosystem)})
			// Cancel this job recorder; FullImport will create its own.
			if recorder != nil {
				recorder.Finish(ctx, "success", 0, 0, 0, nil)
				recorder = nil
			}
			return ing.FullImport(ctx, ecosystem)
		}
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

	// Phase 2+3: Fetch, parse, and store in parallel pipeline.
	batchCh := make(chan []*model.Vulnerability, ing.storeWorkers*2)

	// Producer: fetch and parse in parallel, dispatch batches.
	const maxDeltaWorkers = 10
	var fetchErrors int64

	producerDone := make(chan struct{})
	go func() {
		defer close(producerDone)
		defer close(batchCh)

		var mu sync.Mutex
		batch := make([]*model.Vulnerability, 0, ing.batchSize)

		fg, fCtx := errgroup.WithContext(ctx)
		fg.SetLimit(maxDeltaWorkers)

		for i, entry := range updated {
			i, entry := i, entry
			fg.Go(func() error {
				select {
				case <-fCtx.Done():
					return fCtx.Err()
				default:
				}

				data, err := ing.fetcher.FetchVulnerability(fCtx, ecosystem, entry.ID)
				if err != nil {
					ing.logger.Printf("fetch %s: %v (skipping)", entry.ID, err)
					if recorder != nil {
						recorder.RecordFailure(entry.ID, "fetch_error", err)
					}
					atomic.AddInt64(&fetchErrors, 1)
					return nil
				}

				vuln, err := ing.parser.Parse(data)
				if err != nil {
					ing.logger.Printf("parse %s: %v (skipping)", entry.ID, err)
					if recorder != nil {
						recorder.RecordFailure(entry.ID, "parse_error", err)
					}
					atomic.AddInt64(&fetchErrors, 1)
					return nil
				}

				mu.Lock()
				batch = append(batch, vuln)
				shouldFlush := len(batch) >= ing.batchSize
				var sendBatch []*model.Vulnerability
				if shouldFlush {
					sendBatch = make([]*model.Vulnerability, len(batch))
					copy(sendBatch, batch)
					batch = batch[:0]
				}
				mu.Unlock()

				if shouldFlush {
					select {
					case batchCh <- sendBatch:
					case <-fCtx.Done():
						return fCtx.Err()
					}
				}

				if (i+1)%10 == 0 || i+1 == stats.Total {
					ing.progress(Progress{Phase: "download", Current: i + 1, Total: stats.Total})
				}
				return nil
			})
		}

		if err := fg.Wait(); err != nil {
			return
		}

		// Flush remaining batch.
		mu.Lock()
		remaining := batch
		mu.Unlock()
		if len(remaining) > 0 {
			batchCh <- remaining
		}
	}()

	// Consumers: parallel store workers.
	inserted, storeErr := ing.consumeBatches(ctx, batchCh, 0)
	<-producerDone

	if storeErr != nil {
		return nil, fmt.Errorf("store vulnerabilities: %w", storeErr)
	}

	stats.Errors = int(fetchErrors)
	stats.Skipped = stats.Errors
	stats.Inserted = inserted

	// Note: vulnerability_summary refresh is handled inside consumeBatches
	// using the correct canonical IDs (CVE-* when available).

	// Update sync state with the latest modified timestamp from the CSV
	if len(updated) > 0 {
		// PostgreSQL timestamptz has microsecond precision, but CSV timestamps
		// may have nanosecond precision. Round up to the next microsecond to
		// ensure the same entry is not re-fetched due to precision loss.
		latest := updated[0].ModifiedAt
		if nanos := latest.Nanosecond() % 1000; nanos > 0 {
			latest = latest.Truncate(time.Microsecond).Add(time.Microsecond)
		}
		newSyncState := &store.SyncState{
			Source:         ecosystem,
			SourceType:     "osv",
			LastModifiedAt: latest.Format(time.RFC3339Nano),
			RecordCount:    syncState.RecordCount + int64(stats.Inserted),
		}
		if err := ing.store.UpdateSyncState(ctx, newSyncState); err != nil {
			ing.logger.Printf("warning: failed to update sync state: %v", err)
		}

		// Register ecosystem in osv_ecosystems
		if err := ing.store.UpsertOSVEcosystems(ctx, []string{ecosystem}); err != nil {
			ing.logger.Printf("warning: failed to upsert ecosystem: %v", err)
		}
	}

	stats.Duration = time.Since(start)
	ing.progress(Progress{Phase: "store", Current: stats.Inserted, Total: stats.Total - stats.Errors, Message: fmt.Sprintf("Done: %d inserted in %s", stats.Inserted, stats.Duration.Round(time.Millisecond))})

	return stats, nil
}

// storeBatches splits a slice of vulnerabilities into batches and stores them
// using parallel workers. Returns the total count inserted.
func (ing *Ingester) storeBatches(ctx context.Context, vulns []*model.Vulnerability) (int, error) {
	if len(vulns) == 0 {
		return 0, nil
	}

	// Split into batches and send to channel
	batchCh := make(chan []*model.Vulnerability, ing.storeWorkers*2)

	go func() {
		defer close(batchCh)
		for i := 0; i < len(vulns); i += ing.batchSize {
			end := i + ing.batchSize
			if end > len(vulns) {
				end = len(vulns)
			}
			select {
			case batchCh <- vulns[i:end]:
			case <-ctx.Done():
				return
			}
		}
	}()

	return ing.consumeBatches(ctx, batchCh, len(vulns))
}

// streamParseAndStore reads ZipEntry values from a channel, parses them, and
// stores them in parallel batches. This is the shared pipeline used by
// FullImport.
//
// It returns (inserted, processed, errors, err).
func (ing *Ingester) streamParseAndStore(ctx context.Context, entries <-chan fetcher.ZipEntry, errCh <-chan error, total int) (inserted int, processed int, parseErrors int, err error) {
	batchCh := make(chan []*model.Vulnerability, ing.storeWorkers*2)

	// Producer: read from entries channel, parse, and dispatch batches.
	var producerErr error
	var totalProcessed int64
	var totalErrors int64

	producerDone := make(chan struct{})
	go func() {
		defer close(producerDone)
		defer close(batchCh)

		batch := make([]*model.Vulnerability, 0, ing.batchSize)

		for entry := range entries {
			vuln, parseErr := ing.parser.Parse(entry.Data)
			if parseErr != nil {
				atomic.AddInt64(&totalErrors, 1)
				ing.logger.Printf("parse error: %s: %v", entry.Name, parseErr)
				continue
			}

			batch = append(batch, vuln)
			atomic.AddInt64(&totalProcessed, 1)

			if len(batch) >= ing.batchSize {
				sendBatch := make([]*model.Vulnerability, len(batch))
				copy(sendBatch, batch)
				select {
				case batchCh <- sendBatch:
				case <-ctx.Done():
					producerErr = ctx.Err()
					return
				}
				batch = batch[:0]
			}
		}

		// Flush remaining.
		if len(batch) > 0 {
			select {
			case batchCh <- batch:
			case <-ctx.Done():
				producerErr = ctx.Err()
				return
			}
		}
	}()

	// Consumers: parallel store workers.
	totalInserted, storeErr := ing.consumeBatches(ctx, batchCh, total)

	// Wait for producer to finish.
	<-producerDone
	if storeErr != nil {
		return 0, 0, 0, storeErr
	}
	if producerErr != nil {
		return 0, 0, 0, producerErr
	}

	// Check for streaming errors from the zip reader.
	if streamErr := <-errCh; streamErr != nil {
		return 0, 0, 0, fmt.Errorf("stream zip: %w", streamErr)
	}

	return totalInserted, int(totalProcessed), int(totalErrors), nil
}

// consumeBatches reads batches from a channel and writes them to the store
// using parallel workers. total is used for progress reporting (0 = unknown).
// Returns the total number of records inserted and all affected vulnerability IDs.
func (ing *Ingester) consumeBatches(ctx context.Context, batchCh <-chan []*model.Vulnerability, total int) (int, error) {
	var insertedTotal int64
	var mu sync.Mutex
	var collectedIDs []string

	g, gCtx := errgroup.WithContext(ctx)
	for i := 0; i < ing.storeWorkers; i++ {
		g.Go(func() error {
			var localIDs []string
			for batch := range batchCh {
				select {
				case <-gCtx.Done():
					return gCtx.Err()
				default:
				}

				if err := ing.store.UpsertBatch(gCtx, batch); err != nil {
					return fmt.Errorf("upsert batch: %w", err)
				}

				// Collect canonical vulnerability IDs for summary refresh
				for _, v := range batch {
					localIDs = append(localIDs, canonicalVulnID(v))
				}

				cur := int(atomic.AddInt64(&insertedTotal, int64(len(batch))))
				if total > 0 {
					ing.progress(Progress{Phase: "store", Current: cur, Total: total})
				} else {
					ing.progress(Progress{Phase: "store", Current: cur, Total: 0, Message: fmt.Sprintf("Stored %d entries...", cur)})
				}
			}
			// Merge local IDs into shared slice
			mu.Lock()
			collectedIDs = append(collectedIDs, localIDs...)
			mu.Unlock()
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return int(insertedTotal), err
	}

	// Refresh vulnerability_summary for all ingested vulnerabilities
	ing.refreshSummary(ctx, collectedIDs)

	return int(insertedTotal), nil
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

// startJob creates a new job record if job recording is enabled.
// Returns nil if jobStore is not configured or if job creation fails.
func (ing *Ingester) startJob(ctx context.Context, source string, args map[string]interface{}) *JobRecorder {
	if ing.jobStore == nil {
		return nil
	}
	jr, err := NewJobRecorder(ctx, ing.jobStore, source, args)
	if err != nil {
		ing.logger.Printf("warning: failed to create ingest job record: %v", err)
		return nil
	}
	return jr
}

// refreshSummary calls RefreshSummary on the store for the given vulnerability IDs.
// It logs warnings on failure but does not fail the import.
func (ing *Ingester) refreshSummary(ctx context.Context, vulnIDs []string) {
	if len(vulnIDs) == 0 {
		return
	}
	// Deduplicate
	seen := make(map[string]struct{}, len(vulnIDs))
	unique := make([]string, 0, len(vulnIDs))
	for _, id := range vulnIDs {
		if _, ok := seen[id]; !ok {
			seen[id] = struct{}{}
			unique = append(unique, id)
		}
	}

	total := len(unique)
	ing.progress(Progress{Phase: "summary", Message: fmt.Sprintf("Refreshing summary for %d vulnerabilities...", total)})

	// Process in batches with progress reporting
	const batchSize = 500
	for i := 0; i < total; i += batchSize {
		end := i + batchSize
		if end > total {
			end = total
		}
		if err := ing.store.RefreshSummary(ctx, unique[i:end]); err != nil {
			ing.logger.Printf("warning: failed to refresh summary for %d vulnerabilities: %v", end-i, err)
		}
		ing.progress(Progress{Phase: "summary", Current: end, Total: total})
	}
}

// canonicalVulnID determines the canonical vulnerability ID for display/tracking.
// Uses the same logic as the store layer: first CVE alias wins, otherwise OSV ID.
func canonicalVulnID(v *model.Vulnerability) string {
	for _, alias := range v.Aliases {
		if len(alias) > 4 && alias[:4] == "CVE-" {
			return alias
		}
	}
	return v.ID
}
