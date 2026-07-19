package ingest

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kato83/mayu/internal/fetcher"
	"github.com/kato83/mayu/internal/model"
	"github.com/kato83/mayu/internal/parser"
	"github.com/kato83/mayu/internal/store"
)

const mitreSource = "MITRE"

// mitreBatchStore defines the interface for batch-upserting MITRE CVE records.
// This is used for type assertion against the concrete store implementation.
type mitreBatchStore interface {
	UpsertMITREBatch(ctx context.Context, entries []*model.MITRECVERecord) error
}

// ImportMITRE performs a full import of MITRE CVE data from the latest
// midnight baseline zip (CVEProject/cvelistV5). It downloads the baseline,
// parses each CVE JSON 5.x entry, skips non-PUBLISHED records, and stores
// results in batches.
func (ing *Ingester) ImportMITRE(ctx context.Context) (*Stats, error) {
	start := time.Now()
	stats := &Stats{
		Ecosystem:  mitreSource,
		IsFullSync: true,
	}

	ing.progress(Progress{Phase: "download", Message: "Starting MITRE CVE import (baseline zip)..."})

	entries, errCh, err := ing.fetcher.StreamMITREBaselineZip(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch MITRE baseline zip: %w", err)
	}

	// Process entries in a streaming pipeline: parse → batch → store.
	inserted, skipped, parseErrors, err := ing.streamParseMITRE(ctx, entries, errCh)
	if err != nil {
		return nil, err
	}

	stats.Inserted = inserted
	stats.Skipped = skipped
	stats.Errors = parseErrors
	stats.Total = inserted + skipped + parseErrors

	// Update sync state.
	syncState := &store.SyncState{
		Source:         mitreSource,
		LastModifiedAt: time.Now().UTC().Format(time.RFC3339),
		RecordCount:    int64(inserted),
	}
	if err := ing.store.UpdateSyncState(ctx, syncState); err != nil {
		ing.logger.Printf("warning: failed to update sync state: %v", err)
	}

	stats.Duration = time.Since(start)
	ing.progress(Progress{Phase: "store", Current: inserted, Total: stats.Total, Message: fmt.Sprintf("Done: %d CVEs imported in %s", inserted, stats.Duration.Round(time.Millisecond))})

	return stats, nil
}

// UpdateMITRE performs a delta update of MITRE CVE data using hourly delta
// releases published since the last sync. If the last sync is nil, invalid,
// or older than 24 hours, it falls back to a full import via ImportMITRE.
func (ing *Ingester) UpdateMITRE(ctx context.Context) (*Stats, error) {
	// Check last sync time.
	syncState, err := ing.store.GetSyncState(ctx, mitreSource)
	if err != nil {
		return nil, fmt.Errorf("get sync state: %w", err)
	}

	// If never synced or stale, do full import.
	if shouldFallbackToFullMITREImport(syncState) {
		msg := "No previous sync found, performing full import..."
		if syncState != nil {
			msg = "Last sync > 24h ago or invalid, performing full import..."
		}
		ing.progress(Progress{Phase: "download", Message: msg})
		return ing.ImportMITRE(ctx)
	}

	// Delta update using hourly delta zips.
	start := time.Now()
	stats := &Stats{
		Ecosystem:  mitreSource,
		IsFullSync: false,
	}

	since, _ := time.Parse(time.RFC3339, syncState.LastModifiedAt)

	ing.progress(Progress{Phase: "download", Message: fmt.Sprintf("Fetching MITRE delta zips since %s...", since.Format(time.RFC3339))})

	deltaZips, err := ing.fetcher.FetchMITREDeltaZips(ctx, since)
	if err != nil {
		return nil, fmt.Errorf("fetch MITRE delta zips: %w", err)
	}

	if len(deltaZips) == 0 {
		stats.Duration = time.Since(start)
		ing.progress(Progress{Phase: "download", Message: "No delta updates available"})

		// Still update sync state timestamp.
		newState := &store.SyncState{
			Source:         mitreSource,
			LastModifiedAt: time.Now().UTC().Format(time.RFC3339),
			RecordCount:    syncState.RecordCount,
		}
		if err := ing.store.UpdateSyncState(ctx, newState); err != nil {
			ing.logger.Printf("warning: failed to update sync state: %v", err)
		}
		return stats, nil
	}

	ing.progress(Progress{Phase: "download", Message: fmt.Sprintf("Processing %d delta zip(s)...", len(deltaZips))})

	var totalInserted, totalSkipped, totalErrors int

	for i, data := range deltaZips {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		ing.progress(Progress{Phase: "parse", Current: i + 1, Total: len(deltaZips), Message: fmt.Sprintf("Processing delta zip %d/%d...", i+1, len(deltaZips))})

		entries, errCh, err := ing.fetcher.StreamMITREDeltaZip(ctx, data)
		if err != nil {
			ing.logger.Printf("error opening delta zip %d: %v (skipping)", i+1, err)
			totalErrors++
			continue
		}

		inserted, skipped, parseErrors, err := ing.streamParseMITRE(ctx, entries, errCh)
		if err != nil {
			return nil, fmt.Errorf("process delta zip %d: %w", i+1, err)
		}

		totalInserted += inserted
		totalSkipped += skipped
		totalErrors += parseErrors
	}

	stats.Inserted = totalInserted
	stats.Skipped = totalSkipped
	stats.Errors = totalErrors
	stats.Total = totalInserted + totalSkipped + totalErrors

	// Update sync state.
	newState := &store.SyncState{
		Source:         mitreSource,
		LastModifiedAt: time.Now().UTC().Format(time.RFC3339),
		RecordCount:    syncState.RecordCount + int64(totalInserted),
	}
	if err := ing.store.UpdateSyncState(ctx, newState); err != nil {
		ing.logger.Printf("warning: failed to update sync state: %v", err)
	}

	stats.Duration = time.Since(start)
	ing.progress(Progress{Phase: "store", Current: totalInserted, Total: stats.Total, Message: fmt.Sprintf("Done: %d CVEs updated in %s", totalInserted, stats.Duration.Round(time.Millisecond))})

	return stats, nil
}

// streamParseMITRE reads ZipEntry values from a channel, parses each as a
// MITRE CVE record, skips non-PUBLISHED entries, and stores parsed records
// in batches. Returns (inserted, skipped, errors, err).
func (ing *Ingester) streamParseMITRE(ctx context.Context, entries <-chan fetcher.ZipEntry, errCh <-chan error) (inserted int, skipped int, parseErrors int, err error) {
	var batch []*model.MITRECVERecord
	processed := 0

	for entry := range entries {
		select {
		case <-ctx.Done():
			return inserted, skipped, parseErrors, ctx.Err()
		default:
		}

		processed++
		record, parseErr := ing.parser.ParseMITRERecord(entry.Data)
		if parseErr != nil {
			if errors.Is(parseErr, parser.ErrMITRENotPublished) {
				skipped++
			} else {
				ing.logger.Printf("parse error: %s: %v", entry.Name, parseErr)
				parseErrors++
			}
			continue
		}

		batch = append(batch, record)

		if len(batch) >= ing.batchSize {
			n, storeErr := ing.storeMITREBatches(ctx, batch)
			if storeErr != nil {
				return inserted, skipped, parseErrors, fmt.Errorf("store MITRE batch: %w", storeErr)
			}
			inserted += n
			batch = batch[:0]
			ing.progress(Progress{Phase: "store", Current: inserted, Total: 0, Message: fmt.Sprintf("Stored %d CVEs (%d processed, %d skipped)...", inserted, processed, skipped)})
		}
	}

	// Flush remaining batch.
	if len(batch) > 0 {
		n, storeErr := ing.storeMITREBatches(ctx, batch)
		if storeErr != nil {
			return inserted, skipped, parseErrors, fmt.Errorf("store MITRE batch: %w", storeErr)
		}
		inserted += n
	}

	// Check for streaming errors from the zip reader.
	if streamErr := <-errCh; streamErr != nil {
		return inserted, skipped, parseErrors, fmt.Errorf("stream MITRE zip: %w", streamErr)
	}

	return inserted, skipped, parseErrors, nil
}

// storeMITREBatches stores MITRE CVE entries in batches using the configured batch size.
// It type-asserts the store to the mitreBatchStore interface for access to UpsertMITREBatch.
func (ing *Ingester) storeMITREBatches(ctx context.Context, entries []*model.MITRECVERecord) (int, error) {
	if len(entries) == 0 {
		return 0, nil
	}

	ms, ok := ing.store.(mitreBatchStore)
	if !ok {
		return 0, fmt.Errorf("store does not support MITRE batch upsert")
	}

	total := len(entries)
	inserted := 0

	for i := 0; i < total; i += ing.batchSize {
		select {
		case <-ctx.Done():
			return inserted, ctx.Err()
		default:
		}

		end := i + ing.batchSize
		if end > total {
			end = total
		}

		batch := entries[i:end]
		if err := ms.UpsertMITREBatch(ctx, batch); err != nil {
			return inserted, fmt.Errorf("upsert MITRE batch at offset %d: %w", i, err)
		}

		inserted += len(batch)
	}

	return inserted, nil
}

// shouldFallbackToFullMITREImport determines whether the MITRE update should
// fall back to a full import based on the sync state. Returns true if:
//   - sync state is nil (never synced)
//   - last modified timestamp is empty or unparseable
//   - last sync was more than 24 hours ago (MITRE publishes hourly deltas)
func shouldFallbackToFullMITREImport(state *store.SyncState) bool {
	if state == nil {
		return true
	}
	if state.LastModifiedAt == "" {
		return true
	}
	lastSync, err := time.Parse(time.RFC3339, state.LastModifiedAt)
	if err != nil {
		return true
	}
	return time.Since(lastSync) > 24*time.Hour
}
