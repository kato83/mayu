package ingest

import (
	"context"
	"fmt"
	"time"

	"github.com/kato83/mayu/internal/fetcher"
	"github.com/kato83/mayu/internal/model"
	"github.com/kato83/mayu/internal/store"
)

const nvdNativeSource = "NVD-native"

// ImportNVDNative performs a full import of all NVD CVE data via JSON Feed 2.0.
// It downloads yearly feed files (2002 to current year), parses them, and stores
// each year's data in batches. Uses META file sha256 to skip unchanged feeds.
func (ing *Ingester) ImportNVDNative(ctx context.Context) (*Stats, error) {
	start := time.Now()
	stats := &Stats{
		Ecosystem:  nvdNativeSource,
		IsFullSync: true,
	}

	years := fetcher.NVDFeedYears()
	ing.progress(Progress{Phase: "download", Message: fmt.Sprintf("Starting NVD native import (%d yearly feeds)...", len(years))})

	var totalInserted int
	var totalErrors int

	for i, year := range years {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		ing.progress(Progress{Phase: "download", Current: i, Total: len(years), Message: fmt.Sprintf("Processing feed %d...", year)})

		inserted, errors, err := ing.importNVDYear(ctx, year)
		if err != nil {
			// Log error but continue with other years
			ing.logger.Printf("error importing NVD year %d: %v", year, err)
			totalErrors++
			continue
		}
		totalInserted += inserted
		totalErrors += errors
	}

	stats.Inserted = totalInserted
	stats.Total = totalInserted + totalErrors
	stats.Errors = totalErrors
	stats.Duration = time.Since(start)

	// Update sync state
	syncState := &store.SyncState{
		Source:         nvdNativeSource,
		LastModifiedAt: time.Now().UTC().Format(time.RFC3339),
		RecordCount:    int64(totalInserted),
	}
	if err := ing.store.UpdateSyncState(ctx, syncState); err != nil {
		ing.logger.Printf("warning: failed to update sync state: %v", err)
	}

	ing.progress(Progress{Phase: "store", Current: totalInserted, Total: stats.Total, Message: fmt.Sprintf("Done: %d CVEs imported in %s", totalInserted, stats.Duration.Round(time.Millisecond))})

	return stats, nil
}

// UpdateNVDNative performs a delta update using the NVD modified feed.
// If the last sync was more than 8 days ago, falls back to full import.
func (ing *Ingester) UpdateNVDNative(ctx context.Context) (*Stats, error) {
	// Check last sync time
	syncState, err := ing.store.GetSyncState(ctx, nvdNativeSource)
	if err != nil {
		return nil, fmt.Errorf("get sync state: %w", err)
	}

	// If never synced or last sync > 8 days ago, do full import
	if shouldFallbackToFullImport(syncState) {
		msg := "No previous sync found, performing full import..."
		if syncState != nil {
			msg = "Last sync > 8 days ago or invalid, performing full import..."
		}
		ing.progress(Progress{Phase: "download", Message: msg})
		return ing.ImportNVDNative(ctx)
	}

	// Delta update using modified feed
	start := time.Now()
	stats := &Stats{
		Ecosystem:  nvdNativeSource,
		IsFullSync: false,
	}

	ing.progress(Progress{Phase: "download", Message: "Downloading NVD modified feed..."})

	data, err := ing.fetcher.FetchNVDModifiedFeed(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch NVD modified feed: %w", err)
	}

	ing.progress(Progress{Phase: "parse", Message: "Parsing modified feed..."})

	result, err := ing.parser.ParseNVDFeed(data)
	if err != nil {
		return nil, fmt.Errorf("parse NVD modified feed: %w", err)
	}

	stats.Total = len(result.Entries) + len(result.Errors)
	stats.Errors = len(result.Errors)

	ing.progress(Progress{Phase: "store", Message: fmt.Sprintf("Storing %d modified CVEs...", len(result.Entries))})

	inserted, err := ing.storeNVDBatches(ctx, result.Entries)
	if err != nil {
		return nil, fmt.Errorf("store NVD entries: %w", err)
	}
	stats.Inserted = inserted

	// Update sync state
	newSyncState := &store.SyncState{
		Source:         nvdNativeSource,
		LastModifiedAt: time.Now().UTC().Format(time.RFC3339),
		RecordCount:    syncState.RecordCount + int64(inserted),
	}
	if err := ing.store.UpdateSyncState(ctx, newSyncState); err != nil {
		ing.logger.Printf("warning: failed to update sync state: %v", err)
	}

	stats.Duration = time.Since(start)
	ing.progress(Progress{Phase: "store", Current: inserted, Total: stats.Total, Message: fmt.Sprintf("Done: %d CVEs updated in %s", inserted, stats.Duration.Round(time.Millisecond))})

	return stats, nil
}

// shouldFallbackToFullImport determines whether the NVD update should fall back
// to a full import based on the sync state. Returns true if:
//   - sync state is nil (never synced)
//   - last modified timestamp is empty or unparseable
//   - last sync was more than 8 days ago
func shouldFallbackToFullImport(state *store.SyncState) bool {
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
	return time.Since(lastSync) > 8*24*time.Hour
}

// importNVDYear downloads, parses, and stores a single year's NVD feed.
func (ing *Ingester) importNVDYear(ctx context.Context, year int) (inserted int, errors int, err error) {
	// Download feed
	data, err := ing.fetcher.FetchNVDFeed(ctx, year)
	if err != nil {
		return 0, 0, fmt.Errorf("fetch NVD feed %d: %w", year, err)
	}

	// Parse
	result, err := ing.parser.ParseNVDFeed(data)
	if err != nil {
		return 0, 0, fmt.Errorf("parse NVD feed %d: %w", year, err)
	}

	for _, e := range result.Errors {
		ing.logger.Printf("parse error in %d feed: %s: %v", year, e.ID, e.Error)
	}

	// Store in batches
	n, err := ing.storeNVDBatches(ctx, result.Entries)
	if err != nil {
		return 0, len(result.Errors), fmt.Errorf("store NVD feed %d: %w", year, err)
	}

	return n, len(result.Errors), nil
}

// storeNVDBatches stores NVD entries in batches using the configured batch size.
func (ing *Ingester) storeNVDBatches(ctx context.Context, entries []*model.NVDCVE) (int, error) {
	if len(entries) == 0 {
		return 0, nil
	}

	// We need to access UpsertNVDBatch which is on *PostgresStore, not the Store interface.
	// Use type assertion to access the NVD-specific method.
	type nvdStore interface {
		UpsertNVDBatch(ctx context.Context, entries []*model.NVDCVE) error
	}

	ns, ok := ing.store.(nvdStore)
	if !ok {
		return 0, fmt.Errorf("store does not support NVD batch upsert")
	}

	total := len(entries)
	inserted := 0
	var allCVEIDs []string

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
		if err := ns.UpsertNVDBatch(ctx, batch); err != nil {
			return inserted, fmt.Errorf("upsert batch at offset %d: %w", i, err)
		}

		// Collect CVE IDs for summary refresh
		for _, e := range batch {
			allCVEIDs = append(allCVEIDs, e.ID)
		}

		inserted += len(batch)
		ing.progress(Progress{Phase: "store", Current: inserted, Total: total})
	}

	// Refresh vulnerability_summary for all imported CVEs
	ing.refreshSummary(ctx, allCVEIDs)

	return inserted, nil
}
