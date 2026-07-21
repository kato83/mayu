package ingest

import (
	"context"
	"fmt"
	"time"

	"github.com/kato83/mayu/internal/model"
	"github.com/kato83/mayu/internal/store"
)

const kevSource = "KEV"

// kevBatchStore defines the interface for batch-upserting KEV entries.
// This is used for type assertion against the concrete store implementation.
type kevBatchStore interface {
	UpsertKEVBatch(ctx context.Context, records []*model.KEVRecord) error
}

// ImportKEV performs a full import of the CISA KEV catalog.
// The catalog is a single JSON file (~1-2 MB) containing all known exploited
// vulnerabilities. Unlike EPSS (daily snapshots), KEV is a cumulative catalog
// that only grows — entries are never removed.
func (ing *Ingester) ImportKEV(ctx context.Context) (*Stats, error) {
	start := time.Now()
	stats := &Stats{
		Ecosystem:  kevSource,
		IsFullSync: true,
	}

	ing.progress(Progress{Phase: "download", Message: "Downloading CISA KEV catalog..."})

	catalog, err := ing.fetcher.FetchKEVCatalog(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch KEV catalog: %w", err)
	}

	ing.progress(Progress{Phase: "parse", Message: fmt.Sprintf("Downloaded KEV catalog: %d entries (version %s)", catalog.Count, catalog.CatalogVersion)})

	// Parse all entries into KEVRecords
	var records []*model.KEVRecord
	var parseErrors int
	for i := range catalog.Vulnerabilities {
		record, err := catalog.Vulnerabilities[i].ParseKEVRecord()
		if err != nil {
			ing.logger.Printf("parse KEV entry: %v (skipping)", err)
			parseErrors++
			continue
		}
		records = append(records, record)
	}

	stats.Total = len(records) + parseErrors
	stats.Errors = parseErrors
	stats.Skipped = parseErrors

	if len(records) == 0 {
		return nil, fmt.Errorf("no valid KEV entries found in catalog")
	}

	ing.progress(Progress{Phase: "parse", Message: fmt.Sprintf("Parsed %d KEV entries (%d skipped)", len(records), parseErrors)})

	// Store in batches
	inserted, err := ing.storeKEVBatches(ctx, records)
	if err != nil {
		return nil, fmt.Errorf("store KEV entries: %w", err)
	}
	stats.Inserted = inserted

	// Update sync state
	syncState := &store.SyncState{
		Source:         kevSource,
		LastModifiedAt: time.Now().UTC().Format(time.RFC3339),
		RecordCount:    int64(inserted),
	}
	if err := ing.store.UpdateSyncState(ctx, syncState); err != nil {
		ing.logger.Printf("warning: failed to update sync state: %v", err)
	}

	stats.Duration = time.Since(start)
	ing.progress(Progress{Phase: "store", Current: inserted, Total: stats.Total, Message: fmt.Sprintf("Done: %d KEV entries imported in %s", inserted, stats.Duration.Round(time.Millisecond))})

	return stats, nil
}

// UpdateKEV performs an update of the CISA KEV catalog.
// Since the KEV catalog is cumulative (entries are never removed, only added),
// this method:
//   - If never synced: downloads the full catalog.
//   - If synced within the last hour: skips (already up-to-date).
//   - Otherwise: downloads the full catalog (there is no delta mechanism).
//
// The KEV catalog is small (~1-2 MB) and updates infrequently (a few times per week),
// so a full re-download is always acceptable.
func (ing *Ingester) UpdateKEV(ctx context.Context) (*Stats, error) {
	// Check last sync time
	syncState, err := ing.store.GetSyncState(ctx, kevSource)
	if err != nil {
		return nil, fmt.Errorf("get sync state: %w", err)
	}

	// If never synced, do full import
	if syncState == nil {
		ing.progress(Progress{Phase: "download", Message: "No previous KEV sync found, performing full import..."})
		return ing.ImportKEV(ctx)
	}

	// Parse last sync time
	lastSync, err := time.Parse(time.RFC3339, syncState.LastModifiedAt)
	if err != nil {
		ing.progress(Progress{Phase: "download", Message: "Invalid last sync time, performing full import..."})
		return ing.ImportKEV(ctx)
	}

	// KEV updates a few times per week. If last sync was within 1 hour, skip.
	now := time.Now().UTC()
	if now.Sub(lastSync) < 1*time.Hour {
		stats := &Stats{
			Ecosystem:  kevSource,
			IsFullSync: false,
			Inserted:   0,
			Total:      0,
			Duration:   0,
		}
		ing.progress(Progress{Phase: "download", Message: "KEV catalog already up-to-date (synced within the last hour)"})
		return stats, nil
	}

	// More than 1 hour old — fetch fresh catalog
	ing.progress(Progress{Phase: "download", Message: "KEV catalog outdated, downloading latest..."})
	return ing.ImportKEV(ctx)
}

// storeKEVBatches stores KEV records in batches using the configured batch size.
// It type-asserts the store to the kevBatchStore interface.
func (ing *Ingester) storeKEVBatches(ctx context.Context, records []*model.KEVRecord) (int, error) {
	if len(records) == 0 {
		return 0, nil
	}

	ks, ok := ing.store.(kevBatchStore)
	if !ok {
		return 0, fmt.Errorf("store does not support KEV batch upsert")
	}

	total := len(records)
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

		batch := records[i:end]
		if err := ks.UpsertKEVBatch(ctx, batch); err != nil {
			return inserted, fmt.Errorf("upsert KEV batch at offset %d: %w", i, err)
		}

		// Collect CVE IDs for summary refresh
		for _, r := range batch {
			allCVEIDs = append(allCVEIDs, r.CVEID)
		}

		inserted += len(batch)
		ing.progress(Progress{Phase: "store", Current: inserted, Total: total})
	}

	// Refresh vulnerability_summary for all imported CVEs
	ing.refreshSummary(ctx, allCVEIDs)

	return inserted, nil
}
