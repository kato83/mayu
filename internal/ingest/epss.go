package ingest

import (
	"context"
	"fmt"
	"time"

	"github.com/kato83/mayu/internal/model"
	"github.com/kato83/mayu/internal/store"
)

const epssSource = "EPSS"

// epssBatchStore defines the interface for batch-upserting EPSS score records.
// This is used for type assertion against the concrete store implementation.
// The interface pattern is designed to be reusable for future scoring systems
// (e.g., LEV/NIST CSWP 41) which will follow the same batch upsert pattern.
type epssBatchStore interface {
	UpsertEPSSBatch(ctx context.Context, scores []*model.EPSSScore) error
}

// ImportEPSS performs a full import of EPSS scores from the bulk CSV download.
// This downloads the current day's scores (~200,000+ CVEs) and stores them all.
// It is the recommended method for initial import or daily refresh.
func (ing *Ingester) ImportEPSS(ctx context.Context) (*Stats, error) {
	start := time.Now()
	stats := &Stats{
		Ecosystem:  epssSource,
		IsFullSync: true,
	}

	ing.progress(Progress{Phase: "download", Message: "Downloading EPSS scores (CSV bulk)..."})

	scores, err := ing.fetcher.FetchEPSSByCSV(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch EPSS CSV: %w", err)
	}

	stats.Total = len(scores)
	ing.progress(Progress{Phase: "parse", Message: fmt.Sprintf("Downloaded %d EPSS scores", len(scores))})

	// Store in batches
	inserted, err := ing.storeEPSSBatches(ctx, scores)
	if err != nil {
		return nil, fmt.Errorf("store EPSS scores: %w", err)
	}
	stats.Inserted = inserted

	// Update sync state
	syncState := &store.SyncState{
		Source:         epssSource,
		LastModifiedAt: time.Now().UTC().Format(time.RFC3339),
		RecordCount:    int64(inserted),
	}
	if err := ing.store.UpdateSyncState(ctx, syncState); err != nil {
		ing.logger.Printf("warning: failed to update sync state: %v", err)
	}

	stats.Duration = time.Since(start)
	ing.progress(Progress{Phase: "store", Current: inserted, Total: stats.Total, Message: fmt.Sprintf("Done: %d EPSS scores imported in %s", inserted, stats.Duration.Round(time.Millisecond))})

	return stats, nil
}

// ImportEPSSByDate imports EPSS scores for a specific date (YYYY-MM-DD).
// Useful for backfilling historical data or importing a specific day's scores.
func (ing *Ingester) ImportEPSSByDate(ctx context.Context, date string) (*Stats, error) {
	start := time.Now()
	stats := &Stats{
		Ecosystem:  epssSource,
		IsFullSync: true,
	}

	ing.progress(Progress{Phase: "download", Message: fmt.Sprintf("Downloading EPSS scores for %s...", date)})

	scores, err := ing.fetcher.FetchEPSSByCSVDate(ctx, date)
	if err != nil {
		return nil, fmt.Errorf("fetch EPSS CSV for %s: %w", date, err)
	}

	stats.Total = len(scores)
	ing.progress(Progress{Phase: "parse", Message: fmt.Sprintf("Downloaded %d EPSS scores for %s", len(scores), date)})

	// Store in batches
	inserted, err := ing.storeEPSSBatches(ctx, scores)
	if err != nil {
		return nil, fmt.Errorf("store EPSS scores: %w", err)
	}
	stats.Inserted = inserted

	// Update sync state
	syncState := &store.SyncState{
		Source:         epssSource,
		LastModifiedAt: time.Now().UTC().Format(time.RFC3339),
		RecordCount:    int64(inserted),
	}
	if err := ing.store.UpdateSyncState(ctx, syncState); err != nil {
		ing.logger.Printf("warning: failed to update sync state: %v", err)
	}

	stats.Duration = time.Since(start)
	ing.progress(Progress{Phase: "store", Current: inserted, Total: stats.Total, Message: fmt.Sprintf("Done: %d EPSS scores imported in %s", inserted, stats.Duration.Round(time.Millisecond))})

	return stats, nil
}

// UpdateEPSS performs a delta-style update of EPSS scores.
// Since EPSS scores are recalculated daily for ALL CVEs, there is no true
// "delta" mechanism — each day is a complete snapshot. This method:
//   - If never synced or last sync > 1 day ago: downloads the current CSV (full refresh).
//   - If synced within the last day: skips (already up-to-date).
//
// For daily automation, schedule ImportEPSS once per day (after UTC 00:00).
func (ing *Ingester) UpdateEPSS(ctx context.Context) (*Stats, error) {
	// Check last sync time
	syncState, err := ing.store.GetSyncState(ctx, epssSource)
	if err != nil {
		return nil, fmt.Errorf("get sync state: %w", err)
	}

	// If never synced, do full import
	if syncState == nil {
		ing.progress(Progress{Phase: "download", Message: "No previous EPSS sync found, performing full import..."})
		return ing.ImportEPSS(ctx)
	}

	// Parse last sync time
	lastSync, err := time.Parse(time.RFC3339, syncState.LastModifiedAt)
	if err != nil {
		ing.progress(Progress{Phase: "download", Message: "Invalid last sync time, performing full import..."})
		return ing.ImportEPSS(ctx)
	}

	// EPSS updates daily. If last sync was today (same UTC date), skip.
	now := time.Now().UTC()
	if lastSync.UTC().Year() == now.Year() &&
		lastSync.UTC().YearDay() == now.YearDay() {
		stats := &Stats{
			Ecosystem:  epssSource,
			IsFullSync: false,
			Inserted:   0,
			Total:      0,
			Duration:   0,
		}
		ing.progress(Progress{Phase: "download", Message: "EPSS scores already up-to-date (synced today)"})
		return stats, nil
	}

	// More than a day old — fetch fresh scores
	ing.progress(Progress{Phase: "download", Message: "EPSS scores outdated, downloading latest..."})
	return ing.ImportEPSS(ctx)
}

// storeEPSSBatches stores EPSS scores in batches using the configured batch size.
// It type-asserts the store to the epssBatchStore interface.
func (ing *Ingester) storeEPSSBatches(ctx context.Context, scores []*model.EPSSScore) (int, error) {
	if len(scores) == 0 {
		return 0, nil
	}

	es, ok := ing.store.(epssBatchStore)
	if !ok {
		return 0, fmt.Errorf("store does not support EPSS batch upsert")
	}

	total := len(scores)
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

		batch := scores[i:end]
		if err := es.UpsertEPSSBatch(ctx, batch); err != nil {
			return inserted, fmt.Errorf("upsert EPSS batch at offset %d: %w", i, err)
		}

		inserted += len(batch)
		ing.progress(Progress{Phase: "store", Current: inserted, Total: total})
	}

	return inserted, nil
}
