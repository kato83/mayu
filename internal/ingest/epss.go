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


// EPSSv3StartDate is the release date of EPSS v3, which is the earliest date
// for which daily EPSS CSV data is reliably available from epss.cyentia.com.
// Used as the default --from value for backfill operations.
const EPSSv3StartDate = "2023-03-07"

// epssBackfillStore extends epssBatchStore with the ability to query which
// dates have already been imported (to avoid redundant downloads).
type epssBackfillStore interface {
	epssBatchStore
	GetEPSSImportedDates(ctx context.Context) (map[string]bool, error)
}

// BackfillEPSS imports historical EPSS daily scores from the EPSS v3 start date
// (2023-03-07) through today. Dates that already have scores in the database
// are skipped automatically. This is the recommended way to build up the
// time-series data needed for accurate LEV computation.
func (ing *Ingester) BackfillEPSS(ctx context.Context) (*Stats, error) {
	today := time.Now().UTC().Format("2006-01-02")
	return ing.BackfillEPSSRange(ctx, EPSSv3StartDate, today)
}

// BackfillEPSSRange imports historical EPSS daily scores for the specified
// date range [from, to] inclusive. Both dates must be in YYYY-MM-DD format.
// Dates that already have scores in the database are skipped automatically.
//
// Each day's CSV is approximately 5-7 MB compressed, containing ~200,000+ scores.
// The backfill processes dates sequentially with progress reporting.
//
// Example:
//
//	ing.BackfillEPSSRange(ctx, "2024-01-01", "2025-07-19")
func (ing *Ingester) BackfillEPSSRange(ctx context.Context, from, to string) (*Stats, error) {
	start := time.Now()
	stats := &Stats{
		Ecosystem:  epssSource,
		IsFullSync: true,
	}

	// Parse and validate date range
	fromDate, err := time.Parse("2006-01-02", from)
	if err != nil {
		return nil, fmt.Errorf("invalid --from date %q: must be YYYY-MM-DD", from)
	}
	toDate, err := time.Parse("2006-01-02", to)
	if err != nil {
		return nil, fmt.Errorf("invalid --to date %q: must be YYYY-MM-DD", to)
	}

	epssStart, _ := time.Parse("2006-01-02", EPSSv3StartDate)
	if fromDate.Before(epssStart) {
		return nil, fmt.Errorf("--from date %s is before EPSS v3 availability (%s)", from, EPSSv3StartDate)
	}
	today := time.Now().UTC().Truncate(24 * time.Hour)
	if toDate.After(today) {
		toDate = today
	}
	if fromDate.After(toDate) {
		return nil, fmt.Errorf("--from date %s is after --to date %s", from, to)
	}

	// Calculate total days in range
	totalDays := int(toDate.Sub(fromDate).Hours()/24) + 1

	ing.progress(Progress{Phase: "download", Message: fmt.Sprintf(
		"EPSS backfill: %s to %s (%d days)", from, toDate.Format("2006-01-02"), totalDays)})

	// Query already-imported dates to skip them
	var importedDates map[string]bool
	bs, ok := ing.store.(epssBackfillStore)
	if ok {
		importedDates, err = bs.GetEPSSImportedDates(ctx)
		if err != nil {
			ing.logger.Printf("warning: could not fetch imported dates (will import all): %v", err)
			importedDates = nil
		}
	}

	skippedDays := 0
	if importedDates != nil {
		for d := fromDate; !d.After(toDate); d = d.AddDate(0, 0, 1) {
			if importedDates[d.Format("2006-01-02")] {
				skippedDays++
			}
		}
	}

	pendingDays := totalDays - skippedDays
	if pendingDays == 0 {
		stats.Duration = time.Since(start)
		stats.Skipped = totalDays
		ing.progress(Progress{Phase: "store", Message: fmt.Sprintf(
			"All %d days already imported, nothing to do.", totalDays)})
		return stats, nil
	}

	ing.progress(Progress{Phase: "download", Message: fmt.Sprintf(
		"  %d days to import (%d already in DB, skipping)", pendingDays, skippedDays)})

	// Process each date sequentially
	processedDays := 0
	totalInserted := 0
	failedDays := 0

	for d := fromDate; !d.After(toDate); d = d.AddDate(0, 0, 1) {
		select {
		case <-ctx.Done():
			stats.Duration = time.Since(start)
			stats.Total = processedDays
			stats.Inserted = totalInserted
			stats.Skipped = skippedDays
			stats.Errors = failedDays
			return stats, ctx.Err()
		default:
		}

		dateStr := d.Format("2006-01-02")

		// Skip already-imported dates
		if importedDates != nil && importedDates[dateStr] {
			continue
		}

		processedDays++

		// Download and parse
		scores, err := ing.fetcher.FetchEPSSByCSVDate(ctx, dateStr)
		if err != nil {
			// Log the error but continue with next date (transient failures, missing dates, etc.)
			ing.logger.Printf("warning: failed to fetch EPSS for %s: %v (skipping)", dateStr, err)
			failedDays++
			ing.progress(Progress{Phase: "store", Current: processedDays, Total: pendingDays,
				Message: fmt.Sprintf("  [%d/%d] %s - FAILED: %v", processedDays, pendingDays, dateStr, err)})
			continue
		}

		// Store
		inserted, err := ing.storeEPSSBatches(ctx, scores)
		if err != nil {
			ing.logger.Printf("warning: failed to store EPSS for %s: %v (skipping)", dateStr, err)
			failedDays++
			ing.progress(Progress{Phase: "store", Current: processedDays, Total: pendingDays,
				Message: fmt.Sprintf("  [%d/%d] %s - STORE FAILED: %v", processedDays, pendingDays, dateStr, err)})
			continue
		}

		totalInserted += inserted
		ing.progress(Progress{Phase: "store", Current: processedDays, Total: pendingDays,
			Message: fmt.Sprintf("  [%d/%d] %s - %d scores", processedDays, pendingDays, dateStr, inserted)})
	}

	// Update sync state
	syncState := &store.SyncState{
		Source:         epssSource,
		LastModifiedAt: time.Now().UTC().Format(time.RFC3339),
		RecordCount:    int64(totalInserted),
	}
	if err := ing.store.UpdateSyncState(ctx, syncState); err != nil {
		ing.logger.Printf("warning: failed to update sync state: %v", err)
	}

	stats.Duration = time.Since(start)
	stats.Total = processedDays
	stats.Inserted = totalInserted
	stats.Skipped = skippedDays
	stats.Errors = failedDays

	ing.progress(Progress{Phase: "store", Current: processedDays, Total: pendingDays,
		Message: fmt.Sprintf("Done: %d days processed, %d scores inserted, %d skipped, %d failed in %s",
			processedDays, totalInserted, skippedDays, failedDays, stats.Duration.Round(time.Second))})

	return stats, nil
}
