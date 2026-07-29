package ingest

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/kato83/mayu/internal/fetcher"
	"github.com/kato83/mayu/internal/model"
	"github.com/kato83/mayu/internal/store"
)

const nvdNativeSource = "NVD-native"

// nvdEntryCounter is an optional interface for counting NVD entries by year.
// Used to get accurate record counts after delta updates.
type nvdEntryCounter interface {
	CountNVDEntriesByYear(ctx context.Context, year int) (int64, error)
}

// nvdYearSource returns the sync_state source key for a specific NVD year feed.
func nvdYearSource(year int) string {
	return fmt.Sprintf("NVD-native:%d", year)
}

// nvdModifiedFeedWindow is the maximum age of a year's sync_state before
// we consider the modified feed insufficient and fall back to a full year
// feed download. NVD's modified feed covers the last 8 days.
const nvdModifiedFeedWindow = 8 * 24 * time.Hour

// ImportNVDNative performs an intelligent import of NVD CVE data.
// For each year (2002 to current), it checks the year-level sync_state
// and automatically selects the optimal strategy:
//   - No sync_state or >8 days stale → download the full year feed
//   - ≤8 days since last sync → apply only modified CVEs from the modified feed
//
// This eliminates the need for a separate --update flag.
func (ing *Ingester) ImportNVDNative(ctx context.Context) (*Stats, error) {
	return ing.ImportNVDNativeYears(ctx, nil)
}

// ImportNVDNativeYears performs NVD import for the specified years.
// If years is nil or empty, all available years (2002 to current) are imported.
// When a single explicit year is given (--year flag), the full year feed is
// always downloaded regardless of sync_state (force refresh behavior).
func (ing *Ingester) ImportNVDNativeYears(ctx context.Context, years []int) (*Stats, error) {
	start := time.Now()
	stats := &Stats{
		Ecosystem:  nvdNativeSource,
		IsFullSync: true,
	}

	explicitYear := len(years) == 1
	if len(years) == 0 {
		years = fetcher.NVDFeedYears()
	}

	// Start job recording
	recorder := ing.startJob(ctx, "nvd", map[string]interface{}{
		"native":        true,
		"years":         years,
		"explicit_year": explicitYear,
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

	// For explicit --year, skip modified feed and just do full year import.
	if explicitYear {
		year := years[0]
		ing.progress(Progress{Phase: "download", Message: fmt.Sprintf("Importing NVD year %d (full feed)...", year)})

		inserted, errors, err := ing.importNVDYear(ctx, year)
		if err != nil {
			return nil, fmt.Errorf("import NVD year %d: %w", year, err)
		}

		// Update year checkpoint
		yearState := &store.SyncState{
			Source:       nvdYearSource(year),
			SourceType:   "nvd",
			LastSyncedAt: start.UTC().Format(time.RFC3339),
			RecordCount:  int64(inserted),
		}
		if err := ing.store.UpdateSyncState(ctx, yearState); err != nil {
			ing.logger.Printf("warning: failed to update sync state for NVD year %d: %v", year, err)
		}

		stats.Inserted = inserted
		stats.Errors = errors
		stats.Total = inserted + errors
		stats.Duration = time.Since(start)

		ing.progress(Progress{Phase: "store", Current: inserted, Total: stats.Total,
			Message: fmt.Sprintf("Done: %d CVEs imported for %d in %s", inserted, year, stats.Duration.Round(time.Millisecond))})
		return stats, nil
	}

	// Multi-year flow: download modified feed first, then process each year.
	ing.progress(Progress{Phase: "download", Message: "Downloading NVD modified feed (last 8 days)..."})

	var modifiedEntries []*model.NVDCVE
	modifiedData, modFetchErr := ing.fetcher.FetchNVDModifiedFeed(ctx)
	if modFetchErr != nil {
		// Modified feed failure is non-fatal; we'll fall back to full year feeds for all years.
		ing.logger.Printf("warning: failed to fetch NVD modified feed: %v (all years will use full feed)", modFetchErr)
	} else {
		result, parseErr := ing.parser.ParseNVDFeed(modifiedData)
		if parseErr != nil {
			ing.logger.Printf("warning: failed to parse NVD modified feed: %v (all years will use full feed)", parseErr)
		} else {
			modifiedEntries = result.Entries
			ing.progress(Progress{Phase: "download", Message: fmt.Sprintf("Modified feed: %d CVEs available for delta updates", len(modifiedEntries))})
		}
	}

	// Build a map of modified CVEs grouped by year for quick lookup.
	modifiedByYear := groupCVEsByYear(modifiedEntries)

	// Classify each year's strategy based on its sync_state.
	type yearPlan struct {
		Year     int
		Strategy string // "full" or "delta"
	}
	var plans []yearPlan
	var fullCount, deltaCount int

	for _, y := range years {
		state, err := ing.store.GetSyncState(ctx, nvdYearSource(y))
		if err != nil {
			ing.logger.Printf("warning: failed to check sync state for NVD year %d: %v (will do full import)", y, err)
			plans = append(plans, yearPlan{Year: y, Strategy: "full"})
			fullCount++
			continue
		}

		if needsFullYearImport(state) || modifiedEntries == nil {
			plans = append(plans, yearPlan{Year: y, Strategy: "full"})
			fullCount++
		} else {
			plans = append(plans, yearPlan{Year: y, Strategy: "delta"})
			deltaCount++
		}
	}

	ing.progress(Progress{Phase: "download", Message: fmt.Sprintf(
		"Plan: %d year(s) full import, %d year(s) delta update", fullCount, deltaCount)})

	// Execute plans
	var totalInserted, totalErrors int

	for i, plan := range plans {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		ing.progress(Progress{Phase: "download", Current: i + 1, Total: len(plans),
			Message: fmt.Sprintf("[%d/%d] Year %d (%s)...", i+1, len(plans), plan.Year, plan.Strategy)})

		var inserted, errors int
		var err error

		switch plan.Strategy {
		case "full":
			inserted, errors, err = ing.importNVDYear(ctx, plan.Year)
		case "delta":
			yearCVEs := modifiedByYear[plan.Year]
			if len(yearCVEs) == 0 {
				// No modifications for this year — just update timestamp.
				ing.progress(Progress{Phase: "store", Message: fmt.Sprintf("  Year %d: no modifications in feed, skipping", plan.Year)})
				yearState := &store.SyncState{
					Source:       nvdYearSource(plan.Year),
					SourceType:   "nvd",
					LastSyncedAt: start.UTC().Format(time.RFC3339),
					RecordCount:  0, // keep existing count by using the state directly
				}
				// Preserve existing record count
				existingState, _ := ing.store.GetSyncState(ctx, nvdYearSource(plan.Year))
				if existingState != nil {
					yearState.RecordCount = existingState.RecordCount
				}
				if stateErr := ing.store.UpdateSyncState(ctx, yearState); stateErr != nil {
					ing.logger.Printf("warning: failed to update sync state for NVD year %d: %v", plan.Year, stateErr)
				}
				continue
			}
			inserted, err = ing.storeNVDBatches(ctx, yearCVEs)
			errors = 0
		}

		if err != nil {
			ing.logger.Printf("error importing NVD year %d (%s): %v", plan.Year, plan.Strategy, err)
			if recorder != nil {
				recorder.RecordFailure(fmt.Sprintf("NVD-feed-%d", plan.Year), "import_error", err)
			}
			totalErrors++
			continue
		}

		totalInserted += inserted
		totalErrors += errors

		// Checkpoint: record this year as successfully imported.
		yearState := &store.SyncState{
			Source:       nvdYearSource(plan.Year),
			SourceType:   "nvd",
			LastSyncedAt: start.UTC().Format(time.RFC3339),
			RecordCount:  int64(inserted),
		}
		// For delta updates, the modified feed may contain both new and updated CVEs,
		// so we query the actual DB count for an accurate record_count.
		if plan.Strategy == "delta" {
			if counter, ok := ing.store.(nvdEntryCounter); ok {
				if count, err := counter.CountNVDEntriesByYear(ctx, plan.Year); err == nil {
					yearState.RecordCount = count
				} else {
					ing.logger.Printf("warning: failed to count NVD entries for year %d: %v", plan.Year, err)
					// Fall back to existing state record count
					if existingState, _ := ing.store.GetSyncState(ctx, nvdYearSource(plan.Year)); existingState != nil {
						yearState.RecordCount = existingState.RecordCount
					}
				}
			}
		}
		if err := ing.store.UpdateSyncState(ctx, yearState); err != nil {
			ing.logger.Printf("warning: failed to update sync state for NVD year %d: %v", plan.Year, err)
		}
	}

	stats.Inserted = totalInserted
	stats.Total = totalInserted + totalErrors
	stats.Errors = totalErrors
	stats.Duration = time.Since(start)

	ing.progress(Progress{Phase: "store", Current: totalInserted, Total: stats.Total,
		Message: fmt.Sprintf("Done: %d CVEs imported in %s (%d full, %d delta)",
			totalInserted, stats.Duration.Round(time.Millisecond), fullCount, deltaCount)})

	return stats, nil
}

// needsFullYearImport determines whether a year requires a full feed download.
// Returns true if the sync_state is nil, has an invalid timestamp, or is older
// than nvdModifiedFeedWindow (8 days).
func needsFullYearImport(state *store.SyncState) bool {
	if state == nil {
		return true
	}
	if state.LastSyncedAt == "" {
		return true
	}
	lastSync, err := parseSyncTime(state.LastSyncedAt)
	if err != nil {
		return true
	}
	return time.Since(lastSync) > nvdModifiedFeedWindow
}

// groupCVEsByYear groups NVD CVE entries by the year in their CVE ID.
// CVE IDs follow the format "CVE-YYYY-NNNNN".
func groupCVEsByYear(entries []*model.NVDCVE) map[int][]*model.NVDCVE {
	m := make(map[int][]*model.NVDCVE)
	for _, e := range entries {
		year := extractCVEYear(e.ID)
		if year > 0 {
			m[year] = append(m[year], e)
		}
	}
	return m
}

// extractCVEYear extracts the year from a CVE ID (e.g., "CVE-2017-6770" → 2017).
// Returns 0 if the ID doesn't match the expected format.
func extractCVEYear(cveID string) int {
	// CVE-YYYY-NNNNN
	if !strings.HasPrefix(cveID, "CVE-") {
		return 0
	}
	parts := strings.SplitN(cveID, "-", 4)
	if len(parts) < 3 {
		return 0
	}
	year, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0
	}
	return year
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
// To avoid OOM on large feeds (10,000+ entries), summary refresh is performed
// incrementally per batch rather than accumulating all CVE IDs in memory.
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

		// Refresh summary immediately for this batch to avoid accumulating IDs in memory.
		batchIDs := make([]string, len(batch))
		for j, e := range batch {
			batchIDs[j] = e.ID
		}
		ing.refreshSummary(ctx, batchIDs)

		// Run watchlist matching for this batch (only fires in update mode).
		ing.matchWatchlists(ctx, batchIDs)

		// Release references to processed entries so GC can reclaim the memory
		// (raw JSON, configurations, etc. of each entry are large).
		for j := i; j < end; j++ {
			entries[j] = nil
		}

		inserted += len(batch)
		ing.progress(Progress{Phase: "store", Current: inserted, Total: total})
	}

	return inserted, nil
}
