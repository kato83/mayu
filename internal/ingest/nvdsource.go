package ingest

import (
	"context"
	"fmt"
	"time"

	"github.com/kato83/mayu/internal/model"
	"github.com/kato83/mayu/internal/store"
)

const (
	nvdSourcesSyncKey = "NVD-sources"
	// nvdSourcesSyncInterval is the minimum time between NVD Source API syncs (24 hours).
	nvdSourcesSyncInterval = 24 * time.Hour
)

// nvdSourceUpserter is an optional interface for stores that support NVD source upsert.
type nvdSourceUpserter interface {
	UpsertNVDSources(ctx context.Context, sources []model.NVDSource) error
}

// SyncNVDSources fetches the NVD Source API and updates the nvd_sources table.
// It only performs the sync if the last sync was more than 24 hours ago
// (checked via the "NVD-sources" sync_state entry).
func (ing *Ingester) SyncNVDSources(ctx context.Context) error {
	// Check if sync is needed
	state, err := ing.store.GetSyncState(ctx, nvdSourcesSyncKey)
	if err != nil {
		ing.logger.Printf("warning: failed to check NVD sources sync state: %v", err)
		// Continue with sync on error (better to re-sync than skip)
	}

	if state != nil && state.LastSyncedAt != "" {
		lastSync, parseErr := parseSyncTime(state.LastSyncedAt)
		if parseErr == nil && time.Since(lastSync) < nvdSourcesSyncInterval {
			ing.progress(Progress{Phase: "download", Message: "NVD sources: skipping (synced within 24h)"})
			return nil
		}
	}

	ing.progress(Progress{Phase: "download", Message: "Fetching NVD source organizations..."})

	// Fetch from API
	data, err := ing.fetcher.FetchNVDSources(ctx)
	if err != nil {
		return fmt.Errorf("fetch NVD sources: %w", err)
	}

	// Parse response
	sources, err := ing.parser.ParseNVDSources(data)
	if err != nil {
		return fmt.Errorf("parse NVD sources: %w", err)
	}

	ing.progress(Progress{Phase: "store", Message: fmt.Sprintf("Storing %d NVD source identifiers...", len(sources))})

	// Store using type assertion (not all Store implementations support this)
	upserter, ok := ing.store.(nvdSourceUpserter)
	if !ok {
		return fmt.Errorf("store does not support NVD source upsert")
	}

	if err := upserter.UpsertNVDSources(ctx, sources); err != nil {
		return fmt.Errorf("upsert NVD sources: %w", err)
	}

	// Update sync state
	syncState := &store.SyncState{
		Source:       nvdSourcesSyncKey,
		SourceType:   "nvd",
		LastSyncedAt: time.Now().UTC().Format(time.RFC3339),
		RecordCount:  int64(len(sources)),
	}
	if err := ing.store.UpdateSyncState(ctx, syncState); err != nil {
		ing.logger.Printf("warning: failed to update NVD sources sync state: %v", err)
	}

	ing.progress(Progress{Phase: "store", Message: fmt.Sprintf("NVD sources: %d identifiers synced", len(sources))})
	return nil
}
