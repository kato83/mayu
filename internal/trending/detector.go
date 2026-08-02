// Package trending provides EPSS spike detection for webhook notifications.
// It identifies CVEs with rapidly rising EPSS scores that cross a configurable
// threshold, enabling real-time alerting when exploitation likelihood increases.
package trending

import (
	"context"
	"fmt"

	"github.com/kato83/mayu/internal/store"
)

// EventEPSSSpike is the webhook event type fired when CVEs cross the trending threshold.
const EventEPSSSpike = "epss_spike"

// SpikeResult represents a single CVE that has been detected as having an EPSS spike.
type SpikeResult struct {
	VulnerabilityID string
	CurrentEPSS     float64
	PreviousEPSS    float64
	Delta           float64
	Summary         string
}

// DetectorStore defines the store interface needed by the spike detector.
// This is satisfied by any store implementing GetEPSSTrending.
type DetectorStore interface {
	GetEPSSTrending(ctx context.Context, params store.EPSSTrendingQuery) (*store.EPSSTrendingResult, error)
}

// DetectorParams configures the spike detection query.
type DetectorParams struct {
	// Days is the lookback window for comparison (default 7).
	Days int
	// Threshold is the minimum EPSS delta to qualify as a spike (default 0.1).
	Threshold float64
	// Limit is the maximum number of results to return (default 50).
	Limit int
}

// applyDefaults fills in zero-valued parameters with sensible defaults.
func (p *DetectorParams) applyDefaults() {
	if p.Days <= 0 {
		p.Days = 7
	}
	if p.Threshold <= 0 {
		p.Threshold = 0.1
	}
	if p.Limit <= 0 {
		p.Limit = 50
	}
}

// DetectSpikes queries the store for CVEs with EPSS scores that have increased
// by at least the threshold amount over the lookback window. This function can
// be called from both the API trending endpoint and the post-ingest hook.
func DetectSpikes(ctx context.Context, s DetectorStore, params DetectorParams) ([]SpikeResult, error) {
	params.applyDefaults()

	query := store.EPSSTrendingQuery{
		Days:      params.Days,
		Threshold: params.Threshold,
		Limit:     params.Limit,
	}

	trendingResult, err := s.GetEPSSTrending(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("detect EPSS spikes: %w", err)
	}

	var entries []store.EPSSTrendingEntry
	if trendingResult != nil {
		entries = trendingResult.Entries
	}

	results := make([]SpikeResult, 0, len(entries))
	for _, e := range entries {
		results = append(results, SpikeResult{
			VulnerabilityID: e.VulnerabilityID,
			CurrentEPSS:     e.CurrentEPSS,
			PreviousEPSS:    e.PreviousEPSS,
			Delta:           e.Delta,
			Summary:         e.Summary,
		})
	}

	return results, nil
}

// FilterNewSpikes filters spike results to only include CVEs that are present
// in the given set of recently ingested CVE IDs. This ensures we only fire
// webhook notifications for CVEs that crossed the threshold during THIS ingest,
// not for spikes that were already detected previously.
func FilterNewSpikes(spikes []SpikeResult, ingestedIDs []string) []SpikeResult {
	if len(spikes) == 0 || len(ingestedIDs) == 0 {
		return nil
	}

	idSet := make(map[string]struct{}, len(ingestedIDs))
	for _, id := range ingestedIDs {
		idSet[id] = struct{}{}
	}

	var filtered []SpikeResult
	for _, spike := range spikes {
		if _, ok := idSet[spike.VulnerabilityID]; ok {
			filtered = append(filtered, spike)
		}
	}

	return filtered
}
