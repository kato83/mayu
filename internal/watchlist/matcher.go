package watchlist

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// VulnData holds the data needed by the matcher for a single vulnerability.
type VulnData struct {
	ID            string
	Ecosystems    []string
	SeverityWorst int
	EPSSScore     *float64
	// Product identifiers associated with this vulnerability.
	Identifiers []VulnIdentifier
}

// VulnIdentifier represents a product identifier row relevant for matching.
type VulnIdentifier struct {
	Ecosystem string
	Name      string
	// Purl is the reconstructed purl string (e.g., "pkg:golang/github.com/foo/bar").
	Purl string
	// CPE is the reconstructed CPE 2.3 URI.
	CPE string
}

// VulnDataProvider provides vulnerability metadata needed for watchlist matching.
// This is a small interface that decouples the matcher from the full store.Store.
type VulnDataProvider interface {
	// GetVulnDataForMatching returns vulnerability data for the given IDs.
	// Missing IDs are simply omitted from the result.
	GetVulnDataForMatching(ctx context.Context, vulnIDs []string) ([]VulnData, error)
}

// NotifyFunc is a callback invoked when new matches are found.
// It serves as the integration point for webhook notifications.
type NotifyFunc func(ctx context.Context, matches []WatchlistMatch) error

// Matcher evaluates newly ingested vulnerabilities against active watchlists.
type Matcher struct {
	store      WatchlistStore
	vulnData   VulnDataProvider
	NotifyFunc NotifyFunc
}

// NewMatcher creates a new Matcher with the given stores.
func NewMatcher(store WatchlistStore, vulnData VulnDataProvider) *Matcher {
	return &Matcher{
		store:    store,
		vulnData: vulnData,
	}
}

// MatchNewVulnerabilities checks newly ingested vulnerability IDs against all
// active watchlists, records any matches, and optionally calls NotifyFunc.
func (m *Matcher) MatchNewVulnerabilities(ctx context.Context, vulnIDs []string) ([]WatchlistMatch, error) {
	if len(vulnIDs) == 0 {
		return nil, nil
	}

	// Fetch all enabled watchlists
	watchlists, err := m.store.GetActiveWatchlists(ctx)
	if err != nil {
		return nil, err
	}
	if len(watchlists) == 0 {
		return nil, nil
	}

	// Fetch vulnerability data for matching
	vulnDataList, err := m.vulnData.GetVulnDataForMatching(ctx, vulnIDs)
	if err != nil {
		return nil, err
	}
	if len(vulnDataList) == 0 {
		return nil, nil
	}

	now := time.Now()
	var matches []WatchlistMatch

	for _, vd := range vulnDataList {
		for _, wl := range watchlists {
			if matchesWatchlist(wl, &vd) {
				matches = append(matches, WatchlistMatch{
					WatchlistID:     wl.ID,
					VulnerabilityID: vd.ID,
					MatchedAt:       now,
				})
			}
		}
	}

	if len(matches) == 0 {
		return nil, nil
	}

	// Record matches (ON CONFLICT DO NOTHING handles duplicates)
	if err := m.store.RecordMatches(ctx, matches); err != nil {
		return nil, err
	}

	// Notify if configured
	if m.NotifyFunc != nil {
		if err := m.NotifyFunc(ctx, matches); err != nil {
			// Log but do not fail the ingest pipeline
			return matches, nil
		}
	}

	return matches, nil
}

// CheckAllResult holds the result of a full watchlist check.
type CheckAllResult struct {
	WatchlistID   int64
	WatchlistName string
	NewMatches    []string // vulnerability IDs that are newly matched
}

// CheckAllStore defines the interface required for CheckAll.
// It extends WatchlistStore with the SQL-based vulnerability finder.
type CheckAllStore interface {
	WatchlistStore
	FindMatchingVulnerabilities(ctx context.Context, wl *Watchlist) ([]string, error)
}

// CheckAll scans all active watchlists against the entire vulnerability database,
// records new matches, and optionally notifies. This is designed for periodic
// cron execution (e.g., "mayu watch check").
//
// Unlike MatchNewVulnerabilities (which checks new vulns against watchlists),
// CheckAll checks all vulns against watchlists — catching cases where a
// vulnerability's EPSS score has risen above the threshold since initial ingest.
func (m *Matcher) CheckAll(ctx context.Context) ([]CheckAllResult, error) {
	// CheckAll requires the store to support FindMatchingVulnerabilities
	checkStore, ok := m.store.(CheckAllStore)
	if !ok {
		return nil, fmt.Errorf("store does not support FindMatchingVulnerabilities (required for CheckAll)")
	}

	// Fetch all enabled watchlists
	watchlists, err := m.store.GetActiveWatchlists(ctx)
	if err != nil {
		return nil, err
	}
	if len(watchlists) == 0 {
		return nil, nil
	}

	now := time.Now()
	var results []CheckAllResult

	for _, wl := range watchlists {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		// Use SQL-based search to find matching vulnerabilities
		vulnIDs, err := checkStore.FindMatchingVulnerabilities(ctx, wl)
		if err != nil {
			return results, fmt.Errorf("check watchlist %d (%s): %w", wl.ID, wl.Name, err)
		}

		if len(vulnIDs) == 0 {
			continue
		}

		// Build matches
		matches := make([]WatchlistMatch, len(vulnIDs))
		for i, id := range vulnIDs {
			matches[i] = WatchlistMatch{
				WatchlistID:     wl.ID,
				VulnerabilityID: id,
				MatchedAt:       now,
			}
		}

		// Record matches (ON CONFLICT DO NOTHING)
		if err := m.store.RecordMatches(ctx, matches); err != nil {
			return results, fmt.Errorf("record matches for watchlist %d: %w", wl.ID, err)
		}

		results = append(results, CheckAllResult{
			WatchlistID:   wl.ID,
			WatchlistName: wl.Name,
			NewMatches:    vulnIDs,
		})

		// Notify if configured
		if m.NotifyFunc != nil && len(matches) > 0 {
			if err := m.NotifyFunc(ctx, matches); err != nil {
				// Log but don't fail
				continue
			}
		}
	}

	return results, nil
}

// matchesWatchlist checks whether a vulnerability matches a watchlist entry.
func matchesWatchlist(wl *Watchlist, vd *VulnData) bool {
	// First check type-specific matching
	if !matchesType(wl, vd) {
		return false
	}

	// Apply severity filter
	if wl.SeverityMin != nil {
		if vd.SeverityWorst < int(*wl.SeverityMin) {
			return false
		}
	}

	// Apply EPSS threshold filter
	if wl.EpssThreshold != nil {
		if vd.EPSSScore == nil || *vd.EPSSScore < *wl.EpssThreshold {
			return false
		}
	}

	return true
}

// matchesType checks the type-specific matching condition.
func matchesType(wl *Watchlist, vd *VulnData) bool {
	switch wl.MatchType {
	case MatchTypePackage:
		return matchesPackage(wl, vd)
	case MatchTypePurl:
		return matchesPurl(wl, vd)
	case MatchTypeCPE:
		return matchesCPE(wl, vd)
	case MatchTypeEcosystem:
		return matchesEcosystem(wl, vd)
	default:
		return false
	}
}

// matchesPackage checks if ecosystem matches AND package_name matches (case-insensitive).
func matchesPackage(wl *Watchlist, vd *VulnData) bool {
	if wl.Ecosystem == nil || wl.PackageName == nil {
		return false
	}
	eco := strings.ToLower(*wl.Ecosystem)
	pkg := strings.ToLower(*wl.PackageName)

	for _, ident := range vd.Identifiers {
		if strings.ToLower(ident.Ecosystem) == eco && strings.ToLower(ident.Name) == pkg {
			return true
		}
	}
	return false
}

// matchesPurl checks if any product_identifier purl starts with purl_pattern (prefix match).
func matchesPurl(wl *Watchlist, vd *VulnData) bool {
	if wl.PurlPattern == nil {
		return false
	}
	pattern := strings.ToLower(*wl.PurlPattern)

	for _, ident := range vd.Identifiers {
		if ident.Purl != "" && strings.HasPrefix(strings.ToLower(ident.Purl), pattern) {
			return true
		}
	}
	return false
}

// matchesCPE checks if any product_identifier CPE starts with cpe_pattern (prefix match).
func matchesCPE(wl *Watchlist, vd *VulnData) bool {
	if wl.CpePattern == nil {
		return false
	}
	pattern := strings.ToLower(*wl.CpePattern)

	for _, ident := range vd.Identifiers {
		if ident.CPE != "" && strings.HasPrefix(strings.ToLower(ident.CPE), pattern) {
			return true
		}
	}
	return false
}

// matchesEcosystem checks if any of the vulnerability's ecosystems match.
func matchesEcosystem(wl *Watchlist, vd *VulnData) bool {
	if wl.Ecosystem == nil {
		return false
	}
	eco := strings.ToLower(*wl.Ecosystem)

	for _, e := range vd.Ecosystems {
		if strings.ToLower(e) == eco {
			return true
		}
	}
	return false
}
