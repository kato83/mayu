package watchlist

import "context"

// IngestMatcherAdapter wraps a Matcher to satisfy the ingest.WatchlistMatcher interface.
// The ingest package's WatchlistMatcher interface returns only an error (not matches),
// while our Matcher returns ([]WatchlistMatch, error).
type IngestMatcherAdapter struct {
	matcher *Matcher
}

// NewIngestMatcherAdapter creates an adapter that satisfies ingest.WatchlistMatcher.
func NewIngestMatcherAdapter(matcher *Matcher) *IngestMatcherAdapter {
	return &IngestMatcherAdapter{matcher: matcher}
}

// MatchNewVulnerabilities satisfies the ingest.WatchlistMatcher interface.
func (a *IngestMatcherAdapter) MatchNewVulnerabilities(ctx context.Context, vulnIDs []string) error {
	_, err := a.matcher.MatchNewVulnerabilities(ctx, vulnIDs)
	return err
}
