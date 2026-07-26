package ingest

import (
	"context"
	"testing"
)

type mockWatchlistMatcher struct {
	called  bool
	vulnIDs []string
}

func (m *mockWatchlistMatcher) MatchNewVulnerabilities(_ context.Context, vulnIDs []string) error {
	m.called = true
	m.vulnIDs = vulnIDs
	return nil
}

func TestWithWatchlistMatcher_ConfiguredOnIngester(t *testing.T) {
	mock := &mockWatchlistMatcher{}

	ing := New(nil, nil, nil, WithWatchlistMatcher(mock))

	if ing.watchlistMatcher == nil {
		t.Fatal("expected watchlistMatcher to be set on Ingester")
	}
}

func TestMatchWatchlists_CalledWhenConfigured(t *testing.T) {
	mock := &mockWatchlistMatcher{}
	ing := New(nil, nil, nil, WithWatchlistMatcher(mock), WithUpdateMode(true))

	ctx := context.Background()
	ing.matchWatchlists(ctx, []string{"CVE-2024-0001", "CVE-2024-0002"})

	if !mock.called {
		t.Fatal("expected watchlistMatcher.MatchNewVulnerabilities to be called")
	}
	if len(mock.vulnIDs) != 2 {
		t.Fatalf("expected 2 vulnIDs, got %d", len(mock.vulnIDs))
	}
}

func TestMatchWatchlists_NotCalledWhenNil(t *testing.T) {
	ing := New(nil, nil, nil) // no watchlist matcher

	ctx := context.Background()
	// Should not panic
	ing.matchWatchlists(ctx, []string{"CVE-2024-0001"})
}

func TestMatchWatchlists_DeduplicatesIDs(t *testing.T) {
	mock := &mockWatchlistMatcher{}
	ing := New(nil, nil, nil, WithWatchlistMatcher(mock), WithUpdateMode(true))

	ctx := context.Background()
	ing.matchWatchlists(ctx, []string{"CVE-2024-0001", "CVE-2024-0001", "CVE-2024-0002"})

	if len(mock.vulnIDs) != 2 {
		t.Fatalf("expected 2 unique vulnIDs after dedup, got %d", len(mock.vulnIDs))
	}
}

func TestMatchWatchlists_EmptyIDs(t *testing.T) {
	mock := &mockWatchlistMatcher{}
	ing := New(nil, nil, nil, WithWatchlistMatcher(mock), WithUpdateMode(true))

	ctx := context.Background()
	ing.matchWatchlists(ctx, nil)

	if mock.called {
		t.Fatal("expected watchlistMatcher.MatchNewVulnerabilities NOT to be called for nil IDs")
	}
}

func TestMatchWatchlists_NotCalledWithoutUpdateMode(t *testing.T) {
	mock := &mockWatchlistMatcher{}
	ing := New(nil, nil, nil, WithWatchlistMatcher(mock)) // no WithUpdateMode

	ctx := context.Background()
	ing.matchWatchlists(ctx, []string{"CVE-2024-0001", "CVE-2024-0002"})

	if mock.called {
		t.Fatal("expected watchlistMatcher.MatchNewVulnerabilities NOT to be called without update mode")
	}
}
