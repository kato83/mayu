package watchlist

import (
	"context"
	"testing"
)

// --- Mock implementations ---

type mockWatchlistStore struct {
	watchlists []*Watchlist
	matches    []WatchlistMatch
}

func (m *mockWatchlistStore) CreateWatchlist(_ context.Context, w *Watchlist) (int64, error) {
	return 1, nil
}
func (m *mockWatchlistStore) GetWatchlist(_ context.Context, id int64, userID int64) (*Watchlist, error) {
	return nil, nil
}
func (m *mockWatchlistStore) ListWatchlists(_ context.Context, userID int64) ([]*Watchlist, error) {
	return nil, nil
}
func (m *mockWatchlistStore) UpdateWatchlist(_ context.Context, w *Watchlist) error { return nil }
func (m *mockWatchlistStore) DeleteWatchlist(_ context.Context, id int64, userID int64) error {
	return nil
}
func (m *mockWatchlistStore) ListMatchesByWatchlist(_ context.Context, watchlistID int64, limit int, offset int) ([]*WatchlistMatch, error) {
	return nil, nil
}
func (m *mockWatchlistStore) ListMatchesByUser(_ context.Context, userID int64, limit int, offset int) ([]*WatchlistMatch, error) {
	return nil, nil
}
func (m *mockWatchlistStore) CountMatchesByUser(_ context.Context, userID int64) (int64, error) {
	return 0, nil
}
func (m *mockWatchlistStore) RecordMatches(_ context.Context, matches []WatchlistMatch) error {
	m.matches = append(m.matches, matches...)
	return nil
}
func (m *mockWatchlistStore) GetActiveWatchlists(_ context.Context) ([]*Watchlist, error) {
	return m.watchlists, nil
}

type mockVulnDataProvider struct {
	data []VulnData
}

func (m *mockVulnDataProvider) GetVulnDataForMatching(_ context.Context, vulnIDs []string) ([]VulnData, error) {
	return m.data, nil
}

// --- Tests ---

func strPtr(s string) *string       { return &s }
func int16Ptr(v int16) *int16       { return &v }
func float64Ptr(v float64) *float64 { return &v }

func TestMatcher_MatchPackage(t *testing.T) {
	store := &mockWatchlistStore{
		watchlists: []*Watchlist{
			{
				ID:          1,
				UserID:      1,
				MatchType:   MatchTypePackage,
				Ecosystem:   strPtr("Go"),
				PackageName: strPtr("golang.org/x/crypto"),
				Enabled:     true,
			},
		},
	}

	provider := &mockVulnDataProvider{
		data: []VulnData{
			{
				ID:            "CVE-2024-0001",
				Ecosystems:    []string{"Go"},
				SeverityWorst: 4,
				Identifiers: []VulnIdentifier{
					{Ecosystem: "Go", Name: "golang.org/x/crypto"},
				},
			},
		},
	}

	matcher := NewMatcher(store, provider)
	matches, err := matcher.MatchNewVulnerabilities(context.Background(), []string{"CVE-2024-0001"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].VulnerabilityID != "CVE-2024-0001" {
		t.Errorf("expected vuln ID CVE-2024-0001, got %s", matches[0].VulnerabilityID)
	}
	if matches[0].WatchlistID != 1 {
		t.Errorf("expected watchlist ID 1, got %d", matches[0].WatchlistID)
	}
}

func TestMatcher_MatchPackageCaseInsensitive(t *testing.T) {
	store := &mockWatchlistStore{
		watchlists: []*Watchlist{
			{
				ID:          1,
				UserID:      1,
				MatchType:   MatchTypePackage,
				Ecosystem:   strPtr("go"),
				PackageName: strPtr("Golang.org/X/Crypto"),
				Enabled:     true,
			},
		},
	}

	provider := &mockVulnDataProvider{
		data: []VulnData{
			{
				ID:            "CVE-2024-0001",
				Ecosystems:    []string{"Go"},
				SeverityWorst: 4,
				Identifiers: []VulnIdentifier{
					{Ecosystem: "Go", Name: "golang.org/x/crypto"},
				},
			},
		},
	}

	matcher := NewMatcher(store, provider)
	matches, err := matcher.MatchNewVulnerabilities(context.Background(), []string{"CVE-2024-0001"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
}

func TestMatcher_MatchPurl(t *testing.T) {
	store := &mockWatchlistStore{
		watchlists: []*Watchlist{
			{
				ID:          2,
				UserID:      1,
				MatchType:   MatchTypePurl,
				PurlPattern: strPtr("pkg:npm/express"),
				Enabled:     true,
			},
		},
	}

	provider := &mockVulnDataProvider{
		data: []VulnData{
			{
				ID:            "CVE-2024-0002",
				Ecosystems:    []string{"npm"},
				SeverityWorst: 3,
				Identifiers: []VulnIdentifier{
					{Purl: "pkg:npm/express@4.18.2"},
				},
			},
		},
	}

	matcher := NewMatcher(store, provider)
	matches, err := matcher.MatchNewVulnerabilities(context.Background(), []string{"CVE-2024-0002"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
}

func TestMatcher_MatchCPE(t *testing.T) {
	store := &mockWatchlistStore{
		watchlists: []*Watchlist{
			{
				ID:         3,
				UserID:     1,
				MatchType:  MatchTypeCPE,
				CpePattern: strPtr("cpe:2.3:a:apache:http_server"),
				Enabled:    true,
			},
		},
	}

	provider := &mockVulnDataProvider{
		data: []VulnData{
			{
				ID:            "CVE-2024-0003",
				Ecosystems:    []string{},
				SeverityWorst: 5,
				Identifiers: []VulnIdentifier{
					{CPE: "cpe:2.3:a:apache:http_server:2.4.59:*:*:*:*:*:*:*"},
				},
			},
		},
	}

	matcher := NewMatcher(store, provider)
	matches, err := matcher.MatchNewVulnerabilities(context.Background(), []string{"CVE-2024-0003"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
}

func TestMatcher_MatchEcosystem(t *testing.T) {
	store := &mockWatchlistStore{
		watchlists: []*Watchlist{
			{
				ID:        4,
				UserID:    1,
				MatchType: MatchTypeEcosystem,
				Ecosystem: strPtr("PyPI"),
				Enabled:   true,
			},
		},
	}

	provider := &mockVulnDataProvider{
		data: []VulnData{
			{
				ID:            "CVE-2024-0004",
				Ecosystems:    []string{"PyPI"},
				SeverityWorst: 3,
				Identifiers: []VulnIdentifier{
					{Ecosystem: "PyPI", Name: "requests"},
				},
			},
		},
	}

	matcher := NewMatcher(store, provider)
	matches, err := matcher.MatchNewVulnerabilities(context.Background(), []string{"CVE-2024-0004"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
}

func TestMatcher_SeverityFilter(t *testing.T) {
	store := &mockWatchlistStore{
		watchlists: []*Watchlist{
			{
				ID:          5,
				UserID:      1,
				MatchType:   MatchTypePackage,
				Ecosystem:   strPtr("Go"),
				PackageName: strPtr("golang.org/x/net"),
				SeverityMin: int16Ptr(4), // HIGH or above
				Enabled:     true,
			},
		},
	}

	provider := &mockVulnDataProvider{
		data: []VulnData{
			{
				ID:            "CVE-2024-0005",
				Ecosystems:    []string{"Go"},
				SeverityWorst: 3, // MEDIUM - should NOT match
				Identifiers: []VulnIdentifier{
					{Ecosystem: "Go", Name: "golang.org/x/net"},
				},
			},
		},
	}

	matcher := NewMatcher(store, provider)
	matches, err := matcher.MatchNewVulnerabilities(context.Background(), []string{"CVE-2024-0005"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected 0 matches (severity too low), got %d", len(matches))
	}
}

func TestMatcher_SeverityFilter_Passes(t *testing.T) {
	store := &mockWatchlistStore{
		watchlists: []*Watchlist{
			{
				ID:          5,
				UserID:      1,
				MatchType:   MatchTypePackage,
				Ecosystem:   strPtr("Go"),
				PackageName: strPtr("golang.org/x/net"),
				SeverityMin: int16Ptr(4), // HIGH or above
				Enabled:     true,
			},
		},
	}

	provider := &mockVulnDataProvider{
		data: []VulnData{
			{
				ID:            "CVE-2024-0006",
				Ecosystems:    []string{"Go"},
				SeverityWorst: 5, // CRITICAL - should match
				Identifiers: []VulnIdentifier{
					{Ecosystem: "Go", Name: "golang.org/x/net"},
				},
			},
		},
	}

	matcher := NewMatcher(store, provider)
	matches, err := matcher.MatchNewVulnerabilities(context.Background(), []string{"CVE-2024-0006"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
}

func TestMatcher_EPSSFilter(t *testing.T) {
	store := &mockWatchlistStore{
		watchlists: []*Watchlist{
			{
				ID:            6,
				UserID:        1,
				MatchType:     MatchTypeEcosystem,
				Ecosystem:     strPtr("Go"),
				EpssThreshold: float64Ptr(0.5),
				Enabled:       true,
			},
		},
	}

	provider := &mockVulnDataProvider{
		data: []VulnData{
			{
				ID:            "CVE-2024-0007",
				Ecosystems:    []string{"Go"},
				SeverityWorst: 4,
				EPSSScore:     float64Ptr(0.3), // Below threshold
				Identifiers:   []VulnIdentifier{},
			},
		},
	}

	matcher := NewMatcher(store, provider)
	matches, err := matcher.MatchNewVulnerabilities(context.Background(), []string{"CVE-2024-0007"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected 0 matches (EPSS below threshold), got %d", len(matches))
	}
}

func TestMatcher_EPSSFilter_Passes(t *testing.T) {
	store := &mockWatchlistStore{
		watchlists: []*Watchlist{
			{
				ID:            6,
				UserID:        1,
				MatchType:     MatchTypeEcosystem,
				Ecosystem:     strPtr("Go"),
				EpssThreshold: float64Ptr(0.5),
				Enabled:       true,
			},
		},
	}

	provider := &mockVulnDataProvider{
		data: []VulnData{
			{
				ID:            "CVE-2024-0008",
				Ecosystems:    []string{"Go"},
				SeverityWorst: 4,
				EPSSScore:     float64Ptr(0.7), // Above threshold
				Identifiers:   []VulnIdentifier{},
			},
		},
	}

	matcher := NewMatcher(store, provider)
	matches, err := matcher.MatchNewVulnerabilities(context.Background(), []string{"CVE-2024-0008"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
}

func TestMatcher_EPSSFilter_NilScore(t *testing.T) {
	store := &mockWatchlistStore{
		watchlists: []*Watchlist{
			{
				ID:            7,
				UserID:        1,
				MatchType:     MatchTypeEcosystem,
				Ecosystem:     strPtr("Go"),
				EpssThreshold: float64Ptr(0.5),
				Enabled:       true,
			},
		},
	}

	provider := &mockVulnDataProvider{
		data: []VulnData{
			{
				ID:            "CVE-2024-0009",
				Ecosystems:    []string{"Go"},
				SeverityWorst: 4,
				EPSSScore:     nil, // No EPSS score - should NOT match
				Identifiers:   []VulnIdentifier{},
			},
		},
	}

	matcher := NewMatcher(store, provider)
	matches, err := matcher.MatchNewVulnerabilities(context.Background(), []string{"CVE-2024-0009"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected 0 matches (nil EPSS score), got %d", len(matches))
	}
}

func TestMatcher_NoActiveWatchlists(t *testing.T) {
	store := &mockWatchlistStore{
		watchlists: []*Watchlist{},
	}

	provider := &mockVulnDataProvider{
		data: []VulnData{
			{
				ID:            "CVE-2024-0010",
				Ecosystems:    []string{"Go"},
				SeverityWorst: 4,
			},
		},
	}

	matcher := NewMatcher(store, provider)
	matches, err := matcher.MatchNewVulnerabilities(context.Background(), []string{"CVE-2024-0010"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matches != nil {
		t.Fatalf("expected nil matches, got %d", len(matches))
	}
}

func TestMatcher_NoMatchingVulns(t *testing.T) {
	store := &mockWatchlistStore{
		watchlists: []*Watchlist{
			{
				ID:          1,
				UserID:      1,
				MatchType:   MatchTypePackage,
				Ecosystem:   strPtr("Go"),
				PackageName: strPtr("golang.org/x/crypto"),
				Enabled:     true,
			},
		},
	}

	provider := &mockVulnDataProvider{
		data: []VulnData{
			{
				ID:            "CVE-2024-0011",
				Ecosystems:    []string{"npm"},
				SeverityWorst: 4,
				Identifiers: []VulnIdentifier{
					{Ecosystem: "npm", Name: "express"},
				},
			},
		},
	}

	matcher := NewMatcher(store, provider)
	matches, err := matcher.MatchNewVulnerabilities(context.Background(), []string{"CVE-2024-0011"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matches != nil {
		t.Fatalf("expected nil matches, got %d", len(matches))
	}
}

func TestMatcher_NotifyFuncCalled(t *testing.T) {
	store := &mockWatchlistStore{
		watchlists: []*Watchlist{
			{
				ID:        1,
				UserID:    1,
				MatchType: MatchTypeEcosystem,
				Ecosystem: strPtr("Go"),
				Enabled:   true,
			},
		},
	}

	provider := &mockVulnDataProvider{
		data: []VulnData{
			{
				ID:            "CVE-2024-0012",
				Ecosystems:    []string{"Go"},
				SeverityWorst: 4,
			},
		},
	}

	var notified []WatchlistMatch
	matcher := NewMatcher(store, provider)
	matcher.NotifyFunc = func(_ context.Context, matches []WatchlistMatch) error {
		notified = append(notified, matches...)
		return nil
	}

	_, err := matcher.MatchNewVulnerabilities(context.Background(), []string{"CVE-2024-0012"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(notified) != 1 {
		t.Fatalf("expected NotifyFunc called with 1 match, got %d", len(notified))
	}
}

func TestMatcher_EmptyVulnIDs(t *testing.T) {
	store := &mockWatchlistStore{}
	provider := &mockVulnDataProvider{}

	matcher := NewMatcher(store, provider)
	matches, err := matcher.MatchNewVulnerabilities(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matches != nil {
		t.Fatalf("expected nil, got %v", matches)
	}
}
