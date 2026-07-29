package trending

import (
	"context"
	"errors"
	"testing"

	"github.com/kato83/mayu/internal/store"
)

// mockDetectorStore implements DetectorStore for testing.
type mockDetectorStore struct {
	entries []store.EPSSTrendingEntry
	err     error
	called  bool
	params  store.EPSSTrendingQuery
}

func (m *mockDetectorStore) GetEPSSTrending(ctx context.Context, params store.EPSSTrendingQuery) ([]store.EPSSTrendingEntry, error) {
	m.called = true
	m.params = params
	return m.entries, m.err
}

func TestDetectSpikes_Success(t *testing.T) {
	ms := &mockDetectorStore{
		entries: []store.EPSSTrendingEntry{
			{
				VulnerabilityID: "CVE-2024-1111",
				CurrentEPSS:     0.85,
				PreviousEPSS:    0.15,
				Delta:           0.70,
				Summary:         "Critical RCE in library X",
			},
			{
				VulnerabilityID: "CVE-2024-2222",
				CurrentEPSS:     0.60,
				PreviousEPSS:    0.30,
				Delta:           0.30,
				Summary:         "SQL injection in service Y",
			},
		},
	}

	results, err := DetectSpikes(context.Background(), ms, DetectorParams{
		Days:      7,
		Threshold: 0.1,
		Limit:     50,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !ms.called {
		t.Fatal("expected store to be called")
	}
	if ms.params.Days != 7 {
		t.Errorf("expected days 7, got %d", ms.params.Days)
	}
	if ms.params.Threshold != 0.1 {
		t.Errorf("expected threshold 0.1, got %f", ms.params.Threshold)
	}
	if ms.params.Limit != 50 {
		t.Errorf("expected limit 50, got %d", ms.params.Limit)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	if results[0].VulnerabilityID != "CVE-2024-1111" {
		t.Errorf("expected CVE-2024-1111, got %s", results[0].VulnerabilityID)
	}
	if results[0].Delta != 0.70 {
		t.Errorf("expected delta 0.70, got %f", results[0].Delta)
	}
	if results[0].Summary != "Critical RCE in library X" {
		t.Errorf("unexpected summary: %s", results[0].Summary)
	}
	if results[1].VulnerabilityID != "CVE-2024-2222" {
		t.Errorf("expected CVE-2024-2222, got %s", results[1].VulnerabilityID)
	}
}

func TestDetectSpikes_Defaults(t *testing.T) {
	ms := &mockDetectorStore{
		entries: nil,
	}

	_, err := DetectSpikes(context.Background(), ms, DetectorParams{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ms.params.Days != 7 {
		t.Errorf("expected default days 7, got %d", ms.params.Days)
	}
	if ms.params.Threshold != 0.1 {
		t.Errorf("expected default threshold 0.1, got %f", ms.params.Threshold)
	}
	if ms.params.Limit != 50 {
		t.Errorf("expected default limit 50, got %d", ms.params.Limit)
	}
}

func TestDetectSpikes_StoreError(t *testing.T) {
	ms := &mockDetectorStore{
		err: errors.New("database connection failed"),
	}

	results, err := DetectSpikes(context.Background(), ms, DetectorParams{
		Days:      14,
		Threshold: 0.2,
		Limit:     10,
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if results != nil {
		t.Errorf("expected nil results on error, got %d", len(results))
	}
}

func TestDetectSpikes_EmptyResults(t *testing.T) {
	ms := &mockDetectorStore{
		entries: []store.EPSSTrendingEntry{},
	}

	results, err := DetectSpikes(context.Background(), ms, DetectorParams{
		Days:      7,
		Threshold: 0.5,
		Limit:     20,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestDetectSpikes_NilResults(t *testing.T) {
	ms := &mockDetectorStore{
		entries: nil,
	}

	results, err := DetectSpikes(context.Background(), ms, DetectorParams{
		Days:      7,
		Threshold: 0.1,
		Limit:     20,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestFilterNewSpikes_FiltersToIngestedIDs(t *testing.T) {
	spikes := []SpikeResult{
		{VulnerabilityID: "CVE-2024-1111", Delta: 0.5},
		{VulnerabilityID: "CVE-2024-2222", Delta: 0.4},
		{VulnerabilityID: "CVE-2024-3333", Delta: 0.3},
		{VulnerabilityID: "CVE-2024-4444", Delta: 0.2},
	}

	// Only CVE-2024-1111 and CVE-2024-3333 were just ingested
	ingestedIDs := []string{"CVE-2024-1111", "CVE-2024-3333"}

	filtered := FilterNewSpikes(spikes, ingestedIDs)

	if len(filtered) != 2 {
		t.Fatalf("expected 2 filtered results, got %d", len(filtered))
	}
	if filtered[0].VulnerabilityID != "CVE-2024-1111" {
		t.Errorf("expected CVE-2024-1111, got %s", filtered[0].VulnerabilityID)
	}
	if filtered[1].VulnerabilityID != "CVE-2024-3333" {
		t.Errorf("expected CVE-2024-3333, got %s", filtered[1].VulnerabilityID)
	}
}

func TestFilterNewSpikes_EmptySpikes(t *testing.T) {
	result := FilterNewSpikes(nil, []string{"CVE-2024-1111"})
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}

	result = FilterNewSpikes([]SpikeResult{}, []string{"CVE-2024-1111"})
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}

func TestFilterNewSpikes_EmptyIngestedIDs(t *testing.T) {
	spikes := []SpikeResult{
		{VulnerabilityID: "CVE-2024-1111", Delta: 0.5},
	}

	result := FilterNewSpikes(spikes, nil)
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}

	result = FilterNewSpikes(spikes, []string{})
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}

func TestFilterNewSpikes_NoMatches(t *testing.T) {
	spikes := []SpikeResult{
		{VulnerabilityID: "CVE-2024-1111", Delta: 0.5},
		{VulnerabilityID: "CVE-2024-2222", Delta: 0.4},
	}

	// None of the ingested IDs match
	ingestedIDs := []string{"CVE-2024-9999", "CVE-2024-8888"}

	result := FilterNewSpikes(spikes, ingestedIDs)
	if len(result) != 0 {
		t.Errorf("expected 0 results, got %d", len(result))
	}
}

func TestFilterNewSpikes_AllMatch(t *testing.T) {
	spikes := []SpikeResult{
		{VulnerabilityID: "CVE-2024-1111", Delta: 0.5},
		{VulnerabilityID: "CVE-2024-2222", Delta: 0.4},
	}

	ingestedIDs := []string{"CVE-2024-1111", "CVE-2024-2222", "CVE-2024-3333"}

	result := FilterNewSpikes(spikes, ingestedIDs)
	if len(result) != 2 {
		t.Fatalf("expected 2 results, got %d", len(result))
	}
}
