package store

import "testing"

func TestRangeToInterval(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "30 days", input: "30d", expected: "30"},
		{name: "90 days", input: "90d", expected: "90"},
		{name: "180 days", input: "180d", expected: "180"},
		{name: "365 days", input: "365d", expected: "365"},
		{name: "all returns empty", input: "all", expected: ""},
		{name: "unknown returns empty", input: "unknown", expected: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rangeToInterval(tt.input)
			if got != tt.expected {
				t.Errorf("rangeToInterval(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestStatsTrendQuery_Defaults(t *testing.T) {
	// Verify that zero-value StatsTrendQuery fields are sensible
	q := StatsTrendQuery{}
	if q.ProjectID != 0 {
		t.Errorf("expected zero ProjectID, got %d", q.ProjectID)
	}
	if q.Range != "" {
		t.Errorf("expected empty Range, got %q", q.Range)
	}
	if q.GroupBy != "" {
		t.Errorf("expected empty GroupBy, got %q", q.GroupBy)
	}
	if q.Metric != "" {
		t.Errorf("expected empty Metric, got %q", q.Metric)
	}
}
