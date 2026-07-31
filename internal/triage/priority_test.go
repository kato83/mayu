package triage

import (
	"testing"

	"github.com/kato83/mayu/internal/ssvc"
)

func TestResolvePriority_ScoreOnly(t *testing.T) {
	thresholds := DefaultThresholds()

	tests := []struct {
		name     string
		score    float64
		ssvc     ssvc.Decision
		expected PriorityLevel
	}{
		{"Critical score", 0.90, ssvc.DecisionTrack, PriorityCritical},
		{"High score", 0.70, ssvc.DecisionTrack, PriorityHigh},
		{"Medium score", 0.50, ssvc.DecisionTrack, PriorityMedium},
		{"Low score", 0.20, ssvc.DecisionTrack, PriorityLow},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ResolvePriority(tt.score, tt.ssvc, thresholds)
			if result != tt.expected {
				t.Errorf("ResolvePriority(%f, %s) = %s, want %s", tt.score, tt.ssvc, result, tt.expected)
			}
		})
	}
}

func TestResolvePriority_SSVCOverride(t *testing.T) {
	thresholds := DefaultThresholds()

	// Low score but Act SSVC decision -> should be Critical
	result := ResolvePriority(0.20, ssvc.DecisionAct, thresholds)
	if result != PriorityCritical {
		t.Errorf("expected Critical (SSVC override), got %s", result)
	}

	// Low score but Attend -> High
	result = ResolvePriority(0.20, ssvc.DecisionAttend, thresholds)
	if result != PriorityHigh {
		t.Errorf("expected High (SSVC override), got %s", result)
	}
}

func TestResolvePriority_MaxRule(t *testing.T) {
	thresholds := DefaultThresholds()

	// High score but Track* SSVC -> score wins (High > Medium)
	result := ResolvePriority(0.70, ssvc.DecisionTrackStar, thresholds)
	if result != PriorityHigh {
		t.Errorf("expected High (score > SSVC), got %s", result)
	}

	// Both agree: Critical
	result = ResolvePriority(0.90, ssvc.DecisionAct, thresholds)
	if result != PriorityCritical {
		t.Errorf("expected Critical (both agree), got %s", result)
	}
}

func TestResolvePriority_BoundaryValues(t *testing.T) {
	thresholds := DefaultThresholds()

	// Exactly at critical threshold
	result := ResolvePriority(0.85, ssvc.DecisionTrack, thresholds)
	if result != PriorityCritical {
		t.Errorf("score=0.85 should be Critical, got %s", result)
	}

	// Just below critical
	result = ResolvePriority(0.849, ssvc.DecisionTrack, thresholds)
	if result != PriorityHigh {
		t.Errorf("score=0.849 should be High, got %s", result)
	}

	// Exactly at high threshold
	result = ResolvePriority(0.65, ssvc.DecisionTrack, thresholds)
	if result != PriorityHigh {
		t.Errorf("score=0.65 should be High, got %s", result)
	}

	// Exactly at medium threshold
	result = ResolvePriority(0.40, ssvc.DecisionTrack, thresholds)
	if result != PriorityMedium {
		t.Errorf("score=0.40 should be Medium, got %s", result)
	}

	// Just below medium
	result = ResolvePriority(0.39, ssvc.DecisionTrack, thresholds)
	if result != PriorityLow {
		t.Errorf("score=0.39 should be Low, got %s", result)
	}
}

func TestEstimateSSVC(t *testing.T) {
	tests := []struct {
		name     string
		input    *TriageInput
		expected ssvc.Decision
	}{
		{
			name: "KEV active + high EPSS + high CVSS -> Act",
			input: &TriageInput{
				InKEV:     true,
				EPSSScore: float64Ptr(0.8),
				CVSSScore: float64Ptr(9.0),
			},
			expected: ssvc.DecisionAct,
		},
		{
			name: "No exploit + low EPSS + low CVSS -> Track",
			input: &TriageInput{
				InKEV:     false,
				EPSSScore: float64Ptr(0.1),
				CVSSScore: float64Ptr(3.0),
			},
			expected: ssvc.DecisionTrack,
		},
		{
			name: "ExploitDB + high EPSS + high CVSS -> Attend",
			input: &TriageInput{
				HasExploit: true,
				EPSSScore:  float64Ptr(0.7),
				CVSSScore:  float64Ptr(8.0),
			},
			expected: ssvc.DecisionAttend,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EstimateSSVC(tt.input)
			if result != tt.expected {
				t.Errorf("EstimateSSVC() = %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestPriorityRank(t *testing.T) {
	if PriorityRank(PriorityCritical) <= PriorityRank(PriorityHigh) {
		t.Error("Critical should rank higher than High")
	}
	if PriorityRank(PriorityHigh) <= PriorityRank(PriorityMedium) {
		t.Error("High should rank higher than Medium")
	}
	if PriorityRank(PriorityMedium) <= PriorityRank(PriorityLow) {
		t.Error("Medium should rank higher than Low")
	}
}
