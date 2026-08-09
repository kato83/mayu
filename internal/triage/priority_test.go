package triage

import (
	"testing"

	"github.com/kato83/mayu/internal/ssvc"
)

func TestResolvePriority_V2_WeightedAverage(t *testing.T) {
	thresholds := DefaultThresholds() // C:0.85, H:0.65, M:0.40

	tests := []struct {
		name        string
		composite   float64
		ssvc        ssvc.Decision
		scoreWeight float64
		actFloor    PriorityLevel
		expected    PriorityLevel
	}{
		// High composite + Act → finalScore = 0.6*0.9 + 0.4*1.0 = 0.94 → Critical
		{"High composite + Act", 0.90, ssvc.DecisionAct, 0.60, PriorityCritical, PriorityCritical},
		// Low composite + Act → finalScore = 0.6*0.2 + 0.4*1.0 = 0.52 → Medium, but ActFloor=Critical → Critical
		{"Low composite + Act + Critical floor", 0.20, ssvc.DecisionAct, 0.60, PriorityCritical, PriorityCritical},
		// Low composite + Act + High floor → finalScore=0.52 → Medium, ActFloor=High → High
		{"Low composite + Act + High floor", 0.20, ssvc.DecisionAct, 0.60, PriorityHigh, PriorityHigh},
		// Low composite + Attend → finalScore = 0.6*0.2 + 0.4*0.75 = 0.42 → Medium (no floor for Attend)
		{"Low composite + Attend", 0.20, ssvc.DecisionAttend, 0.60, PriorityCritical, PriorityMedium},
		// High composite + Track → finalScore = 0.6*0.9 + 0.4*0.25 = 0.64 → just below High(0.65) but rounding...
		// Actually 0.64 < 0.65 → Medium. But let's verify: 0.6*0.9=0.54, 0.4*0.25=0.10, total=0.64 < 0.65 → Medium
		{"High composite + Track", 0.90, ssvc.DecisionTrack, 0.60, PriorityCritical, PriorityMedium},
		// Medium composite + None → finalScore = 0.6*0.5 + 0.4*0.0 = 0.30 → Low
		{"Medium composite + None", 0.50, "", 0.60, PriorityCritical, PriorityLow},
		// Air-gapped style: α=0.80, composite=0.7, Act → final=0.8*0.7+0.2*1.0=0.76 >= 0.65 → High, ActFloor=High → High
		{"Air-gapped Act", 0.70, ssvc.DecisionAct, 0.80, PriorityHigh, PriorityHigh},
		// Exactly at critical: α=0.60, composite=1.0, Attend → final=0.6*1.0+0.4*0.75=0.9 >= 0.85 → Critical
		{"High composite + Attend → Critical", 1.0, ssvc.DecisionAttend, 0.60, PriorityCritical, PriorityCritical},
		// α=0.50 (internet-facing), composite=0.8, Act → final=0.5*0.8+0.5*1.0=0.9 >= 0.85 → Critical
		{"Internet-facing Act", 0.80, ssvc.DecisionAct, 0.50, PriorityCritical, PriorityCritical},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ResolvePriority(tt.composite, tt.ssvc, thresholds, tt.scoreWeight, tt.actFloor)
			if result != tt.expected {
				finalScore := tt.scoreWeight*tt.composite + (1-tt.scoreWeight)*SSVCToScore(tt.ssvc)
				t.Errorf("ResolvePriority(composite=%f, ssvc=%s, α=%f, floor=%s) = %s, want %s (finalScore=%.4f)",
					tt.composite, tt.ssvc, tt.scoreWeight, tt.actFloor, result, tt.expected, finalScore)
			}
		})
	}
}

func TestSSVCToScore(t *testing.T) {
	tests := []struct {
		decision ssvc.Decision
		expected float64
	}{
		{ssvc.DecisionAct, 1.0},
		{ssvc.DecisionAttend, 0.75},
		{ssvc.DecisionTrackStar, 0.50},
		{ssvc.DecisionTrack, 0.25},
		{"", 0.0},
	}

	for _, tt := range tests {
		t.Run(string(tt.decision), func(t *testing.T) {
			result := SSVCToScore(tt.decision)
			if result != tt.expected {
				t.Errorf("SSVCToScore(%s) = %f, want %f", tt.decision, result, tt.expected)
			}
		})
	}
}

func TestResolvePriority_V2_BoundaryValues(t *testing.T) {
	thresholds := DefaultThresholds() // C:0.85, H:0.65, M:0.40

	// Exactly at critical with weighted score
	// Need finalScore = 0.85 → α*composite + (1-α)*ssvcScore = 0.85
	// With α=0.60, ssvc=Track(0.25): 0.6*x + 0.4*0.25 = 0.85 → 0.6x = 0.75 → x=1.25 (impossible)
	// With α=0.60, ssvc=Act(1.0): 0.6*x + 0.4*1.0 = 0.85 → 0.6x = 0.45 → x=0.75
	result := ResolvePriority(0.75, ssvc.DecisionAct, thresholds, 0.60, PriorityCritical)
	// finalScore = 0.6*0.75 + 0.4*1.0 = 0.45+0.40 = 0.85 → Critical
	if result != PriorityCritical {
		t.Errorf("boundary at critical: expected Critical, got %s", result)
	}

	// Just below critical
	result = ResolvePriority(0.749, ssvc.DecisionAct, thresholds, 0.60, PriorityCritical)
	// finalScore = 0.6*0.749 + 0.4*1.0 = 0.4494+0.40 = 0.8494 < 0.85 → High, but ActFloor=Critical → Critical
	if result != PriorityCritical {
		t.Errorf("just below critical with ActFloor: expected Critical, got %s", result)
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

func TestPriorityFromSSVC(t *testing.T) {
	// PriorityFromSSVC still works with DefaultSSVCMapping for display purposes
	tests := []struct {
		decision ssvc.Decision
		expected PriorityLevel
	}{
		{ssvc.DecisionAct, PriorityCritical},
		{ssvc.DecisionAttend, PriorityHigh},
		{ssvc.DecisionTrackStar, PriorityMedium},
		{ssvc.DecisionTrack, PriorityLow},
		{"unknown", PriorityLow},
	}

	for _, tt := range tests {
		t.Run(string(tt.decision), func(t *testing.T) {
			result := PriorityFromSSVC(tt.decision)
			if result != tt.expected {
				t.Errorf("PriorityFromSSVC(%s) = %s, want %s", tt.decision, result, tt.expected)
			}
		})
	}
}
