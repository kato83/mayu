package triage

import (
	"math"
	"testing"
	"time"
)

func float64Ptr(v float64) *float64 { return &v }

func TestComputeScore_AllSignalsAvailable(t *testing.T) {
	scorer := NewScorer(DefaultExtendedWeights())
	published := time.Now().Add(-90 * 24 * time.Hour)

	input := &TriageInput{
		VulnerabilityID:     "CVE-2024-1234",
		CVSSScore:           float64Ptr(9.8),
		EPSSScore:           float64Ptr(0.95),
		LEVScore:            float64Ptr(0.8),
		InKEV:               true,
		PatchAvailable:      false,
		PublishedAt:         &published,
		HasExploit:          true,
		ExploitabilityScore: float64Ptr(3.9),
	}

	score, contributions := scorer.ComputeScore(input)

	if score < 0.0 || score > 1.0 {
		t.Fatalf("score %f is out of range [0.0, 1.0]", score)
	}

	// With all high-risk signals, score should be high
	if score < 0.8 {
		t.Errorf("expected high score (>0.8) for all-high-risk input, got %f", score)
	}

	if len(contributions) != 8 {
		t.Errorf("expected 8 contributions, got %d", len(contributions))
	}

	// All signals should be available
	for _, c := range contributions {
		if !c.Available {
			t.Errorf("signal %s should be available", c.Signal)
		}
	}
}

func TestComputeScore_AllLowRisk(t *testing.T) {
	scorer := NewScorer(DefaultExtendedWeights())

	input := &TriageInput{
		VulnerabilityID:     "CVE-2024-5678",
		CVSSScore:           float64Ptr(2.0),
		EPSSScore:           float64Ptr(0.01),
		LEVScore:            float64Ptr(0.05),
		InKEV:               false,
		PatchAvailable:      true,
		PublishedAt:         nil,
		HasExploit:          false,
		ExploitabilityScore: float64Ptr(0.5),
	}

	score, _ := scorer.ComputeScore(input)

	if score < 0.0 || score > 1.0 {
		t.Fatalf("score %f is out of range [0.0, 1.0]", score)
	}

	// Low-risk signals should produce a low score
	if score > 0.3 {
		t.Errorf("expected low score (<0.3) for all-low-risk input, got %f", score)
	}
}

func TestComputeScore_MissingSignals(t *testing.T) {
	scorer := NewScorer(DefaultExtendedWeights())

	// Only CVSS and KEV available
	input := &TriageInput{
		VulnerabilityID: "CVE-2024-9999",
		CVSSScore:       float64Ptr(7.5),
		InKEV:           true,
		PatchAvailable:  false,
		HasExploit:      false,
	}

	score, contributions := scorer.ComputeScore(input)

	if score < 0.0 || score > 1.0 {
		t.Fatalf("score %f is out of range [0.0, 1.0]", score)
	}

	// Verify weight redistribution: effective weights of available signals should sum to ~1.0
	var effectiveSum float64
	for _, c := range contributions {
		if c.Available {
			effectiveSum += c.EffectiveWeight
		}
	}
	if math.Abs(effectiveSum-1.0) > 0.001 {
		t.Errorf("effective weight sum should be ~1.0 (got %f)", effectiveSum)
	}
}

func TestComputeScore_ZeroCVSS(t *testing.T) {
	scorer := NewScorer(DefaultExtendedWeights())

	input := &TriageInput{
		VulnerabilityID:     "CVE-2024-0000",
		CVSSScore:           float64Ptr(0.0),
		EPSSScore:           float64Ptr(0.0),
		LEVScore:            float64Ptr(0.0),
		InKEV:               false,
		PatchAvailable:      true,
		HasExploit:          false,
		ExploitabilityScore: float64Ptr(0.0),
	}

	score, _ := scorer.ComputeScore(input)

	if score != 0.0 {
		t.Errorf("expected score 0.0 for all-zero signals, got %f", score)
	}
}

func TestComputeScore_MaxCVSS(t *testing.T) {
	scorer := NewScorer(DefaultExtendedWeights())
	published := time.Now().Add(-1000 * 24 * time.Hour) // Very old

	input := &TriageInput{
		VulnerabilityID:     "CVE-2024-MAX",
		CVSSScore:           float64Ptr(10.0),
		EPSSScore:           float64Ptr(1.0),
		LEVScore:            float64Ptr(1.0),
		InKEV:               true,
		PatchAvailable:      false,
		PublishedAt:         &published,
		HasExploit:          true,
		ExploitabilityScore: float64Ptr(3.9),
	}

	score, _ := scorer.ComputeScore(input)

	// All signals at max should give score very close to 1.0
	if score < 0.95 {
		t.Errorf("expected score near 1.0 for all-max signals, got %f", score)
	}
}
