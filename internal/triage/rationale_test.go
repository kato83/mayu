package triage

import "testing"

func TestBuildRationale_CriticalPriority(t *testing.T) {
	contributions := []SignalContribution{
		{Signal: "cvss", RawValue: 0.98, Weight: 0.20, EffectiveWeight: 0.20, Contribution: 0.196, Available: true},
		{Signal: "epss", RawValue: 0.97, Weight: 0.20, EffectiveWeight: 0.20, Contribution: 0.194, Available: true},
		{Signal: "kev", RawValue: 1.0, Weight: 0.15, EffectiveWeight: 0.15, Contribution: 0.150, Available: true},
		{Signal: "lev", RawValue: 0.80, Weight: 0.15, EffectiveWeight: 0.15, Contribution: 0.120, Available: true},
		{Signal: "exploitdb", RawValue: 1.0, Weight: 0.10, EffectiveWeight: 0.10, Contribution: 0.100, Available: true},
		{Signal: "patch", RawValue: 1.0, Weight: 0.08, EffectiveWeight: 0.08, Contribution: 0.080, Available: true},
		{Signal: "age", RawValue: 0.5, Weight: 0.05, EffectiveWeight: 0.05, Contribution: 0.025, Available: true},
		{Signal: "reachability", RawValue: 1.0, Weight: 0.07, EffectiveWeight: 0.07, Contribution: 0.070, Available: true},
	}

	rationale := BuildRationale(contributions, "Act", "direct", PriorityCritical, "score_dominant")

	if rationale == nil {
		t.Fatal("expected non-nil rationale")
	}

	if rationale.Summary == "" {
		t.Error("expected non-empty summary")
	}

	if len(rationale.TopFactors) == 0 {
		t.Error("expected at least one top factor")
	}

	// First top factor should be the highest contributor (CVSS in this case)
	if rationale.TopFactors[0].Impact != "high" {
		t.Errorf("expected first factor to have high impact, got %q", rationale.TopFactors[0].Impact)
	}

	if rationale.SSVCDecision != "Act" {
		t.Errorf("expected SSVC decision 'Act', got %q", rationale.SSVCDecision)
	}

	if rationale.ResolutionMethod != "score_dominant" {
		t.Errorf("expected resolution method 'score_dominant', got %q", rationale.ResolutionMethod)
	}
}

func TestBuildRationale_NoContributions(t *testing.T) {
	contributions := []SignalContribution{
		{Signal: "cvss", RawValue: 0, Weight: 0.20, EffectiveWeight: 0.20, Contribution: 0, Available: true},
		{Signal: "epss", RawValue: 0, Weight: 0.20, EffectiveWeight: 0.20, Contribution: 0, Available: true},
	}

	rationale := BuildRationale(contributions, "Track", "estimated", PriorityLow, "score_dominant")

	if rationale == nil {
		t.Fatal("expected non-nil rationale")
	}

	if len(rationale.TopFactors) != 0 {
		t.Errorf("expected no top factors, got %d", len(rationale.TopFactors))
	}
}

func TestSignalDescription(t *testing.T) {
	tests := []struct {
		signal   string
		value    float64
		contains string
	}{
		{"cvss", 0.98, "9.8"},
		{"epss", 0.95, "95%"},
		{"kev", 1.0, "KEV"},
		{"patch", 1.0, "No patch"},
		{"patch", 0.0, "Patch available"},
		{"exploitdb", 1.0, "exploit"},
		{"reachability", 1.0, "reachable"},
	}

	for _, tt := range tests {
		t.Run(tt.signal, func(t *testing.T) {
			desc := signalDescription(tt.signal, tt.value)
			if desc == "" {
				t.Error("expected non-empty description")
			}
		})
	}
}
