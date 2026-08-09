package triage

import (
	"context"
	"testing"
	"time"
)

func TestEngine_Triage_Critical(t *testing.T) {
	engine := NewEngine(nil) // default profile
	ctx := context.Background()
	published := time.Now().Add(-60 * 24 * time.Hour)

	input := &TriageInput{
		VulnerabilityID:     "CVE-2024-1234",
		CVSSScore:           float64Ptr(9.8),
		EPSSScore:           float64Ptr(0.97),
		LEVScore:            float64Ptr(1.0),
		InKEV:               true,
		PatchAvailable:      false,
		PublishedAt:         &published,
		HasExploit:          true,
		ExploitabilityScore: float64Ptr(3.9),
	}

	result, err := engine.Triage(ctx, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.PriorityLevel != PriorityCritical {
		t.Errorf("expected Critical, got %s (composite=%.4f, ssvcScore=%.4f, finalScore=%.4f)",
			result.PriorityLevel, result.CompositeScore, result.SSVCScore, result.FinalScore)
	}
	if result.CompositeScore < 0.85 {
		t.Errorf("expected high composite score (>0.85), got %f", result.CompositeScore)
	}
	if result.SSVCDecision == "" {
		t.Error("expected non-empty SSVC decision")
	}
	if result.Rationale == nil {
		t.Error("expected non-nil rationale")
	}
	if result.ProfileUsed != "default" {
		t.Errorf("expected profile 'default', got %q", result.ProfileUsed)
	}
	if result.FinalScore == 0 {
		t.Error("expected non-zero FinalScore")
	}
	if result.ResolutionMethod == "" {
		t.Error("expected non-empty ResolutionMethod")
	}
}

func TestEngine_Triage_Low(t *testing.T) {
	engine := NewEngine(nil)
	ctx := context.Background()

	input := &TriageInput{
		VulnerabilityID:     "CVE-2024-5678",
		CVSSScore:           float64Ptr(2.5),
		EPSSScore:           float64Ptr(0.01),
		LEVScore:            float64Ptr(0.05),
		InKEV:               false,
		PatchAvailable:      true,
		HasExploit:          false,
		ExploitabilityScore: float64Ptr(0.5),
	}

	result, err := engine.Triage(ctx, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.PriorityLevel != PriorityLow {
		t.Errorf("expected Low, got %s (composite=%.4f, ssvcScore=%.4f, finalScore=%.4f)",
			result.PriorityLevel, result.CompositeScore, result.SSVCScore, result.FinalScore)
	}
	if result.CompositeScore > 0.40 {
		t.Errorf("expected low composite score (<0.40), got %f", result.CompositeScore)
	}
	// Low signals → SSVC should be Track (0.25), finalScore should be low
	if result.FinalScore > 0.40 {
		t.Errorf("expected low final score (<0.40), got %f", result.FinalScore)
	}
}

func TestEngine_Triage_SSVCOverride(t *testing.T) {
	engine := NewEngine(nil)
	ctx := context.Background()

	// Low score signals but SSVC says "Act" via direct options
	input := &TriageInput{
		VulnerabilityID: "CVE-2024-SSVC",
		CVSSScore:       float64Ptr(3.0),
		EPSSScore:       float64Ptr(0.1),
		InKEV:           false,
		PatchAvailable:  true,
		HasExploit:      false,
		SSVCOptions: map[string]string{
			"Exploitation":     "active",
			"Automatable":      "yes",
			"Technical Impact": "total",
		},
	}

	result, err := engine.Triage(ctx, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// SSVC "Act" with low composite → ActFloor should elevate to Critical
	if result.PriorityLevel != PriorityCritical {
		t.Errorf("expected Critical (ActFloor override), got %s (composite=%.4f, ssvcScore=%.4f, finalScore=%.4f, method=%s)",
			result.PriorityLevel, result.CompositeScore, result.SSVCScore, result.FinalScore, result.ResolutionMethod)
	}
	if result.SSVCDecision != "Act" {
		t.Errorf("expected SSVC decision 'Act', got %q", result.SSVCDecision)
	}
	if result.ResolutionMethod != "act_floor" {
		t.Errorf("expected resolution method 'act_floor', got %q", result.ResolutionMethod)
	}
}

func TestEngine_Triage_V2_FinalScore(t *testing.T) {
	engine := NewEngine(nil) // default: α=0.60, ActFloor=Critical
	ctx := context.Background()

	input := &TriageInput{
		VulnerabilityID: "CVE-2024-FINAL",
		CVSSScore:       float64Ptr(7.0),
		EPSSScore:       float64Ptr(0.5),
		LEVScore:        float64Ptr(0.3),
		InKEV:           false,
		PatchAvailable:  false,
		HasExploit:      false,
	}

	result, err := engine.Triage(ctx, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify SSVCScore is populated
	if result.SSVCScore < 0 || result.SSVCScore > 1.0 {
		t.Errorf("SSVCScore out of range: %f", result.SSVCScore)
	}

	// Verify FinalScore = α*composite + (1-α)*ssvcScore
	expectedFinal := 0.60*result.CompositeScore + 0.40*result.SSVCScore
	diff := result.FinalScore - expectedFinal
	if diff < -0.001 || diff > 0.001 {
		t.Errorf("FinalScore mismatch: got %f, expected %f (composite=%f, ssvc=%f)",
			result.FinalScore, expectedFinal, result.CompositeScore, result.SSVCScore)
	}

	// ResolutionMethod should be one of the valid v2 values
	validMethods := map[string]bool{"score_dominant": true, "ssvc_dominant": true, "act_floor": true}
	if !validMethods[result.ResolutionMethod] {
		t.Errorf("invalid resolution method: %q", result.ResolutionMethod)
	}
}

func TestEngine_Triage_V2_AirGapped(t *testing.T) {
	// Find the air-gapped profile from built-in templates
	var airGapped *Profile
	for _, tmpl := range BuiltinTemplates() {
		if tmpl.Name == "air-gapped" {
			p := tmpl
			airGapped = &p
			break
		}
	}
	if airGapped == nil {
		t.Fatal("air-gapped profile not found in built-in templates")
	}

	engine := NewEngine(airGapped) // α=0.80, ActFloor=High
	ctx := context.Background()

	input := &TriageInput{
		VulnerabilityID: "CVE-2024-AIRGAP",
		CVSSScore:       float64Ptr(6.0),
		EPSSScore:       float64Ptr(0.3),
		LEVScore:        float64Ptr(0.2),
		InKEV:           false,
		PatchAvailable:  false,
		HasExploit:      false,
		SSVCOptions: map[string]string{
			"Exploitation":     "active",
			"Automatable":      "yes",
			"Technical Impact": "total",
		},
	}

	result, err := engine.Triage(ctx, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Air-gapped: α=0.80, ActFloor=High
	// SSVC=Act → SSVCScore=1.0
	// finalScore = 0.80*composite + 0.20*1.0
	// ActFloor = High (not Critical like default)
	if result.SSVCDecision != "Act" {
		t.Errorf("expected SSVC 'Act', got %q", result.SSVCDecision)
	}
	if result.ProfileUsed != "air-gapped" {
		t.Errorf("expected profile 'air-gapped', got %q", result.ProfileUsed)
	}

	// With ActFloor=High, the minimum priority for Act is High (not Critical)
	if PriorityRank(result.PriorityLevel) < PriorityRank(PriorityHigh) {
		t.Errorf("expected at least High priority with ActFloor=High and SSVC=Act, got %s", result.PriorityLevel)
	}
}

func TestEngine_TriageBatch_Sorting(t *testing.T) {
	engine := NewEngine(nil)
	ctx := context.Background()

	inputs := []*TriageInput{
		{
			VulnerabilityID: "LOW-1",
			CVSSScore:       float64Ptr(2.0),
			EPSSScore:       float64Ptr(0.01),
			InKEV:           false,
			PatchAvailable:  true,
			HasExploit:      false,
		},
		{
			VulnerabilityID:     "CRITICAL-1",
			CVSSScore:           float64Ptr(9.8),
			EPSSScore:           float64Ptr(0.95),
			InKEV:               true,
			PatchAvailable:      false,
			HasExploit:          true,
			ExploitabilityScore: float64Ptr(3.9),
		},
		{
			VulnerabilityID: "MEDIUM-1",
			CVSSScore:       float64Ptr(5.5),
			EPSSScore:       float64Ptr(0.3),
			InKEV:           false,
			PatchAvailable:  false,
			HasExploit:      false,
		},
	}

	results, err := engine.TriageBatch(ctx, inputs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	// Results should be sorted by priority (Critical first)
	if results[0].VulnerabilityID != "CRITICAL-1" {
		t.Errorf("expected CRITICAL-1 first, got %s", results[0].VulnerabilityID)
	}
	if results[len(results)-1].VulnerabilityID != "LOW-1" {
		t.Errorf("expected LOW-1 last, got %s", results[len(results)-1].VulnerabilityID)
	}
}

func TestEngine_CustomProfile(t *testing.T) {
	profile := &Profile{
		Name:        "internet-facing",
		Description: "Internet-facing services",
		ScoreWeight: 0.50,
		ActFloor:    PriorityCritical,
		Weights: &ExtendedWeights{
			CVSS: 0.15, EPSS: 0.25, LEV: 0.15, KEV: 0.20,
			Patch: 0.05, Age: 0.03, ExploitDB: 0.12, Exploitability: 0.05,
		},
		Thresholds: &Thresholds{Critical: 0.80, High: 0.60, Medium: 0.35},
	}

	engine := NewEngine(profile)
	ctx := context.Background()

	input := &TriageInput{
		VulnerabilityID: "CVE-2024-CUSTOM",
		CVSSScore:       float64Ptr(7.0),
		EPSSScore:       float64Ptr(0.8),
		InKEV:           true,
		PatchAvailable:  false,
		HasExploit:      true,
	}

	result, err := engine.Triage(ctx, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.ProfileUsed != "internet-facing" {
		t.Errorf("expected profile 'internet-facing', got %q", result.ProfileUsed)
	}
}
