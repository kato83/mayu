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
		VulnerabilityID: "CVE-2024-1234",
		CVSSScore:       float64Ptr(9.8),
		EPSSScore:       float64Ptr(0.97),
		LEVScore:        float64Ptr(1.0),
		InKEV:           true,
		PatchAvailable:  false,
		PublishedAt:     &published,
		HasExploit:      true,
		IsReachable:     boolPtr(true),
	}

	result, err := engine.Triage(ctx, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.PriorityLevel != PriorityCritical {
		t.Errorf("expected Critical, got %s", result.PriorityLevel)
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
}

func TestEngine_Triage_Low(t *testing.T) {
	engine := NewEngine(nil)
	ctx := context.Background()

	input := &TriageInput{
		VulnerabilityID: "CVE-2024-5678",
		CVSSScore:       float64Ptr(2.5),
		EPSSScore:       float64Ptr(0.01),
		LEVScore:        float64Ptr(0.05),
		InKEV:           false,
		PatchAvailable:  true,
		HasExploit:      false,
		IsReachable:     boolPtr(false),
	}

	result, err := engine.Triage(ctx, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.PriorityLevel != PriorityLow {
		t.Errorf("expected Low, got %s", result.PriorityLevel)
	}
	if result.CompositeScore > 0.40 {
		t.Errorf("expected low composite score (<0.40), got %f", result.CompositeScore)
	}
}

func TestEngine_Triage_SSVCOverride(t *testing.T) {
	engine := NewEngine(nil)
	ctx := context.Background()

	// Low score signals but SSVC says "Act"
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

	// SSVC "Act" should override the low score
	if result.PriorityLevel != PriorityCritical {
		t.Errorf("expected Critical (SSVC override), got %s", result.PriorityLevel)
	}
	if result.SSVCDecision != "Act" {
		t.Errorf("expected SSVC decision 'Act', got %q", result.SSVCDecision)
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
			VulnerabilityID: "CRITICAL-1",
			CVSSScore:       float64Ptr(9.8),
			EPSSScore:       float64Ptr(0.95),
			InKEV:           true,
			PatchAvailable:  false,
			HasExploit:      true,
			IsReachable:     boolPtr(true),
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
		Weights: &ExtendedWeights{
			CVSS: 0.15, EPSS: 0.25, LEV: 0.15, KEV: 0.20,
			Patch: 0.05, Age: 0.03, ExploitDB: 0.12, Reachability: 0.05,
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
