package policy

import (
	"testing"
)

func boolPtr(b bool) *bool          { return &b }
func float64Ptr(f float64) *float64 { return &f }
func intPtr(i int) *int             { return &i }

func TestEvaluator_Evaluate_SeverityMatch(t *testing.T) {
	pf := &PolicyFile{
		Policies: []Policy{
			{
				Name:   "block-critical",
				Action: "block",
				Conditions: Conditions{
					Severity: []string{"CRITICAL"},
				},
			},
			{
				Name:   "warn-high",
				Action: "warn",
				Conditions: Conditions{
					Severity: []string{"HIGH"},
				},
			},
		},
	}

	eval := NewEvaluator(pf)

	tests := []struct {
		name       string
		ctx        FindingContext
		wantAction Action
		wantPolicy string
	}{
		{
			name:       "critical finding blocked",
			ctx:        FindingContext{Severity: "CRITICAL"},
			wantAction: ActionBlock,
			wantPolicy: "block-critical",
		},
		{
			name:       "high finding warned",
			ctx:        FindingContext{Severity: "HIGH"},
			wantAction: ActionWarn,
			wantPolicy: "warn-high",
		},
		{
			name:       "medium finding allowed (no matching rule)",
			ctx:        FindingContext{Severity: "MEDIUM"},
			wantAction: ActionAllow,
			wantPolicy: "",
		},
		{
			name:       "case insensitive severity",
			ctx:        FindingContext{Severity: "critical"},
			wantAction: ActionBlock,
			wantPolicy: "block-critical",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := eval.Evaluate(tt.ctx)
			if result.Action != tt.wantAction {
				t.Errorf("Action = %q, want %q", result.Action, tt.wantAction)
			}
			if result.PolicyName != tt.wantPolicy {
				t.Errorf("PolicyName = %q, want %q", result.PolicyName, tt.wantPolicy)
			}
		})
	}
}

func TestEvaluator_Evaluate_MultipleConditions(t *testing.T) {
	pf := &PolicyFile{
		Policies: []Policy{
			{
				Name:   "block-critical-kev",
				Action: "block",
				Conditions: Conditions{
					Severity: []string{"CRITICAL"},
					InKEV:    boolPtr(true),
				},
			},
			{
				Name:   "block-high-epss",
				Action: "block",
				Conditions: Conditions{
					Severity:  []string{"CRITICAL", "HIGH"},
					EPSSAbove: float64Ptr(0.7),
				},
			},
			{
				Name:   "suppress-low-no-fix",
				Action: "suppress",
				Conditions: Conditions{
					Severity: []string{"LOW"},
					HasFix:   boolPtr(false),
				},
			},
		},
	}

	eval := NewEvaluator(pf)

	tests := []struct {
		name       string
		ctx        FindingContext
		wantAction Action
		wantPolicy string
	}{
		{
			name:       "critical + KEV blocked",
			ctx:        FindingContext{Severity: "CRITICAL", InKEV: true, EPSS: 0.5},
			wantAction: ActionBlock,
			wantPolicy: "block-critical-kev",
		},
		{
			name:       "critical + not KEV skips first rule, matches second if EPSS high",
			ctx:        FindingContext{Severity: "CRITICAL", InKEV: false, EPSS: 0.9},
			wantAction: ActionBlock,
			wantPolicy: "block-high-epss",
		},
		{
			name:       "critical + not KEV + low EPSS = allow",
			ctx:        FindingContext{Severity: "CRITICAL", InKEV: false, EPSS: 0.3},
			wantAction: ActionAllow,
			wantPolicy: "",
		},
		{
			name:       "high + high EPSS blocked",
			ctx:        FindingContext{Severity: "HIGH", EPSS: 0.8},
			wantAction: ActionBlock,
			wantPolicy: "block-high-epss",
		},
		{
			name:       "high + low EPSS = allow",
			ctx:        FindingContext{Severity: "HIGH", EPSS: 0.5},
			wantAction: ActionAllow,
			wantPolicy: "",
		},
		{
			name:       "low + no fix suppressed",
			ctx:        FindingContext{Severity: "LOW", HasFix: false},
			wantAction: ActionSuppress,
			wantPolicy: "suppress-low-no-fix",
		},
		{
			name:       "low + has fix = allow",
			ctx:        FindingContext{Severity: "LOW", HasFix: true},
			wantAction: ActionAllow,
			wantPolicy: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := eval.Evaluate(tt.ctx)
			if result.Action != tt.wantAction {
				t.Errorf("Action = %q, want %q", result.Action, tt.wantAction)
			}
			if result.PolicyName != tt.wantPolicy {
				t.Errorf("PolicyName = %q, want %q", result.PolicyName, tt.wantPolicy)
			}
		})
	}
}

func TestEvaluator_Evaluate_EPSSBelow(t *testing.T) {
	pf := &PolicyFile{
		Policies: []Policy{
			{
				Name:   "suppress-low-epss",
				Action: "suppress",
				Conditions: Conditions{
					EPSSBelow: float64Ptr(0.1),
				},
			},
		},
	}

	eval := NewEvaluator(pf)

	tests := []struct {
		name       string
		ctx        FindingContext
		wantAction Action
	}{
		{
			name:       "EPSS 0.05 suppressed",
			ctx:        FindingContext{Severity: "HIGH", EPSS: 0.05},
			wantAction: ActionSuppress,
		},
		{
			name:       "EPSS 0.1 not suppressed (not strictly below)",
			ctx:        FindingContext{Severity: "HIGH", EPSS: 0.1},
			wantAction: ActionAllow,
		},
		{
			name:       "EPSS 0.5 not suppressed",
			ctx:        FindingContext{Severity: "HIGH", EPSS: 0.5},
			wantAction: ActionAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := eval.Evaluate(tt.ctx)
			if result.Action != tt.wantAction {
				t.Errorf("Action = %q, want %q", result.Action, tt.wantAction)
			}
		})
	}
}

func TestEvaluator_Evaluate_LEVAbove(t *testing.T) {
	pf := &PolicyFile{
		Policies: []Policy{
			{
				Name:   "block-likely-exploited",
				Action: "block",
				Conditions: Conditions{
					LEVAbove: float64Ptr(0.9),
				},
			},
		},
	}

	eval := NewEvaluator(pf)

	tests := []struct {
		name       string
		ctx        FindingContext
		wantAction Action
	}{
		{
			name:       "LEV 0.95 blocked",
			ctx:        FindingContext{Severity: "MEDIUM", LEV: 0.95},
			wantAction: ActionBlock,
		},
		{
			name:       "LEV 0.9 not blocked (not strictly above)",
			ctx:        FindingContext{Severity: "MEDIUM", LEV: 0.9},
			wantAction: ActionAllow,
		},
		{
			name:       "LEV 0.5 not blocked",
			ctx:        FindingContext{Severity: "MEDIUM", LEV: 0.5},
			wantAction: ActionAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := eval.Evaluate(tt.ctx)
			if result.Action != tt.wantAction {
				t.Errorf("Action = %q, want %q", result.Action, tt.wantAction)
			}
		})
	}
}

func TestEvaluator_Evaluate_CWEMatch(t *testing.T) {
	pf := &PolicyFile{
		Policies: []Policy{
			{
				Name:   "block-injection",
				Action: "block",
				Conditions: Conditions{
					CWE: []string{"CWE-79", "CWE-89"},
				},
			},
		},
	}

	eval := NewEvaluator(pf)

	tests := []struct {
		name       string
		ctx        FindingContext
		wantAction Action
	}{
		{
			name:       "CWE-79 blocked",
			ctx:        FindingContext{Severity: "HIGH", CWEs: []string{"CWE-79"}},
			wantAction: ActionBlock,
		},
		{
			name:       "CWE-89 blocked",
			ctx:        FindingContext{Severity: "HIGH", CWEs: []string{"CWE-89", "CWE-20"}},
			wantAction: ActionBlock,
		},
		{
			name:       "CWE-20 only = allow",
			ctx:        FindingContext{Severity: "HIGH", CWEs: []string{"CWE-20"}},
			wantAction: ActionAllow,
		},
		{
			name:       "no CWEs = allow",
			ctx:        FindingContext{Severity: "HIGH", CWEs: nil},
			wantAction: ActionAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := eval.Evaluate(tt.ctx)
			if result.Action != tt.wantAction {
				t.Errorf("Action = %q, want %q", result.Action, tt.wantAction)
			}
		})
	}
}

func TestEvaluator_Evaluate_EcosystemMatch(t *testing.T) {
	pf := &PolicyFile{
		Policies: []Policy{
			{
				Name:   "block-go-critical",
				Action: "block",
				Conditions: Conditions{
					Severity:  []string{"CRITICAL"},
					Ecosystem: []string{"Go"},
				},
			},
		},
	}

	eval := NewEvaluator(pf)

	tests := []struct {
		name       string
		ctx        FindingContext
		wantAction Action
	}{
		{
			name:       "Go + critical blocked",
			ctx:        FindingContext{Severity: "CRITICAL", Ecosystem: "Go"},
			wantAction: ActionBlock,
		},
		{
			name:       "npm + critical = allow (wrong ecosystem)",
			ctx:        FindingContext{Severity: "CRITICAL", Ecosystem: "npm"},
			wantAction: ActionAllow,
		},
		{
			name:       "Go + high = allow (wrong severity)",
			ctx:        FindingContext{Severity: "HIGH", Ecosystem: "Go"},
			wantAction: ActionAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := eval.Evaluate(tt.ctx)
			if result.Action != tt.wantAction {
				t.Errorf("Action = %q, want %q", result.Action, tt.wantAction)
			}
		})
	}
}

func TestEvaluator_Evaluate_AgeDays(t *testing.T) {
	pf := &PolicyFile{
		Policies: []Policy{
			{
				Name:   "block-old-critical",
				Action: "block",
				Conditions: Conditions{
					Severity: []string{"CRITICAL"},
					AgeDays:  intPtr(30),
				},
			},
		},
	}

	eval := NewEvaluator(pf)

	tests := []struct {
		name       string
		ctx        FindingContext
		wantAction Action
	}{
		{
			name:       "60 days old blocked",
			ctx:        FindingContext{Severity: "CRITICAL", PublishedAge: 60},
			wantAction: ActionBlock,
		},
		{
			name:       "30 days old not blocked (not strictly above)",
			ctx:        FindingContext{Severity: "CRITICAL", PublishedAge: 30},
			wantAction: ActionAllow,
		},
		{
			name:       "10 days old not blocked",
			ctx:        FindingContext{Severity: "CRITICAL", PublishedAge: 10},
			wantAction: ActionAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := eval.Evaluate(tt.ctx)
			if result.Action != tt.wantAction {
				t.Errorf("Action = %q, want %q", result.Action, tt.wantAction)
			}
		})
	}
}

func TestEvaluator_Evaluate_FirstMatchWins(t *testing.T) {
	pf := &PolicyFile{
		Policies: []Policy{
			{
				Name:   "first-rule",
				Action: "block",
				Conditions: Conditions{
					Severity: []string{"CRITICAL"},
				},
			},
			{
				Name:   "second-rule",
				Action: "warn",
				Conditions: Conditions{
					Severity: []string{"CRITICAL", "HIGH"},
				},
			},
		},
	}

	eval := NewEvaluator(pf)

	// CRITICAL should match first rule (block), not second (warn)
	result := eval.Evaluate(FindingContext{Severity: "CRITICAL"})
	if result.Action != ActionBlock {
		t.Errorf("Action = %q, want %q (first-match-wins)", result.Action, ActionBlock)
	}
	if result.PolicyName != "first-rule" {
		t.Errorf("PolicyName = %q, want %q", result.PolicyName, "first-rule")
	}
}

func TestEvaluator_Evaluate_EmptyPolicies(t *testing.T) {
	pf := &PolicyFile{Policies: nil}
	eval := NewEvaluator(pf)

	result := eval.Evaluate(FindingContext{Severity: "CRITICAL"})
	if result.Action != ActionAllow {
		t.Errorf("Action = %q, want %q for empty policies", result.Action, ActionAllow)
	}
}
