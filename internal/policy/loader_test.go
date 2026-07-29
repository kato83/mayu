package policy

import (
	"strings"
	"testing"
)

func TestParse_ValidPolicyFile(t *testing.T) {
	yaml := `
policies:
  - name: block-critical-kev
    description: "Block CRITICAL vulnerabilities in KEV"
    conditions:
      severity: [CRITICAL]
      in_kev: true
    action: block
  - name: block-high-epss
    description: "Block HIGH with EPSS > 0.7"
    conditions:
      severity: [CRITICAL, HIGH]
      epss_above: 0.7
    action: block
  - name: warn-medium
    description: "Warn on MEDIUM"
    conditions:
      severity: [MEDIUM]
    action: warn
  - name: suppress-low-no-fix
    description: "Suppress LOW with no fix available"
    conditions:
      severity: [LOW]
      has_fix: false
    action: suppress
`

	pf, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if len(pf.Policies) != 4 {
		t.Fatalf("got %d policies, want 4", len(pf.Policies))
	}

	// Check first policy
	p := pf.Policies[0]
	if p.Name != "block-critical-kev" {
		t.Errorf("policies[0].Name = %q, want %q", p.Name, "block-critical-kev")
	}
	if p.Action != "block" {
		t.Errorf("policies[0].Action = %q, want %q", p.Action, "block")
	}
	if len(p.Conditions.Severity) != 1 || p.Conditions.Severity[0] != "CRITICAL" {
		t.Errorf("policies[0].Conditions.Severity = %v, want [CRITICAL]", p.Conditions.Severity)
	}
	if p.Conditions.InKEV == nil || *p.Conditions.InKEV != true {
		t.Errorf("policies[0].Conditions.InKEV = %v, want true", p.Conditions.InKEV)
	}

	// Check second policy
	p = pf.Policies[1]
	if p.Conditions.EPSSAbove == nil || *p.Conditions.EPSSAbove != 0.7 {
		t.Errorf("policies[1].Conditions.EPSSAbove = %v, want 0.7", p.Conditions.EPSSAbove)
	}

	// Check fourth policy
	p = pf.Policies[3]
	if p.Conditions.HasFix == nil || *p.Conditions.HasFix != false {
		t.Errorf("policies[3].Conditions.HasFix = %v, want false", p.Conditions.HasFix)
	}
}

func TestParse_InvalidYAML(t *testing.T) {
	_, err := Parse([]byte(`{invalid: yaml: [broken`))
	if err == nil {
		t.Fatal("Parse() error = nil, want error for invalid YAML")
	}
}

func TestValidate_EmptyPolicies(t *testing.T) {
	pf := &PolicyFile{}
	errs := Validate(pf)
	if len(errs) == 0 {
		t.Fatal("Validate() = no errors, want error for empty policies")
	}
}

func TestValidate_MissingName(t *testing.T) {
	pf := &PolicyFile{
		Policies: []Policy{
			{Action: "block", Conditions: Conditions{Severity: []string{"HIGH"}}},
		},
	}
	errs := Validate(pf)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Error(), "name is required") {
			found = true
		}
	}
	if !found {
		t.Error("Validate() did not report missing name")
	}
}

func TestValidate_DuplicateName(t *testing.T) {
	pf := &PolicyFile{
		Policies: []Policy{
			{Name: "dup", Action: "block", Conditions: Conditions{Severity: []string{"HIGH"}}},
			{Name: "dup", Action: "warn", Conditions: Conditions{Severity: []string{"MEDIUM"}}},
		},
	}
	errs := Validate(pf)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Error(), "duplicate policy name") {
			found = true
		}
	}
	if !found {
		t.Error("Validate() did not report duplicate name")
	}
}

func TestValidate_InvalidAction(t *testing.T) {
	pf := &PolicyFile{
		Policies: []Policy{
			{Name: "bad", Action: "reject", Conditions: Conditions{Severity: []string{"HIGH"}}},
		},
	}
	errs := Validate(pf)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Error(), "invalid action") {
			found = true
		}
	}
	if !found {
		t.Error("Validate() did not report invalid action")
	}
}

func TestValidate_InvalidSeverity(t *testing.T) {
	pf := &PolicyFile{
		Policies: []Policy{
			{Name: "bad", Action: "block", Conditions: Conditions{Severity: []string{"EXTREME"}}},
		},
	}
	errs := Validate(pf)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Error(), "invalid severity") {
			found = true
		}
	}
	if !found {
		t.Error("Validate() did not report invalid severity")
	}
}

func TestValidate_InvalidEPSS(t *testing.T) {
	overOne := 1.5
	pf := &PolicyFile{
		Policies: []Policy{
			{Name: "bad", Action: "block", Conditions: Conditions{EPSSAbove: &overOne}},
		},
	}
	errs := Validate(pf)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Error(), "epss_above must be between") {
			found = true
		}
	}
	if !found {
		t.Error("Validate() did not report invalid EPSS value")
	}
}

func TestValidate_NoConditions(t *testing.T) {
	pf := &PolicyFile{
		Policies: []Policy{
			{Name: "empty", Action: "block", Conditions: Conditions{}},
		},
	}
	errs := Validate(pf)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Error(), "at least one condition") {
			found = true
		}
	}
	if !found {
		t.Error("Validate() did not report missing conditions")
	}
}

func TestValidate_NegativeAgeDays(t *testing.T) {
	neg := -1
	pf := &PolicyFile{
		Policies: []Policy{
			{Name: "bad", Action: "block", Conditions: Conditions{AgeDays: &neg}},
		},
	}
	errs := Validate(pf)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Error(), "age_days_above must be non-negative") {
			found = true
		}
	}
	if !found {
		t.Error("Validate() did not report negative age_days_above")
	}
}

func TestValidate_ValidFile(t *testing.T) {
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
					Severity:  []string{"HIGH"},
					EPSSAbove: float64Ptr(0.5),
				},
			},
		},
	}

	errs := Validate(pf)
	if len(errs) != 0 {
		t.Errorf("Validate() returned %d errors for valid file: %v", len(errs), errs)
	}
}
