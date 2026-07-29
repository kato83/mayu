package policy

import "strings"

// Evaluator evaluates findings against a loaded policy file.
type Evaluator struct {
	policies []Policy
}

// NewEvaluator creates an Evaluator from a PolicyFile.
func NewEvaluator(pf *PolicyFile) *Evaluator {
	return &Evaluator{policies: pf.Policies}
}

// Evaluate checks the finding context against all policies in order.
// The first matching policy determines the action.
// If no policy matches, ActionAllow is returned.
func (e *Evaluator) Evaluate(ctx FindingContext) EvalResult {
	for _, p := range e.policies {
		if matchesPolicy(ctx, p.Conditions) {
			return EvalResult{
				Action:     ValidActions[strings.ToLower(p.Action)],
				PolicyName: p.Name,
			}
		}
	}
	return EvalResult{Action: ActionAllow}
}

// matchesPolicy checks if a finding context satisfies all conditions of a policy.
// All non-nil/non-empty conditions must match (AND logic).
func matchesPolicy(ctx FindingContext, cond Conditions) bool {
	// Severity check: finding severity must be in the list
	if len(cond.Severity) > 0 {
		if !containsIgnoreCase(cond.Severity, ctx.Severity) {
			return false
		}
	}

	// InKEV check
	if cond.InKEV != nil {
		if *cond.InKEV != ctx.InKEV {
			return false
		}
	}

	// EPSS above threshold
	if cond.EPSSAbove != nil {
		if ctx.EPSS <= *cond.EPSSAbove {
			return false
		}
	}

	// EPSS below threshold
	if cond.EPSSBelow != nil {
		if ctx.EPSS >= *cond.EPSSBelow {
			return false
		}
	}

	// LEV above threshold
	if cond.LEVAbove != nil {
		if ctx.LEV <= *cond.LEVAbove {
			return false
		}
	}

	// HasFix check
	if cond.HasFix != nil {
		if *cond.HasFix != ctx.HasFix {
			return false
		}
	}

	// CWE check: at least one CWE must match
	if len(cond.CWE) > 0 {
		if !hasOverlap(cond.CWE, ctx.CWEs) {
			return false
		}
	}

	// Ecosystem check: finding ecosystem must be in the list
	if len(cond.Ecosystem) > 0 {
		if !containsIgnoreCase(cond.Ecosystem, ctx.Ecosystem) {
			return false
		}
	}

	// Age check: finding must be older than N days
	if cond.AgeDays != nil {
		if ctx.PublishedAge <= *cond.AgeDays {
			return false
		}
	}

	return true
}

// containsIgnoreCase checks if the list contains the value (case-insensitive).
func containsIgnoreCase(list []string, value string) bool {
	upper := strings.ToUpper(value)
	for _, item := range list {
		if strings.ToUpper(item) == upper {
			return true
		}
	}
	return false
}

// hasOverlap checks if there is at least one common element between two string slices (case-insensitive).
func hasOverlap(a, b []string) bool {
	set := make(map[string]bool, len(a))
	for _, item := range a {
		set[strings.ToUpper(item)] = true
	}
	for _, item := range b {
		if set[strings.ToUpper(item)] {
			return true
		}
	}
	return false
}
