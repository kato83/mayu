package triage

import (
	"fmt"
	"sort"
)

// Rationale contains the human-readable and machine-processable explanation
// of why a vulnerability received its priority level.
type Rationale struct {
	// Summary is a one-line human-readable explanation.
	Summary string `json:"summary"`

	// TopFactors lists the most impactful factors in descending order.
	TopFactors []Factor `json:"top_factors"`

	// SignalDetails contains all signal values and their contributions.
	SignalDetails []SignalContribution `json:"signal_details"`

	// SSVCDecision is the SSVC outcome (if available).
	SSVCDecision string `json:"ssvc_decision,omitempty"`

	// ResolutionMethod describes how the final priority was determined
	// (e.g., "score_based", "ssvc_override", "combined_max").
	ResolutionMethod string `json:"resolution_method"`
}

// Factor represents a key contributing factor in the triage decision.
type Factor struct {
	Description string `json:"description"`
	Impact      string `json:"impact"`
}

// BuildRationale generates a rationale from signal contributions and the SSVC decision.
func BuildRationale(contributions []SignalContribution, ssvcDecision string, ssvcMethod string, priorityLevel PriorityLevel, resolutionMethod string) *Rationale {
	// Sort contributions by contribution value descending
	sorted := make([]SignalContribution, len(contributions))
	copy(sorted, contributions)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Contribution > sorted[j].Contribution
	})

	// Build top factors (max 3)
	var topFactors []Factor
	for _, sc := range sorted {
		if !sc.Available || sc.Contribution <= 0 {
			continue
		}
		if len(topFactors) >= 3 {
			break
		}
		topFactors = append(topFactors, Factor{
			Description: signalDescription(sc.Signal, sc.RawValue),
			Impact:      signalImpact(sc.Contribution),
		})
	}

	// For Critical priority, ensure the highest contributor is first
	// (already handled by sort, but explicitly placed for clarity)

	summary := buildSummary(topFactors, priorityLevel)

	return &Rationale{
		Summary:          summary,
		TopFactors:       topFactors,
		SignalDetails:    contributions,
		SSVCDecision:     ssvcDecision,
		ResolutionMethod: resolutionMethod,
	}
}

// signalDescription generates a human-readable description for a signal.
func signalDescription(signal string, rawValue float64) string {
	switch signal {
	case "cvss":
		return fmt.Sprintf("CVSS base score %.1f/10.0", rawValue*10)
	case "epss":
		return fmt.Sprintf("EPSS exploitation probability %.0f%%", rawValue*100)
	case "lev":
		return fmt.Sprintf("LEV exploitation likelihood %.0f%%", rawValue*100)
	case "kev":
		if rawValue >= 1.0 {
			return "Listed in CISA KEV catalog"
		}
		return "Not in CISA KEV catalog"
	case "patch":
		if rawValue >= 1.0 {
			return "No patch available"
		}
		return "Patch available"
	case "age":
		return fmt.Sprintf("Age factor %.0f%% (older = higher risk)", rawValue*100)
	case "exploitdb":
		if rawValue >= 1.0 {
			return "Public exploit exists in Exploit-DB"
		}
		return "No known public exploit"
	case "exploitability":
		if rawValue >= 0.8 {
			return "High exploitability (easy to attack: network, low complexity, no auth)"
		} else if rawValue >= 0.5 {
			return "Moderate exploitability"
		}
		return "Low exploitability (difficult to attack)"
	default:
		return fmt.Sprintf("%s: %.2f", signal, rawValue)
	}
}

// signalImpact categorizes a contribution value into impact level.
func signalImpact(contribution float64) string {
	switch {
	case contribution >= 0.15:
		return "high"
	case contribution >= 0.08:
		return "medium"
	default:
		return "low"
	}
}

// buildSummary generates a one-line summary from top factors.
func buildSummary(factors []Factor, priority PriorityLevel) string {
	if len(factors) == 0 {
		return fmt.Sprintf("Priority: %s (no significant contributing signals)", priority)
	}

	summary := ""
	for i, f := range factors {
		if i > 0 {
			summary += ", "
		}
		summary += f.Description
	}
	return summary
}
