package triage

import (
	"github.com/kato83/mayu/internal/cvss"
	"github.com/kato83/mayu/internal/ssvc"
)

// Deprecated: DefaultSSVCMapping is kept for display/reference purposes only.
// It is no longer used in the priority calculation (v2 uses weighted average + act floor).
var DefaultSSVCMapping = map[ssvc.Decision]PriorityLevel{
	ssvc.DecisionAct:       PriorityCritical,
	ssvc.DecisionAttend:    PriorityHigh,
	ssvc.DecisionTrackStar: PriorityMedium,
	ssvc.DecisionTrack:     PriorityLow,
}

// SSVCToScore converts an SSVC decision to a numeric score [0.0, 1.0].
func SSVCToScore(decision ssvc.Decision) float64 {
	switch decision {
	case ssvc.DecisionAct:
		return 1.0
	case ssvc.DecisionAttend:
		return 0.75
	case ssvc.DecisionTrackStar:
		return 0.50
	case ssvc.DecisionTrack:
		return 0.25
	default:
		return 0.0
	}
}

// ResolvePriority determines the final priority using weighted average + Act floor.
// Final Score = α × compositeScore + (1-α) × SSVCScore
// Final Priority = max(PriorityFromScore(finalScore), actFloor if SSVC=Act)
func ResolvePriority(compositeScore float64, ssvcDecision ssvc.Decision, thresholds *Thresholds, scoreWeight float64, actFloor PriorityLevel) PriorityLevel {
	ssvcScore := SSVCToScore(ssvcDecision)
	finalScore := scoreWeight*compositeScore + (1-scoreWeight)*ssvcScore

	thresholdPriority := PriorityFromScore(finalScore, thresholds)

	// Apply Act floor
	if ssvcDecision == ssvc.DecisionAct {
		if PriorityRank(actFloor) > PriorityRank(thresholdPriority) {
			return actFloor
		}
	}

	return thresholdPriority
}

// PriorityFromScore determines priority level based on composite score and thresholds.
func PriorityFromScore(score float64, thresholds *Thresholds) PriorityLevel {
	if thresholds == nil {
		thresholds = DefaultThresholds()
	}
	switch {
	case score >= thresholds.Critical:
		return PriorityCritical
	case score >= thresholds.High:
		return PriorityHigh
	case score >= thresholds.Medium:
		return PriorityMedium
	default:
		return PriorityLow
	}
}

// PriorityFromSSVC maps an SSVC decision to a priority level.
func PriorityFromSSVC(decision ssvc.Decision) PriorityLevel {
	if p, ok := DefaultSSVCMapping[decision]; ok {
		return p
	}
	return PriorityLow
}

// EstimateSSVC infers SSVC decision points from available risk signals
// when direct SSVC data is unavailable.
func EstimateSSVC(input *TriageInput) ssvc.Decision {
	// Determine Exploitation
	var exploitation ssvc.Exploitation
	switch {
	case input.InKEV:
		exploitation = ssvc.ExploitationActive
	case input.HasExploit:
		exploitation = ssvc.ExploitationPOC
	default:
		exploitation = ssvc.ExploitationNone
	}

	// Determine Automatable
	var automatable ssvc.Automatable
	if input.EPSSScore != nil && *input.EPSSScore > 0.5 {
		automatable = ssvc.AutomatableYes
	} else {
		automatable = ssvc.AutomatableNo
	}

	// Determine TechnicalImpact from CVSS vector C/I/A if available, else fallback to score.
	technicalImpact := estimateTechnicalImpact(input)

	return ssvc.Evaluate(exploitation, automatable, technicalImpact)
}

// EvaluateSSVC evaluates SSVC decision from input.
// Uses direct options if available, otherwise estimates from signals.
func EvaluateSSVC(input *TriageInput) (ssvc.Decision, string) {
	// Try direct evaluation from SSVCOptions
	if len(input.SSVCOptions) > 0 {
		decision, ok := ssvc.EvaluateFromOptions(input.SSVCOptions)
		if ok {
			return decision, "direct"
		}
	}

	// Estimate from available signals
	decision := EstimateSSVC(input)
	if decision == "" {
		return ssvc.DecisionTrack, "estimated"
	}
	return decision, "estimated"
}

// estimateTechnicalImpact determines SSVC Technical Impact from CVSS vector C/I/A metrics.
// It first tries to parse the CVSS vector string for precise C/I/A values.
// If the vector is unavailable, it falls back to the CVSS base score heuristic.
//
// SSVC Technical Impact definition:
//   - Total: attacker gains full control (C:High + I:High + A:High, or v2 C:Complete + I:Complete + A:Complete)
//   - Partial: anything less than total
func estimateTechnicalImpact(input *TriageInput) ssvc.TechnicalImpact {
	// 1. Try vector-based CIA analysis (preferred — more accurate)
	if input.CVSSVector != "" {
		cia := cvss.ParseCIAImpact(input.CVSSVector)
		if cia != nil {
			if cia.IsAllHigh() {
				return ssvc.TechnicalImpactTotal
			}
			return ssvc.TechnicalImpactPartial
		}
	}

	// 2. Fallback: score-based heuristic (existing behavior for backwards compatibility)
	if input.CVSSScore != nil && *input.CVSSScore >= 7.0 {
		return ssvc.TechnicalImpactTotal
	}
	return ssvc.TechnicalImpactPartial
}
