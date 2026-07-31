package triage

import (
	"math"
	"time"
)

// Scorer computes the composite risk score from weighted signals.
type Scorer struct {
	weights *ExtendedWeights
}

// NewScorer creates a new Scorer with the given weights.
func NewScorer(weights *ExtendedWeights) *Scorer {
	if weights == nil {
		weights = DefaultExtendedWeights()
	}
	return &Scorer{weights: weights}
}

// ComputeScore calculates the composite score with weight redistribution
// for unavailable signals. Returns a score in [0.0, 1.0] and the contribution
// breakdown for each signal.
func (s *Scorer) ComputeScore(input *TriageInput) (float64, []SignalContribution) {
	type signalDef struct {
		name      string
		value     float64
		weight    float64
		available bool
	}

	signals := []signalDef{
		{name: "cvss", value: normalizeCVSS(input.CVSSScore), weight: s.weights.CVSS, available: input.CVSSScore != nil},
		{name: "epss", value: normalizeEPSS(input.EPSSScore), weight: s.weights.EPSS, available: input.EPSSScore != nil},
		{name: "lev", value: normalizeLEV(input.LEVScore), weight: s.weights.LEV, available: input.LEVScore != nil},
		{name: "kev", value: normalizeKEV(input.InKEV), weight: s.weights.KEV, available: true},
		{name: "patch", value: normalizePatch(input.PatchAvailable), weight: s.weights.Patch, available: true},
		{name: "age", value: normalizeAge(input.PublishedAt), weight: s.weights.Age, available: input.PublishedAt != nil},
		{name: "exploitdb", value: normalizeExploitDB(input.HasExploit), weight: s.weights.ExploitDB, available: true},
		{name: "reachability", value: normalizeReachability(input.IsReachable), weight: s.weights.Reachability, available: input.IsReachable != nil},
	}

	// Calculate total weight and available weight for redistribution.
	var totalWeight, availableWeight float64
	for _, sig := range signals {
		totalWeight += sig.weight
		if sig.available {
			availableWeight += sig.weight
		}
	}

	// Build contributions
	contributions := make([]SignalContribution, len(signals))
	var composite float64

	for i, sig := range signals {
		var effectiveWeight float64
		if sig.available && availableWeight > 0 {
			effectiveWeight = sig.weight * (totalWeight / availableWeight)
		}

		contribution := effectiveWeight * sig.value
		composite += contribution

		contributions[i] = SignalContribution{
			Signal:          sig.name,
			RawValue:        sig.value,
			Weight:          sig.weight,
			EffectiveWeight: effectiveWeight,
			Contribution:    contribution,
			Available:       sig.available,
		}
	}

	// Clamp to [0.0, 1.0]
	composite = clamp(composite)

	return composite, contributions
}

// normalizeCVSS normalizes a CVSS score (0.0-10.0) to [0.0, 1.0].
func normalizeCVSS(score *float64) float64 {
	if score == nil {
		return 0
	}
	return clamp(*score / 10.0)
}

// normalizeEPSS returns the EPSS score directly (already in [0.0, 1.0]).
func normalizeEPSS(score *float64) float64 {
	if score == nil {
		return 0
	}
	return clamp(*score)
}

// normalizeLEV returns the LEV score directly (already in [0.0, 1.0]).
func normalizeLEV(score *float64) float64 {
	if score == nil {
		return 0
	}
	return clamp(*score)
}

// normalizeKEV returns 1.0 if in KEV, 0.0 otherwise.
func normalizeKEV(inKEV bool) float64 {
	if inKEV {
		return 1.0
	}
	return 0.0
}

// normalizePatch returns (1 - patch_available): 1.0 if no patch, 0.0 if patched.
// Higher risk when no patch is available.
func normalizePatch(patchAvailable bool) float64 {
	if patchAvailable {
		return 0.0
	}
	return 1.0
}

// normalizeAge computes an age factor in [0.0, 1.0] using logarithmic decay.
// Older vulnerabilities that remain unpatched are considered higher risk.
func normalizeAge(published *time.Time) float64 {
	if published == nil {
		return 0
	}
	days := time.Since(*published).Hours() / 24
	if days <= 0 {
		return 0
	}
	// log(1+days) / log(1+730) — saturates at ~1.0 after ~2 years
	factor := math.Log1p(days) / math.Log1p(730)
	return clamp(factor)
}

// normalizeExploitDB returns 1.0 if exploit exists, 0.0 otherwise.
func normalizeExploitDB(hasExploit bool) float64 {
	if hasExploit {
		return 1.0
	}
	return 0.0
}

// normalizeReachability returns 1.0 if reachable, 0.0 if unreachable.
func normalizeReachability(isReachable *bool) float64 {
	if isReachable == nil {
		return 0
	}
	if *isReachable {
		return 1.0
	}
	return 0.0
}

// clamp restricts a value to [0.0, 1.0].
func clamp(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1.0 {
		return 1.0
	}
	return v
}
