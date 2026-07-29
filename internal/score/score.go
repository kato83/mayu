// Package score provides composite risk score computation for vulnerabilities.
//
// The composite score integrates multiple risk signals (CVSS, EPSS, LEV, KEV,
// patch availability, and age) into a single normalized [0.0, 1.0] score
// for vulnerability prioritization.
package score

import (
	"math"
	"time"
)

// DefaultWeights returns the default weight configuration for composite scoring.
func DefaultWeights() Weights {
	return Weights{
		CVSS:  0.25,
		EPSS:  0.25,
		LEV:   0.20,
		KEV:   0.15,
		Patch: 0.10,
		Age:   0.05,
	}
}

// Weights defines the relative weights for each risk signal in the composite score.
// All weights should sum to 1.0.
type Weights struct {
	CVSS  float64
	EPSS  float64
	LEV   float64
	KEV   float64
	Patch float64
	Age   float64
}

// Input contains all the data needed to compute a composite risk score.
type Input struct {
	// CVSSScore is the base CVSS score (0.0 - 10.0). nil if unavailable.
	CVSSScore *float64

	// EPSSScore is the EPSS exploitation probability (0.0 - 1.0). nil if unavailable.
	EPSSScore *float64

	// LEVScore is the LEV (Likely Exploited Vulnerability) probability (0.0 - 1.0). nil if unavailable.
	LEVScore *float64

	// InKEV indicates whether the vulnerability is in the CISA KEV catalog.
	InKEV bool

	// PatchAvailable indicates whether a patch/fix is known to exist.
	PatchAvailable bool

	// PublishedAt is when the vulnerability was first published. Zero value if unknown.
	PublishedAt time.Time
}

// Compute calculates the composite risk score using the given weights and input signals.
// Returns a score in [0.0, 1.0] where higher means higher risk.
//
// The formula is:
//
//	composite = w_cvss*normalize(cvss) + w_epss*epss + w_lev*lev
//	          + w_kev*kev_flag + w_patch*(1-patch_available) + w_age*age_factor
//
// For unavailable signals, the weight is redistributed proportionally among available signals.
func Compute(input Input, weights Weights) float64 {
	type signal struct {
		value     float64
		weight    float64
		available bool
	}

	signals := []signal{
		{value: normalizeCVSS(input.CVSSScore), weight: weights.CVSS, available: input.CVSSScore != nil},
		{value: normalizeEPSS(input.EPSSScore), weight: weights.EPSS, available: input.EPSSScore != nil},
		{value: normalizeLEV(input.LEVScore), weight: weights.LEV, available: input.LEVScore != nil},
		{value: normalizeKEV(input.InKEV), weight: weights.KEV, available: true}, // KEV is always known (false = not in KEV)
		{value: normalizePatch(input.PatchAvailable), weight: weights.Patch, available: true},
		{value: normalizeAge(input.PublishedAt), weight: weights.Age, available: !input.PublishedAt.IsZero()},
	}

	// Calculate total weight of available signals for redistribution.
	var availableWeight float64
	var totalWeight float64
	for _, s := range signals {
		totalWeight += s.weight
		if s.available {
			availableWeight += s.weight
		}
	}

	if availableWeight == 0 {
		return 0
	}

	// Compute weighted sum with redistribution for missing signals.
	var composite float64
	for _, s := range signals {
		if s.available {
			// Redistribute weight: this signal's effective weight = original weight * (totalWeight / availableWeight)
			effectiveWeight := s.weight * (totalWeight / availableWeight)
			composite += effectiveWeight * s.value
		}
	}

	// Clamp to [0.0, 1.0]
	if composite < 0 {
		return 0
	}
	if composite > 1.0 {
		return 1.0
	}
	return composite
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

// normalizeAge computes an age factor in [0.0, 1.0] using a logarithmic decay.
// Older vulnerabilities that remain unpatched are considered higher risk.
// The factor saturates at ~1.0 after approximately 2 years (730 days).
func normalizeAge(published time.Time) float64 {
	if published.IsZero() {
		return 0
	}
	days := time.Since(published).Hours() / 24
	if days <= 0 {
		return 0
	}
	// Logarithmic scaling: log(1 + days) / log(1 + 730)
	// This gives ~0.5 at ~26 days, ~0.75 at ~200 days, saturates near 1.0 at 730+ days
	factor := math.Log1p(days) / math.Log1p(730)
	return clamp(factor)
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
