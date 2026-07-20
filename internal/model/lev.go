// Package model defines Go structs for LEV (Likely Exploited Vulnerabilities) computation.
// See NIST CSWP 41: https://doi.org/10.6028/NIST.CSWP.41
//
// LEV estimates the probability that a vulnerability has already been exploited
// in the wild, based on historical EPSS scores and KEV membership.
//
// The calculation follows the rigorous approach (not the P30/30 approximation):
//   - Convert each daily EPSS score (P30) to a daily probability (P1)
//     using: P1 = 1 - (1 - P30)^(1/30)
//   - Compound across all days: LEV = 1 - product of (1 - P1_i) for each day i
//   - If the CVE is in the CISA KEV catalog, LEV = 1.0 (confirmed exploitation)
package model

import (
	"math"
	"time"
)

// LEVScore represents the computed LEV (Likely Exploited Vulnerabilities) score
// for a single CVE. It provides a probability estimate that the vulnerability
// has already been exploited in the wild.
type LEVScore struct {
	// CVEID is the CVE identifier (e.g., "CVE-2023-38831").
	CVEID string `json:"cve_id"`

	// LEV is the computed probability of past exploitation [0.0, 1.0].
	// A value of 1.0 means confirmed exploitation (e.g., in CISA KEV).
	LEV float64 `json:"lev"`

	// InKEV indicates whether the CVE is in the CISA KEV catalog.
	// If true, LEV is automatically set to 1.0.
	InKEV bool `json:"in_kev"`

	// EPSSScoreCount is the number of historical EPSS daily scores used
	// in the computation.
	EPSSScoreCount int `json:"epss_score_count"`

	// FirstEPSSDate is the earliest EPSS score date used in computation.
	FirstEPSSDate *time.Time `json:"first_epss_date,omitempty"`

	// LastEPSSDate is the most recent EPSS score date used in computation.
	LastEPSSDate *time.Time `json:"last_epss_date,omitempty"`

	// ComputedAt is the timestamp when this LEV score was calculated.
	ComputedAt time.Time `json:"computed_at"`
}

// LEVInput represents the input data needed to compute a LEV score for a single CVE.
type LEVInput struct {
	// CVEID is the CVE identifier.
	CVEID string

	// InKEV indicates whether the CVE is in the CISA KEV catalog.
	InKEV bool

	// EPSSScores is the list of historical EPSS daily scores (P30 values)
	// ordered by date. Each entry is a (date, P30) pair.
	EPSSScores []EPSSDailyScore
}

// EPSSDailyScore represents a single day's EPSS score for LEV computation.
type EPSSDailyScore struct {
	Date time.Time
	P30  float64 // EPSS probability over 30 days [0.0, 1.0]
}

// ComputeLEV calculates the LEV score from the given input.
//
// Algorithm (rigorous approach from NIST CSWP 41):
//  1. If the CVE is in KEV, return LEV = 1.0 (confirmed exploitation).
//  2. If no EPSS data is available, return LEV = 0.0.
//  3. For each historical EPSS score (P30):
//     a. Convert to daily probability: P1 = 1 - (1 - P30)^(1/30)
//     b. Accumulate non-exploitation probability: product *= (1 - P1)
//  4. LEV = 1 - product (probability of exploitation at some point in the past)
//
// This uses the rigorous conversion from P30 to P1 rather than the
// approximation (P30/30) which is inaccurate for high EPSS scores.
func ComputeLEV(input LEVInput) LEVScore {
	now := time.Now().UTC()

	result := LEVScore{
		CVEID:      input.CVEID,
		InKEV:      input.InKEV,
		ComputedAt: now,
	}

	// If in KEV, exploitation is confirmed → LEV = 1.0
	if input.InKEV {
		result.LEV = 1.0
		result.EPSSScoreCount = len(input.EPSSScores)
		if len(input.EPSSScores) > 0 {
			first := input.EPSSScores[0].Date
			last := input.EPSSScores[len(input.EPSSScores)-1].Date
			result.FirstEPSSDate = &first
			result.LastEPSSDate = &last
		}
		return result
	}

	// No EPSS data → LEV = 0.0
	if len(input.EPSSScores) == 0 {
		result.LEV = 0.0
		return result
	}

	// Compute LEV using rigorous approach
	// LEV = 1 - ∏(1 - P1_i) for each day i
	//
	// Use log-space computation for numerical stability when dealing with
	// many small probabilities: log(∏(1-P1_i)) = Σ log(1-P1_i)
	var logProduct float64

	for _, score := range input.EPSSScores {
		p1 := p30ToP1(score.P30)

		// Skip negligible probabilities to avoid log(0) issues
		if p1 <= 0 {
			continue
		}
		if p1 >= 1.0 {
			// If any day has P1 >= 1.0, exploitation is certain
			result.LEV = 1.0
			result.EPSSScoreCount = len(input.EPSSScores)
			first := input.EPSSScores[0].Date
			last := input.EPSSScores[len(input.EPSSScores)-1].Date
			result.FirstEPSSDate = &first
			result.LastEPSSDate = &last
			return result
		}

		logProduct += math.Log(1 - p1)
	}

	// LEV = 1 - exp(Σ log(1 - P1_i))
	result.LEV = 1 - math.Exp(logProduct)

	// Clamp to [0, 1] to handle floating point imprecision
	if result.LEV < 0 {
		result.LEV = 0
	}
	if result.LEV > 1 {
		result.LEV = 1
	}

	result.EPSSScoreCount = len(input.EPSSScores)
	first := input.EPSSScores[0].Date
	last := input.EPSSScores[len(input.EPSSScores)-1].Date
	result.FirstEPSSDate = &first
	result.LastEPSSDate = &last

	return result
}

// p30ToP1 converts a 30-day exploitation probability (EPSS score) to a
// daily probability using the rigorous formula:
//
//	P1 = 1 - (1 - P30)^(1/30)
//
// This is derived from the independent events assumption:
//
//	P30 = 1 - (1 - P1)^30
//	=> (1 - P1)^30 = 1 - P30
//	=> 1 - P1 = (1 - P30)^(1/30)
//	=> P1 = 1 - (1 - P30)^(1/30)
func p30ToP1(p30 float64) float64 {
	if p30 <= 0 {
		return 0
	}
	if p30 >= 1 {
		return 1
	}
	return 1 - math.Pow(1-p30, 1.0/30.0)
}
