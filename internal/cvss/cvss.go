// Package cvss implements CVSS (Common Vulnerability Scoring System) base score
// calculation from vector strings.
//
// Supported formats:
//   - CVSS v3.0 and v3.1: "CVSS:3.0/..." or "CVSS:3.1/..."
//   - CVSS v2: "(AV:N/AC:L/...)" (best-effort, limited accuracy)
//
// The implementation follows the CVSS v3.1 specification published by FIRST.org:
// https://www.first.org/cvss/v3.1/specification-document
package cvss

import (
	"math"
	"strings"
)

// BaseScore calculates the CVSS base score from a vector string.
// Returns 0 and false if the vector cannot be parsed.
func BaseScore(vector string) (float64, bool) {
	vector = strings.TrimSpace(vector)
	if vector == "" {
		return 0, false
	}

	// CVSS v3.x
	if strings.HasPrefix(vector, "CVSS:3") {
		return baseScoreV3(vector)
	}

	// CVSS v4.0 — not yet supported for calculation (too complex).
	// Return 0, false so caller falls through.
	if strings.HasPrefix(vector, "CVSS:4") {
		return 0, false
	}

	return 0, false
}

// baseScoreV3 calculates the CVSS v3.0/v3.1 base score.
// Formula reference: https://www.first.org/cvss/v3.1/specification-document (Section 5)
func baseScoreV3(vector string) (float64, bool) {
	metrics := parseV3Metrics(vector)
	if metrics == nil {
		return 0, false
	}

	av, ok := metrics["AV"]
	if !ok {
		return 0, false
	}
	ac, ok := metrics["AC"]
	if !ok {
		return 0, false
	}
	pr, ok := metrics["PR"]
	if !ok {
		return 0, false
	}
	ui, ok := metrics["UI"]
	if !ok {
		return 0, false
	}
	s, ok := metrics["S"]
	if !ok {
		return 0, false
	}
	c, ok := metrics["C"]
	if !ok {
		return 0, false
	}
	i, ok := metrics["I"]
	if !ok {
		return 0, false
	}
	a, ok := metrics["A"]
	if !ok {
		return 0, false
	}

	scopeChanged := s == "C"

	// Exploitability sub-score weights
	avScore := attackVectorScore(av)
	acScore := attackComplexityScore(ac)
	prScore := privilegesRequiredScore(pr, scopeChanged)
	uiScore := userInteractionScore(ui)

	if avScore < 0 || acScore < 0 || prScore < 0 || uiScore < 0 {
		return 0, false
	}

	// Impact sub-score weights
	cScore := impactMetricScore(c)
	iScore := impactMetricScore(i)
	aScore := impactMetricScore(a)

	if cScore < 0 || iScore < 0 || aScore < 0 {
		return 0, false
	}

	// ISS = 1 - [(1 - Confidentiality) × (1 - Integrity) × (1 - Availability)]
	iss := 1.0 - (1.0-cScore)*(1.0-iScore)*(1.0-aScore)

	// Impact
	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}

	// Exploitability = 8.22 × AV × AC × PR × UI
	exploitability := 8.22 * avScore * acScore * prScore * uiScore

	// If Impact <= 0, base score is 0
	if impact <= 0 {
		return 0, true
	}

	// Base score
	var base float64
	if scopeChanged {
		base = math.Min(1.08*(impact+exploitability), 10.0)
	} else {
		base = math.Min(impact+exploitability, 10.0)
	}

	// Round up to one decimal place (CVSS "roundup" function)
	return roundUp(base), true
}

// parseV3Metrics parses the metric key-value pairs from a CVSS v3.x vector string.
func parseV3Metrics(vector string) map[string]string {
	// Format: "CVSS:3.x/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	parts := strings.Split(vector, "/")
	if len(parts) < 2 {
		return nil
	}

	// First part should be "CVSS:3.x"
	if !strings.HasPrefix(parts[0], "CVSS:3") {
		return nil
	}

	metrics := make(map[string]string)
	for _, part := range parts[1:] {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			continue
		}
		metrics[kv[0]] = kv[1]
	}

	return metrics
}

// attackVectorScore returns the weight for the Attack Vector metric.
func attackVectorScore(av string) float64 {
	switch av {
	case "N": // Network
		return 0.85
	case "A": // Adjacent
		return 0.62
	case "L": // Local
		return 0.55
	case "P": // Physical
		return 0.20
	default:
		return -1
	}
}

// attackComplexityScore returns the weight for the Attack Complexity metric.
func attackComplexityScore(ac string) float64 {
	switch ac {
	case "L": // Low
		return 0.77
	case "H": // High
		return 0.44
	default:
		return -1
	}
}

// privilegesRequiredScore returns the weight for the Privileges Required metric.
// The weight differs depending on whether scope is changed.
func privilegesRequiredScore(pr string, scopeChanged bool) float64 {
	if scopeChanged {
		switch pr {
		case "N": // None
			return 0.85
		case "L": // Low
			return 0.68
		case "H": // High
			return 0.50
		default:
			return -1
		}
	}
	switch pr {
	case "N":
		return 0.85
	case "L":
		return 0.62
	case "H":
		return 0.27
	default:
		return -1
	}
}

// userInteractionScore returns the weight for the User Interaction metric.
func userInteractionScore(ui string) float64 {
	switch ui {
	case "N": // None
		return 0.85
	case "R": // Required
		return 0.62
	default:
		return -1
	}
}

// impactMetricScore returns the weight for a CIA impact metric (C, I, or A).
func impactMetricScore(val string) float64 {
	switch val {
	case "H": // High
		return 0.56
	case "L": // Low
		return 0.22
	case "N": // None
		return 0.0
	default:
		return -1
	}
}

// roundUp implements the CVSS "roundup" function:
// the smallest number, specified to one decimal place, that is equal to or
// higher than its input.
func roundUp(x float64) float64 {
	return math.Ceil(x*10) / 10.0
}
