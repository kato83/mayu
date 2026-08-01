// Package cvss implements CVSS (Common Vulnerability Scoring System) base score
// calculation from vector strings.
//
// Supported formats:
//   - CVSS v2.0: "(AV:N/AC:L/Au:N/C:C/I:C/A:C)" or "AV:N/AC:L/Au:N/C:C/I:C/A:C"
//   - CVSS v3.0: "CVSS:3.0/..."
//   - CVSS v3.1: "CVSS:3.1/..."
//   - CVSS v4.0: "CVSS:4.0/..."
//
// This package uses github.com/pandatix/go-cvss for score computation.
package cvss

import (
	"strings"

	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
)

// BaseSeverity returns the qualitative severity label for a given CVSS base score.
// The vector parameter is used to determine the CVSS version for threshold selection.
// CVSS v2: HIGH >= 7.0, MEDIUM >= 4.0, LOW > 0.0
// CVSS v3.x/v4.0: CRITICAL >= 9.0, HIGH >= 7.0, MEDIUM >= 4.0, LOW >= 0.1, NONE = 0.0
func BaseSeverity(score float64, vector string) string {
	if isV2Vector(vector) {
		switch {
		case score >= 7.0:
			return "HIGH"
		case score >= 4.0:
			return "MEDIUM"
		case score > 0.0:
			return "LOW"
		default:
			return "NONE"
		}
	}

	// CVSS v3.0, v3.1, v4.0 (and default for empty/unknown vectors)
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score >= 0.1:
		return "LOW"
	default:
		return "NONE"
	}
}

// isV2Vector returns true if the vector string appears to be a CVSS v2 vector.
// CVSS v2 vectors have no "CVSS:" prefix and may optionally be wrapped in parentheses.
func isV2Vector(vector string) bool {
	v := strings.TrimSpace(vector)
	if v == "" {
		return false
	}
	// CVSS v3.x and v4.0 vectors start with "CVSS:"
	if strings.HasPrefix(v, "CVSS:") {
		return false
	}
	// v2 vectors start with "(" or directly with a metric like "AV:"
	return strings.HasPrefix(v, "(") || strings.Contains(v, "AV:")
}

// BaseScore calculates the CVSS base score from a vector string.
// Returns 0 and false if the vector cannot be parsed.
func BaseScore(vector string) (float64, bool) {
	vector = strings.TrimSpace(vector)
	if vector == "" {
		return 0, false
	}

	switch {
	case strings.HasPrefix(vector, "CVSS:4.0"):
		cvss, err := gocvss40.ParseVector(vector)
		if err != nil {
			return 0, false
		}
		return cvss.Score(), true

	case strings.HasPrefix(vector, "CVSS:3.1"):
		cvss, err := gocvss31.ParseVector(vector)
		if err != nil {
			return 0, false
		}
		return cvss.BaseScore(), true

	case strings.HasPrefix(vector, "CVSS:3.0"):
		cvss, err := gocvss30.ParseVector(vector)
		if err != nil {
			return 0, false
		}
		return cvss.BaseScore(), true

	default:
		// Try CVSS v2.0: strip surrounding parentheses if present
		v := vector
		if strings.HasPrefix(v, "(") && strings.HasSuffix(v, ")") {
			v = v[1 : len(v)-1]
		}
		cvss, err := gocvss20.ParseVector(v)
		if err != nil {
			return 0, false
		}
		return cvss.BaseScore(), true
	}
}

// ImpactLevel represents the impact metric value for C/I/A.
type ImpactLevel string

const (
	ImpactNone     ImpactLevel = "none"
	ImpactLow      ImpactLevel = "low"
	ImpactHigh     ImpactLevel = "high"
	ImpactPartial  ImpactLevel = "partial"  // CVSS v2
	ImpactComplete ImpactLevel = "complete" // CVSS v2
)

// CIAImpact holds the Confidentiality, Integrity, and Availability impact levels.
type CIAImpact struct {
	Confidentiality ImpactLevel
	Integrity       ImpactLevel
	Availability    ImpactLevel
}

// IsAllHigh returns true if all three impact metrics are at maximum severity.
// For CVSS v2 this means Complete; for v3.x/v4.0 this means High.
func (c *CIAImpact) IsAllHigh() bool {
	return isMaxImpact(c.Confidentiality) && isMaxImpact(c.Integrity) && isMaxImpact(c.Availability)
}

// isMaxImpact returns true if the impact level represents maximum severity.
func isMaxImpact(level ImpactLevel) bool {
	return level == ImpactHigh || level == ImpactComplete
}

// ParseCIAImpact extracts Confidentiality, Integrity, and Availability impact
// metrics from a CVSS vector string. Supports v2.0, v3.0, v3.1, and v4.0.
// Returns nil if the vector cannot be parsed.
func ParseCIAImpact(vector string) *CIAImpact {
	vector = strings.TrimSpace(vector)
	if vector == "" {
		return nil
	}

	switch {
	case strings.HasPrefix(vector, "CVSS:4.0"):
		return parseCIAv4(vector)
	case strings.HasPrefix(vector, "CVSS:3.1"), strings.HasPrefix(vector, "CVSS:3.0"):
		return parseCIAv3(vector)
	default:
		return parseCIAv2(vector)
	}
}

// parseCIAv3 extracts C/I/A from CVSS v3.0 or v3.1 vectors.
// Metrics: C:N|L|H, I:N|L|H, A:N|L|H
func parseCIAv3(vector string) *CIAImpact {
	metrics := parseMetrics(vector)
	c, cOk := metrics["C"]
	i, iOk := metrics["I"]
	a, aOk := metrics["A"]
	if !cOk || !iOk || !aOk {
		return nil
	}
	return &CIAImpact{
		Confidentiality: normalizeV3Impact(c),
		Integrity:       normalizeV3Impact(i),
		Availability:    normalizeV3Impact(a),
	}
}

// parseCIAv4 extracts VC/VI/VA (vulnerable system impact) from CVSS v4.0 vectors.
// Metrics: VC:N|L|H, VI:N|L|H, VA:N|L|H
func parseCIAv4(vector string) *CIAImpact {
	metrics := parseMetrics(vector)
	vc, vcOk := metrics["VC"]
	vi, viOk := metrics["VI"]
	va, vaOk := metrics["VA"]
	if !vcOk || !viOk || !vaOk {
		return nil
	}
	return &CIAImpact{
		Confidentiality: normalizeV3Impact(vc),
		Integrity:       normalizeV3Impact(vi),
		Availability:    normalizeV3Impact(va),
	}
}

// parseCIAv2 extracts C/I/A from CVSS v2.0 vectors.
// Metrics: C:N|P|C, I:N|P|C, A:N|P|C
func parseCIAv2(vector string) *CIAImpact {
	v := vector
	if strings.HasPrefix(v, "(") && strings.HasSuffix(v, ")") {
		v = v[1 : len(v)-1]
	}
	metrics := parseMetrics(v)
	c, cOk := metrics["C"]
	i, iOk := metrics["I"]
	a, aOk := metrics["A"]
	if !cOk || !iOk || !aOk {
		return nil
	}
	return &CIAImpact{
		Confidentiality: normalizeV2Impact(c),
		Integrity:       normalizeV2Impact(i),
		Availability:    normalizeV2Impact(a),
	}
}

// parseMetrics splits a CVSS vector into key:value pairs.
func parseMetrics(vector string) map[string]string {
	result := make(map[string]string)
	// Remove version prefix (e.g., "CVSS:3.1/")
	if idx := strings.Index(vector, "/"); idx >= 0 && strings.HasPrefix(vector, "CVSS:") {
		vector = vector[idx+1:]
	}
	parts := strings.Split(vector, "/")
	for _, part := range parts {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			result[kv[0]] = kv[1]
		}
	}
	return result
}

// normalizeV3Impact maps CVSS v3.x/v4.0 C/I/A values to ImpactLevel.
func normalizeV3Impact(val string) ImpactLevel {
	switch strings.ToUpper(val) {
	case "H":
		return ImpactHigh
	case "L":
		return ImpactLow
	case "N":
		return ImpactNone
	default:
		return ImpactNone
	}
}

// normalizeV2Impact maps CVSS v2.0 C/I/A values to ImpactLevel.
func normalizeV2Impact(val string) ImpactLevel {
	switch strings.ToUpper(val) {
	case "C":
		return ImpactComplete
	case "P":
		return ImpactPartial
	case "N":
		return ImpactNone
	default:
		return ImpactNone
	}
}
