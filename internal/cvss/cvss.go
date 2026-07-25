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
