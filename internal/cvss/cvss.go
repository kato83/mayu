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
