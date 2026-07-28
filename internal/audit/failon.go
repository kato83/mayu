package audit

import (
	"fmt"
	"strings"
)

// ParseFailOn parses a comma-separated string of severity labels and returns
// the minimum severity level that should cause a failure. For example,
// "critical,high" returns 4 (HIGH), meaning findings at level 4 or above
// trigger failure. Returns an error if the spec is empty or contains invalid
// severity labels.
func ParseFailOn(spec string) (int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return 0, fmt.Errorf("--fail-on value must not be empty")
	}

	parts := strings.Split(spec, ",")
	minLevel := 6 // Start above max (5=CRITICAL)

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		level := SeverityFromLabel(part)
		if level == 0 {
			return 0, fmt.Errorf("invalid severity label: %q (valid: critical, high, medium, low, none)", part)
		}
		if level < minLevel {
			minLevel = level
		}
	}

	if minLevel > 5 {
		return 0, fmt.Errorf("--fail-on value must not be empty")
	}

	return minLevel, nil
}

// ShouldFail reports whether any finding in the slice has a SeverityLevel at
// or above the given minimum level. Returns false for empty findings.
func ShouldFail(findings []Finding, minLevel int) bool {
	for _, f := range findings {
		if f.SeverityLevel >= minLevel {
			return true
		}
	}
	return false
}
