// Package model defines Go structs for the vulnerability_summary table.
// This table stores pre-computed derived data for list views and filtering.
// It is updated synchronously at the end of each import pipeline.
package model

import (
	"encoding/json"
	"math"
	"strings"
	"time"
)

// VulnerabilitySummary represents a row in the vulnerability_summary table.
// It aggregates scoring, ecosystem, and CWE information from all sources.
type VulnerabilitySummary struct {
	VulnerabilityID string

	// SeverityWorst is the highest normalized severity level across all sources.
	// Scale: 5=CRITICAL, 4=HIGH, 3=MEDIUM, 2=LOW, 1=NONE, 0=UNKNOWN
	SeverityWorst int

	// SeverityBest is the lowest normalized severity level across all sources.
	SeverityBest int

	// ScoresDetail is a JSONB array of per-source score entries.
	ScoresDetail json.RawMessage

	// EPSSScore is the latest EPSS probability (0.0-1.0).
	EPSSScore *float64

	// EPSSPercentile is the latest EPSS percentile (0.0-1.0).
	EPSSPercentile *float64

	// InKEV indicates whether the vulnerability is in the CISA KEV catalog.
	InKEV bool

	// LEVScore is the computed LEV probability (0.0-1.0).
	LEVScore *float64

	// EcosystemList contains all ecosystems from all sources (deduplicated).
	EcosystemList []string

	// CWEList contains all CWE IDs from all sources (deduplicated).
	CWEList []string

	// ComputedAt is when this summary was last computed.
	ComputedAt time.Time
}

// ScoreEntry represents a single score entry in the scores_detail JSONB array.
type ScoreEntry struct {
	// Src identifies the source (e.g., "nvd", "mitre_cna", "mitre_adp", "osv", "osv_ghsa").
	Src string `json:"src"`

	// System identifies the scoring system (e.g., "cvss", "nistir7864", "ssvc").
	System string `json:"system"`

	// Ver is the scoring system version (e.g., "v31", "v40", "v2").
	Ver string `json:"ver,omitempty"`

	// Vector is the raw CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/...").
	// Preserved separately from the computed Score for traceability.
	Vector string `json:"vector,omitempty"`

	// Score is the raw numeric score (nil if only severity label is available).
	// When the source provides a vector string, this is computed from the vector.
	Score *float64 `json:"score"`

	// Sev is the severity label (e.g., "CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE").
	Sev string `json:"sev"`

	// Normalized is the 5-level normalized value.
	Normalized int `json:"normalized"`
}

// SeverityLevel constants for the 5-level normalized severity scale.
const (
	SeverityUnknown  = 0
	SeverityNone     = 1
	SeverityLow      = 2
	SeverityMedium   = 3
	SeverityHigh     = 4
	SeverityCritical = 5
)

// SeverityLevelName returns the human-readable name for a severity level.
func SeverityLevelName(level int) string {
	switch level {
	case SeverityCritical:
		return "CRITICAL"
	case SeverityHigh:
		return "HIGH"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityLow:
		return "LOW"
	case SeverityNone:
		return "NONE"
	default:
		return "UNKNOWN"
	}
}

// NormalizeSeverity converts any scoring system's score/label to the 5-level scale.
// Parameters:
//   - system: scoring system identifier ("cvss", "nistir7864", "ssvc", or empty for label-only)
//   - score: numeric score (nil if label-only)
//   - sevLabel: severity label string
//
// Returns a value from 0 (UNKNOWN) to 5 (CRITICAL).
func NormalizeSeverity(system string, score *float64, sevLabel string) int {
	switch strings.ToLower(system) {
	case "cvss":
		if score != nil {
			return normalizeCVSSScore(*score)
		}
		return normalizeSeverityLabel(sevLabel)

	case "nistir7864":
		// Drupal's 25-point scale based on NISTIR 7864
		if score != nil {
			switch {
			case *score >= 20:
				return SeverityCritical
			case *score >= 15:
				return SeverityHigh
			case *score >= 10:
				return SeverityMedium
			case *score >= 5:
				return SeverityLow
			default:
				return SeverityNone
			}
		}
		return normalizeSeverityLabel(sevLabel)

	case "ssvc":
		switch strings.ToLower(sevLabel) {
		case "act":
			return SeverityCritical
		case "attend":
			return SeverityHigh
		case "track*":
			return SeverityMedium
		case "track":
			return SeverityLow
		default:
			return SeverityUnknown
		}

	default:
		// Label-only or unknown system
		if score != nil {
			// Assume CVSS-like 0-10 scale if no system is specified
			return normalizeCVSSScore(*score)
		}
		return normalizeSeverityLabel(sevLabel)
	}
}

// normalizeCVSSScore converts a CVSS base score (0.0-10.0) to the 5-level scale.
func normalizeCVSSScore(score float64) int {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0.0:
		return SeverityLow
	default:
		return SeverityNone
	}
}

// normalizeSeverityLabel converts a severity label string to the 5-level scale.
func normalizeSeverityLabel(label string) int {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "critical", "highly critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium", "moderate", "moderately critical":
		return SeverityMedium
	case "low", "less critical":
		return SeverityLow
	case "none", "not critical", "informational":
		return SeverityNone
	default:
		return SeverityUnknown
	}
}

// ComputeSummaryFromScores computes severity_worst and severity_best from a list of ScoreEntry.
func ComputeSummaryFromScores(entries []ScoreEntry) (worst int, best int) {
	if len(entries) == 0 {
		return SeverityUnknown, SeverityUnknown
	}

	worst = 0
	best = math.MaxInt32

	for _, e := range entries {
		if e.Normalized == SeverityUnknown {
			continue
		}
		if e.Normalized > worst {
			worst = e.Normalized
		}
		if e.Normalized < best {
			best = e.Normalized
		}
	}

	if best == math.MaxInt32 {
		best = SeverityUnknown
	}

	return worst, best
}
