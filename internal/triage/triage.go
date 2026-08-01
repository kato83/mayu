// Package triage provides the vulnerability triage engine that integrates
// multiple risk signals into a prioritized assessment.
//
// The triage engine computes a composite score from 8 risk signals (CVSS, EPSS,
// LEV, KEV, Patch availability, Age, ExploitDB, Reachability), determines a
// priority level using both score thresholds and SSVC decision tree outcomes,
// and produces a human-readable rationale for each decision.
package triage

import "time"

// PriorityLevel represents the triage priority classification.
type PriorityLevel string

const (
	PriorityCritical PriorityLevel = "Critical"
	PriorityHigh     PriorityLevel = "High"
	PriorityMedium   PriorityLevel = "Medium"
	PriorityLow      PriorityLevel = "Low"
)

// PriorityRank returns a numeric rank for a priority level (higher = more urgent).
func PriorityRank(p PriorityLevel) int {
	switch p {
	case PriorityCritical:
		return 4
	case PriorityHigh:
		return 3
	case PriorityMedium:
		return 2
	case PriorityLow:
		return 1
	default:
		return 0
	}
}

// TriageInput contains all risk signals needed for triage computation.
type TriageInput struct {
	// VulnerabilityID is the CVE or vulnerability identifier.
	VulnerabilityID string

	// CVSSScore is the base CVSS score (0.0-10.0). nil if unavailable.
	CVSSScore *float64

	// CVSSVector is the full CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/...").
	// Used for precise Technical Impact determination in SSVC estimation.
	// nil/empty if unavailable.
	CVSSVector string

	// EPSSScore is the EPSS exploitation probability (0.0-1.0). nil if unavailable.
	EPSSScore *float64

	// LEVScore is the LEV probability (0.0-1.0). nil if unavailable.
	LEVScore *float64

	// InKEV indicates whether the vulnerability is in the CISA KEV catalog.
	InKEV bool

	// PatchAvailable indicates whether a patch/fix is known to exist.
	PatchAvailable bool

	// PublishedAt is when the vulnerability was first published.
	PublishedAt *time.Time

	// HasExploit indicates whether a public exploit exists in Exploit-DB.
	HasExploit bool

	// IsReachable indicates whether reachability analysis confirms
	// the vulnerable code is reachable. nil if analysis not performed.
	IsReachable *bool

	// SSVCOptions contains SSVC decision points (Exploitation, Automatable, TechnicalImpact).
	// nil if SSVC data is not available.
	SSVCOptions map[string]string
}

// TriageResult is the complete triage assessment for a single vulnerability.
type TriageResult struct {
	VulnerabilityID string             `json:"vulnerability_id"`
	PriorityLevel   PriorityLevel      `json:"priority_level"`
	CompositeScore  float64            `json:"composite_score"`
	SSVCDecision    string             `json:"ssvc_decision,omitempty"`
	Rationale       *Rationale         `json:"rationale"`
	SignalValues    map[string]float64 `json:"signal_values"`
	ProfileUsed     string             `json:"profile_used"`
	ComputedAt      time.Time          `json:"computed_at"`
}

// SignalContribution represents a single signal's contribution to the composite score.
type SignalContribution struct {
	Signal          string  `json:"signal"`
	RawValue        float64 `json:"raw_value"`
	Weight          float64 `json:"weight"`
	EffectiveWeight float64 `json:"effective_weight"`
	Contribution    float64 `json:"contribution"`
	Available       bool    `json:"available"`
}

// NewTriageInputFromDetail constructs a TriageInput from a VulnerabilityDetail.
func NewTriageInputFromDetail(id string, cvss *float64, cvssVector string, epss *float64, lev *float64, inKEV bool, patchAvailable bool, publishedAt *time.Time, hasExploit bool, isReachable *bool, ssvcOptions map[string]string) *TriageInput {
	return &TriageInput{
		VulnerabilityID: id,
		CVSSScore:       cvss,
		CVSSVector:      cvssVector,
		EPSSScore:       epss,
		LEVScore:        lev,
		InKEV:           inKEV,
		PatchAvailable:  patchAvailable,
		PublishedAt:     publishedAt,
		HasExploit:      hasExploit,
		IsReachable:     isReachable,
		SSVCOptions:     ssvcOptions,
	}
}
