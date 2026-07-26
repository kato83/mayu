// Package ssvc implements the CISA Coordinator SSVC Decision Tree v2.0.3.
// It evaluates three decision points (Exploitation, Automatable, Technical Impact)
// and determines the recommended action (Track, Track*, Attend, Act).
//
// Reference: https://certcc.github.io/SSVC/
// Decision table: https://github.com/CERTCC/SSVC/blob/main/data/csv/cisa/cisa_coordinator_2_0_3.csv
package ssvc

import "strings"

// Decision represents the SSVC recommended action.
type Decision string

const (
	DecisionTrack     Decision = "Track"
	DecisionTrackStar Decision = "Track*"
	DecisionAttend    Decision = "Attend"
	DecisionAct       Decision = "Act"
)

// Exploitation represents the exploitation status decision point.
type Exploitation string

const (
	ExploitationNone   Exploitation = "none"
	ExploitationPOC    Exploitation = "poc"
	ExploitationActive Exploitation = "active"
)

// Automatable represents the automatable (virulence) decision point.
type Automatable string

const (
	AutomatableNo  Automatable = "no"
	AutomatableYes Automatable = "yes"
)

// TechnicalImpact represents the technical impact decision point.
type TechnicalImpact string

const (
	TechnicalImpactPartial TechnicalImpact = "partial"
	TechnicalImpactTotal   TechnicalImpact = "total"
)

// decisionTable encodes the CISA Coordinator v2.0.3 decision tree.
// The key is [exploitation][automatable][technicalImpact] and the value
// is the worst-case decision (assuming high Mission & Well-Being impact).
// This is appropriate because the SSVC data from MITRE/NVD only contains
// the three decision points (Exploitation, Automatable, Technical Impact)
// without Mission & Well-Being Impact.
//
// From the CSV, for each (Exploitation, Automatable, TechnicalImpact) combination,
// we take the maximum severity outcome across all Mission & Well-Being values
// (low, medium, high) to get the worst-case decision.
var decisionTable = map[Exploitation]map[Automatable]map[TechnicalImpact]Decision{
	ExploitationNone: {
		AutomatableNo: {
			TechnicalImpactPartial: DecisionTrack,     // rows 0-2: track, track, track → max: track
			TechnicalImpactTotal:   DecisionTrackStar, // rows 3-5: track, track, track* → max: track*
		},
		AutomatableYes: {
			TechnicalImpactPartial: DecisionAttend, // rows 6-8: track, track, attend → max: attend
			TechnicalImpactTotal:   DecisionAttend, // rows 9-11: track, track, attend → max: attend
		},
	},
	ExploitationPOC: {
		AutomatableNo: {
			TechnicalImpactPartial: DecisionTrackStar, // rows 12-14: track, track, track* → max: track*
			TechnicalImpactTotal:   DecisionAttend,    // rows 15-17: track, track*, attend → max: attend
		},
		AutomatableYes: {
			TechnicalImpactPartial: DecisionAttend, // rows 18-20: track, track, attend → max: attend
			TechnicalImpactTotal:   DecisionAttend, // rows 21-23: track, track*, attend → max: attend
		},
	},
	ExploitationActive: {
		AutomatableNo: {
			TechnicalImpactPartial: DecisionAttend, // rows 24-26: track, track, attend → max: attend
			TechnicalImpactTotal:   DecisionAct,    // rows 27-29: track, attend, act → max: act
		},
		AutomatableYes: {
			TechnicalImpactPartial: DecisionAct, // rows 30-32: attend, attend, act → max: act
			TechnicalImpactTotal:   DecisionAct, // rows 33-35: attend, act, act → max: act
		},
	},
}

// Evaluate determines the SSVC decision (worst-case) from the three decision points.
// Returns empty string if any input is not recognized.
func Evaluate(exploitation Exploitation, automatable Automatable, technicalImpact TechnicalImpact) Decision {
	a, ok := decisionTable[exploitation]
	if !ok {
		return ""
	}
	b, ok := a[automatable]
	if !ok {
		return ""
	}
	d, ok := b[technicalImpact]
	if !ok {
		return ""
	}
	return d
}

// EvaluateFromOptions determines the SSVC decision from a list of key-value options
// as stored in MITRE/NVD SSVC data. Keys are case-insensitive.
// Returns the decision and true if all three required options were found, or empty and false otherwise.
func EvaluateFromOptions(options map[string]string) (Decision, bool) {
	var exploitation Exploitation
	var automatable Automatable
	var technicalImpact TechnicalImpact
	var hasExpl, hasAuto, hasTech bool

	for k, v := range options {
		lower := strings.ToLower(v)
		switch strings.ToLower(k) {
		case "exploitation":
			exploitation = normalizeExploitation(lower)
			hasExpl = exploitation != ""
		case "automatable":
			automatable = normalizeAutomatable(lower)
			hasAuto = automatable != ""
		case "technical impact", "technicalimpact":
			technicalImpact = normalizeTechnicalImpact(lower)
			hasTech = technicalImpact != ""
		}
	}

	if !hasExpl || !hasAuto || !hasTech {
		return "", false
	}

	d := Evaluate(exploitation, automatable, technicalImpact)
	if d == "" {
		return "", false
	}
	return d, true
}

func normalizeExploitation(s string) Exploitation {
	switch s {
	case "none":
		return ExploitationNone
	case "poc", "public poc":
		return ExploitationPOC
	case "active":
		return ExploitationActive
	default:
		return ""
	}
}

func normalizeAutomatable(s string) Automatable {
	switch s {
	case "no":
		return AutomatableNo
	case "yes":
		return AutomatableYes
	default:
		return ""
	}
}

func normalizeTechnicalImpact(s string) TechnicalImpact {
	switch s {
	case "partial":
		return TechnicalImpactPartial
	case "total":
		return TechnicalImpactTotal
	default:
		return ""
	}
}
