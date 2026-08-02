package triage

import (
	"context"
	"sort"
	"time"
)

// Engine is the main triage computation engine.
type Engine struct {
	profile *Profile
	scorer  *Scorer
}

// NewEngine creates a new triage engine with the given profile.
// If profile is nil, the default profile is used.
func NewEngine(profile *Profile) *Engine {
	if profile == nil {
		profile = DefaultProfile()
	}
	return &Engine{
		profile: profile,
		scorer:  NewScorer(profile.Weights),
	}
}

// Triage computes the triage result for a single vulnerability.
func (e *Engine) Triage(ctx context.Context, input *TriageInput) (*TriageResult, error) {
	// Step 1: Compute composite score
	compositeScore, contributions := e.scorer.ComputeScore(input)

	// Step 2: Evaluate SSVC
	ssvcDecision, ssvcMethod := EvaluateSSVC(input)

	// Step 3: Resolve priority (max of score-based and SSVC-based)
	priorityLevel := ResolvePriority(compositeScore, ssvcDecision, e.profile.Thresholds)

	// Determine resolution method
	scorePriority := PriorityFromScore(compositeScore, e.profile.Thresholds)
	ssvcPriority := PriorityFromSSVC(ssvcDecision)
	resolutionMethod := determineResolutionMethod(scorePriority, ssvcPriority, priorityLevel)

	// Step 4: Build rationale
	rationale := BuildRationale(contributions, string(ssvcDecision), ssvcMethod, priorityLevel, resolutionMethod)

	// Build signal values map
	signalValues := buildSignalValues(input)

	return &TriageResult{
		VulnerabilityID: input.VulnerabilityID,
		PriorityLevel:   priorityLevel,
		CompositeScore:  compositeScore,
		SSVCDecision:    string(ssvcDecision),
		Rationale:       rationale,
		SignalValues:    signalValues,
		ProfileUsed:     e.profile.Name,
		ComputedAt:      time.Now(),
	}, nil
}

// TriageBatch computes triage results for multiple vulnerabilities.
// Results are returned sorted by priority (Critical first) then by composite score descending.
func (e *Engine) TriageBatch(ctx context.Context, inputs []*TriageInput) ([]*TriageResult, error) {
	results := make([]*TriageResult, 0, len(inputs))

	for _, input := range inputs {
		result, err := e.Triage(ctx, input)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}

	// Sort by priority (Critical first), then by composite score descending
	sort.Slice(results, func(i, j int) bool {
		ri := PriorityRank(results[i].PriorityLevel)
		rj := PriorityRank(results[j].PriorityLevel)
		if ri != rj {
			return ri > rj
		}
		return results[i].CompositeScore > results[j].CompositeScore
	})

	return results, nil
}

// Profile returns the engine's active profile.
func (e *Engine) Profile() *Profile {
	return e.profile
}

// determineResolutionMethod determines how the final priority was resolved.
func determineResolutionMethod(scorePriority, ssvcPriority, finalPriority PriorityLevel) string {
	scoreRank := PriorityRank(scorePriority)
	ssvcRank := PriorityRank(ssvcPriority)

	switch {
	case scoreRank == ssvcRank:
		return "combined_max"
	case scoreRank > ssvcRank:
		return "score_based"
	default:
		return "ssvc_override"
	}
}

// buildSignalValues constructs a map of signal name to raw value for the result.
func buildSignalValues(input *TriageInput) map[string]float64 {
	values := make(map[string]float64)

	if input.CVSSScore != nil {
		values["cvss"] = *input.CVSSScore
	}
	if input.EPSSScore != nil {
		values["epss"] = *input.EPSSScore
	}
	if input.LEVScore != nil {
		values["lev"] = *input.LEVScore
	}
	if input.InKEV {
		values["kev"] = 1.0
	} else {
		values["kev"] = 0.0
	}
	if input.PatchAvailable {
		values["patch"] = 1.0
	} else {
		values["patch"] = 0.0
	}
	if input.PublishedAt != nil {
		values["age_days"] = time.Since(*input.PublishedAt).Hours() / 24
	}
	if input.HasExploit {
		values["exploitdb"] = 1.0
	} else {
		values["exploitdb"] = 0.0
	}
	if input.ExploitabilityScore != nil {
		values["exploitability"] = *input.ExploitabilityScore
	}

	return values
}
