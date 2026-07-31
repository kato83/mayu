package watchlist

import (
	"context"
	"fmt"
	"strings"

	"github.com/kato83/mayu/internal/triage"
)

// TriagePriorityMin defines the minimum priority level for notification filtering.
// When set, only matches with triage priority at or above this level will trigger notifications.
type TriagePriorityMin struct {
	Level triage.PriorityLevel
}

// ParseTriagePriorityMin parses a string like "critical", "high", "medium", "low"
// into a TriagePriorityMin filter.
func ParseTriagePriorityMin(s string) (*TriagePriorityMin, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return &TriagePriorityMin{Level: triage.PriorityCritical}, nil
	case "high":
		return &TriagePriorityMin{Level: triage.PriorityHigh}, nil
	case "medium":
		return &TriagePriorityMin{Level: triage.PriorityMedium}, nil
	case "low":
		return &TriagePriorityMin{Level: triage.PriorityLow}, nil
	default:
		return nil, fmt.Errorf("invalid triage priority level %q: must be one of critical, high, medium, low", s)
	}
}

// ShouldNotify returns true if the given priority level meets or exceeds the minimum.
func (t *TriagePriorityMin) ShouldNotify(level triage.PriorityLevel) bool {
	if t == nil {
		return true // no filter = always notify
	}
	return triage.PriorityRank(level) >= triage.PriorityRank(t.Level)
}

// TriageNotificationPayload extends the watchlist match notification with triage information.
// This is added to the notification context when triage results are available.
type TriageNotificationPayload struct {
	// VulnerabilityID is the CVE/vulnerability identifier.
	VulnerabilityID string `json:"vulnerability_id"`

	// TriagePriorityLevel is the computed triage priority (Critical/High/Medium/Low).
	TriagePriorityLevel string `json:"triage_priority_level"`

	// CompositeScore is the weighted composite risk score (0.0-1.0).
	CompositeScore float64 `json:"composite_score"`

	// SSVCDecision is the SSVC decision tree outcome (Act/Attend/Track*/Track).
	SSVCDecision string `json:"ssvc_decision,omitempty"`
}

// TriageWebhookEvent extends webhook template variables with triage information.
// These fields are available for mustache template expansion in webhook body_template.
type TriageWebhookEvent struct {
	// Standard webhook fields
	Event    string  `json:"event"`
	ID       string  `json:"id"`
	Severity string  `json:"severity"`
	EPSS     float64 `json:"epss"`
	LEV      float64 `json:"lev"`
	Summary  string  `json:"summary"`

	// Triage-specific fields available as {{TriagePriority}}, {{CompositeScore}}, {{SSVCDecision}}
	TriagePriority string  `json:"triage_priority"`
	CompositeScore float64 `json:"composite_score"`
	SSVCDecision   string  `json:"ssvc_decision"`
}

// TriageProvider provides triage results for vulnerabilities.
// This decouples the watchlist notification system from the full triage engine.
type TriageProvider interface {
	// GetTriageResult returns the triage result for a vulnerability.
	// Returns nil, nil if triage has not been computed for this vulnerability.
	GetTriageResult(ctx context.Context, vulnID string) (*triage.TriageResult, error)
}

// TriageAwareMatcher wraps a Matcher with triage-enriched notification support.
type TriageAwareMatcher struct {
	matcher        *Matcher
	triageProvider TriageProvider
	priorityMin    *TriagePriorityMin
}

// NewTriageAwareMatcher creates a matcher that enriches notifications with triage data.
// If triageProvider is nil, triage enrichment is skipped.
// If priorityMin is nil, no priority filtering is applied.
func NewTriageAwareMatcher(matcher *Matcher, triageProvider TriageProvider, priorityMin *TriagePriorityMin) *TriageAwareMatcher {
	return &TriageAwareMatcher{
		matcher:        matcher,
		triageProvider: triageProvider,
		priorityMin:    priorityMin,
	}
}

// MatchNewVulnerabilities checks new vulnerabilities against watchlists,
// enriches matches with triage data, and filters by priority minimum.
func (m *TriageAwareMatcher) MatchNewVulnerabilities(ctx context.Context, vulnIDs []string) ([]WatchlistMatch, error) {
	matches, err := m.matcher.MatchNewVulnerabilities(ctx, vulnIDs)
	if err != nil {
		return nil, err
	}

	if len(matches) == 0 || m.triageProvider == nil {
		return matches, nil
	}

	// Filter by triage priority if configured
	if m.priorityMin == nil {
		return matches, nil
	}

	filtered := make([]WatchlistMatch, 0, len(matches))
	for _, match := range matches {
		result, err := m.triageProvider.GetTriageResult(ctx, match.VulnerabilityID)
		if err != nil {
			// On error, include the match (fail open)
			filtered = append(filtered, match)
			continue
		}
		if result == nil {
			// No triage result available, include the match
			filtered = append(filtered, match)
			continue
		}
		if m.priorityMin.ShouldNotify(result.PriorityLevel) {
			filtered = append(filtered, match)
		}
	}

	return filtered, nil
}

// EnrichMatchWithTriage creates a TriageNotificationPayload for a vulnerability match.
// Returns nil if triage data is not available.
func (m *TriageAwareMatcher) EnrichMatchWithTriage(ctx context.Context, vulnID string) *TriageNotificationPayload {
	if m.triageProvider == nil {
		return nil
	}

	result, err := m.triageProvider.GetTriageResult(ctx, vulnID)
	if err != nil || result == nil {
		return nil
	}

	return &TriageNotificationPayload{
		VulnerabilityID:     vulnID,
		TriagePriorityLevel: string(result.PriorityLevel),
		CompositeScore:      result.CompositeScore,
		SSVCDecision:        result.SSVCDecision,
	}
}

// BuildTriageWebhookEvent creates a webhook event enriched with triage data.
// This enables {{TriagePriority}}, {{CompositeScore}}, {{SSVCDecision}} template variables.
func BuildTriageWebhookEvent(event, id, severity string, epss, lev float64, summary string, triagePayload *TriageNotificationPayload) *TriageWebhookEvent {
	evt := &TriageWebhookEvent{
		Event:    event,
		ID:       id,
		Severity: severity,
		EPSS:     epss,
		LEV:      lev,
		Summary:  summary,
	}

	if triagePayload != nil {
		evt.TriagePriority = triagePayload.TriagePriorityLevel
		evt.CompositeScore = triagePayload.CompositeScore
		evt.SSVCDecision = triagePayload.SSVCDecision
	}

	return evt
}
