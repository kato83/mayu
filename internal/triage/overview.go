package triage

import "sort"

// CrossProjectTriageResult represents the aggregated triage view for a single
// vulnerability across all affected projects/servers.
type CrossProjectTriageResult struct {
	VulnerabilityID   string              `json:"vulnerability_id"`
	OrgPriorityLevel  PriorityLevel       `json:"org_priority_level"`
	MaxCompositeScore float64             `json:"max_composite_score"`
	AffectedServers   int                 `json:"affected_servers"`
	AffectedProjects  int                 `json:"affected_projects"`
	ServerBreakdown   []ServerTriageEntry `json:"server_breakdown"`
}

// ServerTriageEntry contains triage results for a specific server/project combination.
type ServerTriageEntry struct {
	ProjectID    int64         `json:"project_id"`
	ProjectName  string        `json:"project_name"`
	ServerLabel  string        `json:"server_label"`
	Environment  string        `json:"environment"`
	ProfileUsed  string        `json:"profile_used"`
	TriageResult *TriageResult `json:"triage_result"`
}

// OverviewSummary holds aggregated counts by priority level.
type OverviewSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// AggregateCrossProject computes the cross-project aggregation for a single
// vulnerability from multiple server triage entries.
// It uses the max priority and max score across all servers.
func AggregateCrossProject(vulnID string, entries []ServerTriageEntry) *CrossProjectTriageResult {
	if len(entries) == 0 {
		return nil
	}

	result := &CrossProjectTriageResult{
		VulnerabilityID:  vulnID,
		OrgPriorityLevel: PriorityLow,
		ServerBreakdown:  entries,
		AffectedServers:  len(entries),
	}

	// Track unique projects
	projectSet := make(map[int64]struct{})

	for _, entry := range entries {
		projectSet[entry.ProjectID] = struct{}{}

		if entry.TriageResult == nil {
			continue
		}

		// Max composite score
		if entry.TriageResult.CompositeScore > result.MaxCompositeScore {
			result.MaxCompositeScore = entry.TriageResult.CompositeScore
		}

		// Max priority level
		if PriorityRank(entry.TriageResult.PriorityLevel) > PriorityRank(result.OrgPriorityLevel) {
			result.OrgPriorityLevel = entry.TriageResult.PriorityLevel
		}
	}

	result.AffectedProjects = len(projectSet)
	return result
}

// AggregateCrossProjectBatch aggregates multiple vulnerabilities' server entries
// into cross-project results, sorted by priority then by affected server count.
func AggregateCrossProjectBatch(entriesByVuln map[string][]ServerTriageEntry) []*CrossProjectTriageResult {
	var results []*CrossProjectTriageResult

	for vulnID, entries := range entriesByVuln {
		r := AggregateCrossProject(vulnID, entries)
		if r != nil {
			results = append(results, r)
		}
	}

	// Sort by priority (Critical first), then affected_servers desc, then score desc
	sort.Slice(results, func(i, j int) bool {
		ri := PriorityRank(results[i].OrgPriorityLevel)
		rj := PriorityRank(results[j].OrgPriorityLevel)
		if ri != rj {
			return ri > rj
		}
		if results[i].AffectedServers != results[j].AffectedServers {
			return results[i].AffectedServers > results[j].AffectedServers
		}
		return results[i].MaxCompositeScore > results[j].MaxCompositeScore
	})

	return results
}

// ComputeOverviewSummary computes priority-level summary counts from cross-project results.
func ComputeOverviewSummary(results []*CrossProjectTriageResult) *OverviewSummary {
	s := &OverviewSummary{Total: len(results)}
	for _, r := range results {
		switch r.OrgPriorityLevel {
		case PriorityCritical:
			s.Critical++
		case PriorityHigh:
			s.High++
		case PriorityMedium:
			s.Medium++
		case PriorityLow:
			s.Low++
		}
	}
	return s
}
