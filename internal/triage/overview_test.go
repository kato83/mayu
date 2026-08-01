package triage

import "testing"

func TestAggregateCrossProject_UniqueServers(t *testing.T) {
	tests := []struct {
		name         string
		vulnID       string
		entries      []ServerTriageEntry
		wantServers  int
		wantProjects int
		wantPriority PriorityLevel
		wantMaxScore float64
		wantNil      bool
	}{
		{
			name:    "nil for empty entries",
			vulnID:  "CVE-2024-0001",
			entries: nil,
			wantNil: true,
		},
		{
			name:   "single entry",
			vulnID: "CVE-2024-0001",
			entries: []ServerTriageEntry{
				{
					ProjectID:   1,
					ProjectName: "service-a",
					ServerLabel: "production",
					TriageResult: &TriageResult{
						VulnerabilityID: "CVE-2024-0001",
						PriorityLevel:   PriorityHigh,
						CompositeScore:  0.75,
					},
				},
			},
			wantServers:  1,
			wantProjects: 1,
			wantPriority: PriorityHigh,
			wantMaxScore: 0.75,
		},
		{
			name:   "different projects different labels",
			vulnID: "CVE-2024-0002",
			entries: []ServerTriageEntry{
				{
					ProjectID:   1,
					ProjectName: "service-a",
					ServerLabel: "production",
					TriageResult: &TriageResult{
						VulnerabilityID: "CVE-2024-0002",
						PriorityLevel:   PriorityCritical,
						CompositeScore:  0.92,
					},
				},
				{
					ProjectID:   2,
					ProjectName: "service-b",
					ServerLabel: "staging",
					TriageResult: &TriageResult{
						VulnerabilityID: "CVE-2024-0002",
						PriorityLevel:   PriorityMedium,
						CompositeScore:  0.55,
					},
				},
			},
			wantServers:  2,
			wantProjects: 2,
			wantPriority: PriorityCritical,
			wantMaxScore: 0.92,
		},
		{
			name:   "duplicate project and server label deduplicates",
			vulnID: "CVE-2024-0003",
			entries: []ServerTriageEntry{
				{
					ProjectID:   1,
					ProjectName: "service-a",
					ServerLabel: "production",
					TriageResult: &TriageResult{
						VulnerabilityID: "CVE-2024-0003",
						PriorityLevel:   PriorityHigh,
						CompositeScore:  0.80,
					},
				},
				{
					ProjectID:   1,
					ProjectName: "service-a",
					ServerLabel: "production",
					TriageResult: &TriageResult{
						VulnerabilityID: "CVE-2024-0003",
						PriorityLevel:   PriorityMedium,
						CompositeScore:  0.50,
					},
				},
			},
			wantServers:  1,
			wantProjects: 1,
			wantPriority: PriorityHigh,
			wantMaxScore: 0.80,
		},
		{
			name:   "same project different server labels counts separately",
			vulnID: "CVE-2024-0004",
			entries: []ServerTriageEntry{
				{
					ProjectID:   1,
					ProjectName: "service-a",
					ServerLabel: "production",
					TriageResult: &TriageResult{
						VulnerabilityID: "CVE-2024-0004",
						PriorityLevel:   PriorityHigh,
						CompositeScore:  0.80,
					},
				},
				{
					ProjectID:   1,
					ProjectName: "service-a",
					ServerLabel: "staging",
					TriageResult: &TriageResult{
						VulnerabilityID: "CVE-2024-0004",
						PriorityLevel:   PriorityLow,
						CompositeScore:  0.30,
					},
				},
			},
			wantServers:  2,
			wantProjects: 1,
			wantPriority: PriorityHigh,
			wantMaxScore: 0.80,
		},
		{
			name:   "entry with nil TriageResult still counts as server",
			vulnID: "CVE-2024-0005",
			entries: []ServerTriageEntry{
				{
					ProjectID:    1,
					ProjectName:  "service-a",
					ServerLabel:  "production",
					TriageResult: nil,
				},
				{
					ProjectID:   2,
					ProjectName: "service-b",
					ServerLabel: "production",
					TriageResult: &TriageResult{
						VulnerabilityID: "CVE-2024-0005",
						PriorityLevel:   PriorityMedium,
						CompositeScore:  0.60,
					},
				},
			},
			wantServers:  2,
			wantProjects: 2,
			wantPriority: PriorityMedium,
			wantMaxScore: 0.60,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AggregateCrossProject(tt.vulnID, tt.entries)

			if tt.wantNil {
				if result != nil {
					t.Fatal("expected nil result")
				}
				return
			}

			if result == nil {
				t.Fatal("expected non-nil result")
			}

			if result.AffectedServers != tt.wantServers {
				t.Errorf("AffectedServers: got %d, want %d", result.AffectedServers, tt.wantServers)
			}
			if result.AffectedProjects != tt.wantProjects {
				t.Errorf("AffectedProjects: got %d, want %d", result.AffectedProjects, tt.wantProjects)
			}
			if result.OrgPriorityLevel != tt.wantPriority {
				t.Errorf("OrgPriorityLevel: got %s, want %s", result.OrgPriorityLevel, tt.wantPriority)
			}
			if result.MaxCompositeScore != tt.wantMaxScore {
				t.Errorf("MaxCompositeScore: got %f, want %f", result.MaxCompositeScore, tt.wantMaxScore)
			}
		})
	}
}

func TestAggregateCrossProjectBatch_DeduplicatesServers(t *testing.T) {
	entriesByVuln := map[string][]ServerTriageEntry{
		"CVE-2024-0001": {
			{
				ProjectID:   1,
				ProjectName: "service-a",
				ServerLabel: "production",
				TriageResult: &TriageResult{
					VulnerabilityID: "CVE-2024-0001",
					PriorityLevel:   PriorityCritical,
					CompositeScore:  0.95,
				},
			},
			// Duplicate server entry (same project + label)
			{
				ProjectID:   1,
				ProjectName: "service-a",
				ServerLabel: "production",
				TriageResult: &TriageResult{
					VulnerabilityID: "CVE-2024-0001",
					PriorityLevel:   PriorityHigh,
					CompositeScore:  0.70,
				},
			},
			{
				ProjectID:   2,
				ProjectName: "service-b",
				ServerLabel: "staging",
				TriageResult: &TriageResult{
					VulnerabilityID: "CVE-2024-0001",
					PriorityLevel:   PriorityMedium,
					CompositeScore:  0.50,
				},
			},
		},
		"CVE-2024-0002": {
			{
				ProjectID:   1,
				ProjectName: "service-a",
				ServerLabel: "production",
				TriageResult: &TriageResult{
					VulnerabilityID: "CVE-2024-0002",
					PriorityLevel:   PriorityLow,
					CompositeScore:  0.20,
				},
			},
		},
	}

	results := AggregateCrossProjectBatch(entriesByVuln)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	// Find CVE-2024-0001 result (should be first due to higher priority)
	var cve0001 *CrossProjectTriageResult
	for _, r := range results {
		if r.VulnerabilityID == "CVE-2024-0001" {
			cve0001 = r
			break
		}
	}

	if cve0001 == nil {
		t.Fatal("expected to find CVE-2024-0001 in results")
	}

	// Despite 3 entries, only 2 unique servers (project1|production and project2|staging)
	if cve0001.AffectedServers != 2 {
		t.Errorf("CVE-2024-0001 AffectedServers: got %d, want 2", cve0001.AffectedServers)
	}
	if cve0001.AffectedProjects != 2 {
		t.Errorf("CVE-2024-0001 AffectedProjects: got %d, want 2", cve0001.AffectedProjects)
	}
}
