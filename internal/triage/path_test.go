package triage

import (
	"testing"
)

func TestComputeTriagePaths_DeterministicIDs(t *testing.T) {
	findings := []ScanFinding{
		{
			VulnerabilityID: "CVE-2024-0001",
			PackagePurl:     "pkg:golang/golang.org/x/text",
			CurrentVersion:  "0.3.5",
			FixedVersion:    "0.3.8",
			Ecosystem:       "Go",
			ServerLabel:     "server-1",
			ProjectID:       1,
			ProjectName:     "app-1",
			CompositeScore:  7.5,
			PriorityLevel:   PriorityHigh,
		},
		{
			VulnerabilityID: "CVE-2024-0002",
			PackagePurl:     "pkg:npm/express",
			CurrentVersion:  "4.17.1",
			FixedVersion:    "4.18.0",
			Ecosystem:       "npm",
			ServerLabel:     "server-2",
			ProjectID:       2,
			ProjectName:     "app-2",
			CompositeScore:  5.0,
			PriorityLevel:   PriorityMedium,
		},
		{
			VulnerabilityID: "CVE-2024-0003",
			PackagePurl:     "pkg:golang/golang.org/x/text",
			CurrentVersion:  "0.3.5",
			FixedVersion:    "0.3.9",
			Ecosystem:       "Go",
			ServerLabel:     "server-1",
			ProjectID:       1,
			ProjectName:     "app-1",
			CompositeScore:  9.0,
			PriorityLevel:   PriorityCritical,
		},
	}

	// Run multiple times to confirm determinism
	var firstRunIDs map[string]string // package -> id
	for i := 0; i < 20; i++ {
		paths := ComputeTriagePaths(findings)
		if len(paths) != 2 {
			t.Fatalf("expected 2 paths, got %d", len(paths))
		}

		currentIDs := make(map[string]string)
		for _, p := range paths {
			currentIDs[p.Action.Package] = p.ID
		}

		if firstRunIDs == nil {
			firstRunIDs = currentIDs
		} else {
			for pkg, id := range firstRunIDs {
				if currentIDs[pkg] != id {
					t.Errorf("non-deterministic ID on iteration %d: package %s had ID %q, now %q",
						i, pkg, id, currentIDs[pkg])
				}
			}
		}
	}
}

func TestComputeTriagePaths_IDFormat(t *testing.T) {
	findings := []ScanFinding{
		{
			VulnerabilityID: "CVE-2024-0001",
			PackagePurl:     "pkg:golang/golang.org/x/text",
			CurrentVersion:  "0.3.5",
			FixedVersion:    "0.3.8",
			Ecosystem:       "Go",
			ServerLabel:     "server-1",
			ProjectID:       1,
			ProjectName:     "app-1",
			CompositeScore:  7.5,
			PriorityLevel:   PriorityHigh,
		},
	}

	paths := ComputeTriagePaths(findings)
	if len(paths) != 1 {
		t.Fatalf("expected 1 path, got %d", len(paths))
	}

	id := paths[0].ID
	if len(id) == 0 {
		t.Fatal("path ID is empty")
	}
	if id[:5] != "path-" {
		t.Errorf("path ID should start with 'path-', got %q", id)
	}
	// Should be "path-" + 16 hex chars = 21 chars total
	if len(id) != 21 {
		t.Errorf("expected path ID length 21, got %d (%q)", len(id), id)
	}
}

func TestComputeTriagePaths_SameInputSameID(t *testing.T) {
	// Two identical sets of findings should produce identical IDs
	findings := []ScanFinding{
		{
			VulnerabilityID: "CVE-2024-0001",
			PackagePurl:     "pkg:golang/golang.org/x/text",
			CurrentVersion:  "0.3.5",
			FixedVersion:    "0.3.8",
			Ecosystem:       "Go",
			ServerLabel:     "server-1",
			ProjectID:       1,
			ProjectName:     "app-1",
			CompositeScore:  7.5,
			PriorityLevel:   PriorityHigh,
		},
	}

	paths1 := ComputeTriagePaths(findings)
	paths2 := ComputeTriagePaths(findings)

	if paths1[0].ID != paths2[0].ID {
		t.Errorf("same input produced different IDs: %q vs %q", paths1[0].ID, paths2[0].ID)
	}
}

func TestComputeTriagePaths_DifferentInputDifferentID(t *testing.T) {
	findingsA := []ScanFinding{
		{
			VulnerabilityID: "CVE-2024-0001",
			PackagePurl:     "pkg:golang/golang.org/x/text",
			CurrentVersion:  "0.3.5",
			FixedVersion:    "0.3.8",
			Ecosystem:       "Go",
			ServerLabel:     "server-1",
			ProjectID:       1,
			ProjectName:     "app-1",
			CompositeScore:  7.5,
			PriorityLevel:   PriorityHigh,
		},
	}

	findingsB := []ScanFinding{
		{
			VulnerabilityID: "CVE-2024-0001",
			PackagePurl:     "pkg:npm/express",
			CurrentVersion:  "4.17.1",
			FixedVersion:    "4.18.0",
			Ecosystem:       "npm",
			ServerLabel:     "server-1",
			ProjectID:       1,
			ProjectName:     "app-1",
			CompositeScore:  7.5,
			PriorityLevel:   PriorityHigh,
		},
	}

	pathsA := ComputeTriagePaths(findingsA)
	pathsB := ComputeTriagePaths(findingsB)

	if pathsA[0].ID == pathsB[0].ID {
		t.Errorf("different inputs should produce different IDs, both got %q", pathsA[0].ID)
	}
}
