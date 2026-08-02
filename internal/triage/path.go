package triage

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// TriagePath represents a remediation action group — a single upgrade/fix
// that resolves multiple vulnerabilities across multiple servers/projects.
type TriagePath struct {
	ID                      string              `json:"id"`
	Action                  RemediationAction   `json:"action"`
	ResolvedVulnerabilities []ResolvedVulnEntry `json:"resolved_vulnerabilities"`
	Servers                 []ServerTriageEntry `json:"-"`
	AffectedServers         []string            `json:"affected_servers"`
	ImpactScore             float64             `json:"impact_score"`
	MaxPriorityLevel        PriorityLevel       `json:"max_priority_level"`
	TotalVulnCount          int                 `json:"total_vuln_count"`
	TotalServerCount        int                 `json:"total_server_count"`
}

// RemediationAction represents a concrete remediation step.
type RemediationAction struct {
	Type           string `json:"type"`
	Package        string `json:"package_name"`
	CurrentVersion string `json:"current_version"`
	TargetVersion  string `json:"target_version"`
	Ecosystem      string `json:"ecosystem"`
}

// ResolvedVulnEntry represents a vulnerability resolved by a triage path action.
type ResolvedVulnEntry struct {
	VulnerabilityID string        `json:"vulnerability_id"`
	PriorityLevel   PriorityLevel `json:"priority_level"`
	CompositeScore  float64       `json:"composite_score"`
	FixedVersion    string        `json:"fixed_version"`
	AffectedServers []string      `json:"affected_servers"`
}

// ScanFinding is an input type representing a vulnerability finding from an SBOM scan.
type ScanFinding struct {
	VulnerabilityID string
	PackagePurl     string
	CurrentVersion  string
	FixedVersion    string
	Ecosystem       string
	ServerLabel     string
	ProjectID       int64
	ProjectName     string
	Environment     string
	CompositeScore  float64
	PriorityLevel   PriorityLevel
}

// ComputeTriagePaths groups scan findings into triage paths.
// Each path represents a single upgrade action that resolves multiple CVEs.
func ComputeTriagePaths(findings []ScanFinding) []*TriagePath {
	// Step 1: Group by (package_purl, current_version, ecosystem)
	type groupKey struct {
		PackagePurl    string
		CurrentVersion string
		Ecosystem      string
	}

	groups := make(map[groupKey][]ScanFinding)
	for _, f := range findings {
		if f.FixedVersion == "" {
			continue // Skip findings without a known fix
		}
		key := groupKey{
			PackagePurl:    f.PackagePurl,
			CurrentVersion: f.CurrentVersion,
			Ecosystem:      f.Ecosystem,
		}
		groups[key] = append(groups[key], f)
	}

	var paths []*TriagePath

	for key, groupFindings := range groups {
		// Generate a deterministic ID from the group key so that the same
		// package+version+ecosystem always maps to the same path ID regardless
		// of Go map iteration order.
		idInput := key.PackagePurl + "|" + key.CurrentVersion + "|" + key.Ecosystem
		hash := sha256.Sum256([]byte(idInput))
		pathIDStr := "path-" + hex.EncodeToString(hash[:8])

		path := &TriagePath{
			ID: pathIDStr,
			Action: RemediationAction{
				Type:           "upgrade",
				Package:        key.PackagePurl,
				CurrentVersion: key.CurrentVersion,
				Ecosystem:      key.Ecosystem,
			},
		}

		// Step 4: Compute target version (max of all fixed versions)
		var fixedVersions []string
		for _, f := range groupFindings {
			fixedVersions = append(fixedVersions, f.FixedVersion)
		}
		path.Action.TargetVersion = ComputeTargetVersion(fixedVersions)

		// Aggregate vulnerabilities and servers
		vulnMap := make(map[string]*ResolvedVulnEntry)
		serverSet := make(map[string]struct{})
		maxPriority := PriorityLow

		for _, f := range groupFindings {
			// Track unique servers
			serverKey := fmt.Sprintf("%d:%s", f.ProjectID, f.ServerLabel)
			serverSet[serverKey] = struct{}{}

			// Update priority
			if PriorityRank(f.PriorityLevel) > PriorityRank(maxPriority) {
				maxPriority = f.PriorityLevel
			}

			// Aggregate by vulnerability
			if entry, exists := vulnMap[f.VulnerabilityID]; exists {
				entry.AffectedServers = appendUnique(entry.AffectedServers, f.ServerLabel)
				if f.CompositeScore > entry.CompositeScore {
					entry.CompositeScore = f.CompositeScore
					entry.PriorityLevel = f.PriorityLevel
				}
				if f.FixedVersion != "" && VersionGreaterThan(f.FixedVersion, entry.FixedVersion) {
					entry.FixedVersion = f.FixedVersion
				}
			} else {
				vulnMap[f.VulnerabilityID] = &ResolvedVulnEntry{
					VulnerabilityID: f.VulnerabilityID,
					PriorityLevel:   f.PriorityLevel,
					CompositeScore:  f.CompositeScore,
					FixedVersion:    f.FixedVersion,
					AffectedServers: []string{f.ServerLabel},
				}
			}
		}

		// Build resolved vulnerabilities list
		for _, entry := range vulnMap {
			path.ResolvedVulnerabilities = append(path.ResolvedVulnerabilities, *entry)
		}

		path.MaxPriorityLevel = maxPriority
		path.TotalVulnCount = len(vulnMap)
		path.TotalServerCount = len(serverSet)

		// Build Servers (internal, for filtering) and AffectedServers (JSON output)
		serverEntrySeen := make(map[string]bool)
		for _, f := range groupFindings {
			entryKey := fmt.Sprintf("%d:%s", f.ProjectID, f.ServerLabel)
			if !serverEntrySeen[entryKey] {
				serverEntrySeen[entryKey] = true
				path.Servers = append(path.Servers, ServerTriageEntry{
					ProjectID:   f.ProjectID,
					ProjectName: f.ProjectName,
					ServerLabel: f.ServerLabel,
					Environment: f.Environment,
				})
				// Build display label: "ProjectName / ServerLabel" or just "ProjectName" if default
				var displayLabel string
				if f.ServerLabel == "" || f.ServerLabel == "default" {
					displayLabel = f.ProjectName
				} else {
					displayLabel = f.ProjectName + " / " + f.ServerLabel
				}
				path.AffectedServers = append(path.AffectedServers, displayLabel)
			}
		}

		// Step 3: Compute Impact Score
		path.ImpactScore = ComputeImpactScore(groupFindings)

		paths = append(paths, path)
	}

	// Sort by Impact Score descending
	sort.Slice(paths, func(i, j int) bool {
		return paths[i].ImpactScore > paths[j].ImpactScore
	})

	return paths
}

// ComputeImpactScore calculates the impact score for a set of findings.
// impact_score = Σ (composite_score[i] × server_weight[i])
// server_weight = 1.0 + 0.1 × (affected_server_count - 1)
func ComputeImpactScore(findings []ScanFinding) float64 {
	// Count unique servers
	serverSet := make(map[string]struct{})
	for _, f := range findings {
		serverKey := fmt.Sprintf("%d:%s", f.ProjectID, f.ServerLabel)
		serverSet[serverKey] = struct{}{}
	}
	serverCount := len(serverSet)
	serverWeight := 1.0 + 0.1*float64(serverCount-1)

	var total float64
	for _, f := range findings {
		total += f.CompositeScore * serverWeight
	}
	return total
}

// ComputeTargetVersion determines the minimum version that resolves all CVEs.
// Uses simple semantic version comparison; falls back to lexicographic if not semver.
func ComputeTargetVersion(fixedVersions []string) string {
	if len(fixedVersions) == 0 {
		return ""
	}

	target := fixedVersions[0]
	for _, v := range fixedVersions[1:] {
		if VersionGreaterThan(v, target) {
			target = v
		}
	}
	return target
}

// VersionGreaterThan returns true if a > b using semver-like comparison.
func VersionGreaterThan(a, b string) bool {
	aParts := parseVersionParts(a)
	bParts := parseVersionParts(b)

	maxLen := len(aParts)
	if len(bParts) > maxLen {
		maxLen = len(bParts)
	}

	for i := 0; i < maxLen; i++ {
		var av, bv int
		if i < len(aParts) {
			av = aParts[i]
		}
		if i < len(bParts) {
			bv = bParts[i]
		}
		if av != bv {
			return av > bv
		}
	}
	return false
}

// VersionLessThan returns true if a < b.
func VersionLessThan(a, b string) bool {
	return VersionGreaterThan(b, a)
}

// parseVersionParts splits a version string into numeric parts.
func parseVersionParts(v string) []int {
	parts := strings.Split(v, ".")
	result := make([]int, 0, len(parts))
	for _, p := range parts {
		// Parse only the numeric prefix
		n := 0
		for _, ch := range p {
			if ch >= '0' && ch <= '9' {
				n = n*10 + int(ch-'0')
			} else {
				break
			}
		}
		result = append(result, n)
	}
	return result
}

// appendUnique appends a value to a slice only if it's not already present.
func appendUnique(slice []string, val string) []string {
	for _, s := range slice {
		if s == val {
			return slice
		}
	}
	return append(slice, val)
}
