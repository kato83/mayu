package sbom

import (
	"context"
	"log"
	"time"

	"github.com/kato83/mayu/internal/triage"
)

// TriageOnScanConfig configures automatic triage execution during SBOM scanning.
type TriageOnScanConfig struct {
	// Enabled controls whether automatic triage is triggered on scan.
	Enabled bool

	// DefaultProfile is the fallback triage profile when no project/server binding exists.
	DefaultProfile *triage.Profile

	// BindingStore provides server-level profile bindings for resolution.
	BindingStore triage.BindingStore

	// PathCacheStore stores computed triage paths for fast retrieval.
	PathCacheStore TriagePathCacheStore

	// Logger for diagnostic output.
	Logger *log.Logger
}

// TriagePathCacheStore persists computed triage paths.
type TriagePathCacheStore interface {
	// UpsertTriagePaths replaces the cached triage paths for a project.
	UpsertTriagePaths(ctx context.Context, projectID int64, paths []*triage.TriagePath) error

	// GetTriagePaths retrieves cached triage paths for a project.
	GetTriagePaths(ctx context.Context, projectID int64) ([]*triage.TriagePath, error)
}

// VulnDataForTriage holds the vulnerability data needed for triage computation.
// This is populated from the scan results or vulnerability database.
type VulnDataForTriage struct {
	VulnerabilityID string
	PackagePurl     string
	CurrentVersion  string
	FixedVersion    string
	Ecosystem       string
	CVSSScore       *float64
	CVSSVector      string
	EPSSScore       *float64
	LEVScore        *float64
	InKEV           bool
	PatchAvailable  bool
	PublishedAt     *time.Time
	HasExploit      bool
	IsReachable     *bool
}

// ScanTriageResult holds the outcome of automatic triage execution on scan.
type ScanTriageResult struct {
	// ProjectID is the SBOM project that was scanned.
	ProjectID int64

	// ServerLabel is the server/asset label (if specified).
	ServerLabel string

	// ProfileUsed is the name of the triage profile applied.
	ProfileUsed string

	// Results contains the individual triage results for each vulnerability.
	Results []*triage.TriageResult

	// Paths contains the computed triage paths (remediation groupings).
	Paths []*triage.TriagePath

	// ComputedAt is when the triage was computed.
	ComputedAt time.Time
}

// AutoTriageOnScan executes automatic triage when an SBOM project is re-scanned.
// It resolves the appropriate profile (project binding preferred), runs triage on
// all findings, computes triage paths, and updates the path cache.
//
// Requirements: 9.1 (auto-triage on rescan), 9.3 (project profile preference)
func AutoTriageOnScan(ctx context.Context, cfg *TriageOnScanConfig, projectID int64, serverLabel string, findings []VulnDataForTriage) (*ScanTriageResult, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}

	logger := cfg.Logger
	if logger == nil {
		logger = log.Default()
	}

	// Resolve which triage profile to use for this project/server
	profile, resolveSource := resolveProfileForScan(cfg, projectID, serverLabel)
	logger.Printf("triage/scan: project=%d server=%q profile=%q (source=%s)", projectID, serverLabel, profile.Name, resolveSource)

	// Create engine with resolved profile
	engine := triage.NewEngine(profile)

	// Build triage inputs from scan findings
	inputs := make([]*triage.TriageInput, 0, len(findings))
	for _, f := range findings {
		input := triage.NewTriageInputFromDetail(
			f.VulnerabilityID,
			f.CVSSScore,
			f.CVSSVector,
			f.EPSSScore,
			f.LEVScore,
			f.InKEV,
			f.PatchAvailable,
			f.PublishedAt,
			f.HasExploit,
			f.IsReachable,
			nil, // SSVCOptions - populated separately if available
		)
		inputs = append(inputs, input)
	}

	// Execute batch triage
	results, err := engine.TriageBatch(ctx, inputs)
	if err != nil {
		return nil, err
	}

	// Build scan findings for triage path computation
	scanFindings := buildScanFindings(findings, results, projectID, serverLabel)

	// Compute triage paths
	paths := triage.ComputeTriagePaths(scanFindings)

	// Update triage path cache if store is available
	if cfg.PathCacheStore != nil {
		if err := cfg.PathCacheStore.UpsertTriagePaths(ctx, projectID, paths); err != nil {
			logger.Printf("triage/scan: failed to cache triage paths for project %d: %v", projectID, err)
			// Non-fatal: continue even if caching fails
		}
	}

	return &ScanTriageResult{
		ProjectID:   projectID,
		ServerLabel: serverLabel,
		ProfileUsed: profile.Name,
		Results:     results,
		Paths:       paths,
		ComputedAt:  time.Now(),
	}, nil
}

// RecalculateTriageOnDataIngest triggers triage recalculation when new EPSS/KEV/Exploit-DB
// data is ingested. This ensures that existing findings are re-evaluated with the latest
// threat intelligence data.
//
// Requirements: 9.2 (recalculation on new data ingest)
func RecalculateTriageOnDataIngest(ctx context.Context, cfg *TriageOnScanConfig, projectID int64, serverLabel string, findings []VulnDataForTriage) (*ScanTriageResult, error) {
	// Recalculation uses the same logic as initial scan triage
	return AutoTriageOnScan(ctx, cfg, projectID, serverLabel, findings)
}

// resolveProfileForScan determines which profile to use for a scan.
// Priority: server binding > project binding > default profile.
func resolveProfileForScan(cfg *TriageOnScanConfig, projectID int64, serverLabel string) (*triage.Profile, string) {
	if cfg.BindingStore != nil {
		// Try server-level binding first
		if serverLabel != "" {
			binding, err := cfg.BindingStore.GetBindingByServer(projectID, serverLabel)
			if err == nil && binding != nil {
				p := findBuiltinProfile(binding.ProfileName)
				if p != nil {
					return p, "server_binding"
				}
			}
		}

		// Try project-level binding (server_label = "" is the project-level convention)
		binding, err := cfg.BindingStore.GetBindingByServer(projectID, "")
		if err == nil && binding != nil {
			p := findBuiltinProfile(binding.ProfileName)
			if p != nil {
				return p, "project_binding"
			}
		}
	}

	// Fall back to configured default or global default
	if cfg.DefaultProfile != nil {
		return cfg.DefaultProfile, "configured_default"
	}
	return triage.DefaultProfile(), "global_default"
}

// findBuiltinProfile looks up a profile from built-in templates.
func findBuiltinProfile(name string) *triage.Profile {
	for _, t := range triage.BuiltinTemplates() {
		if t.Name == name {
			return &t
		}
	}
	return nil
}

// buildScanFindings maps vulnerability data and triage results into ScanFinding entries
// for triage path computation.
func buildScanFindings(vulnData []VulnDataForTriage, results []*triage.TriageResult, projectID int64, serverLabel string) []triage.ScanFinding {
	// Build lookup map from vulnerability ID to triage result
	resultMap := make(map[string]*triage.TriageResult, len(results))
	for _, r := range results {
		resultMap[r.VulnerabilityID] = r
	}

	findings := make([]triage.ScanFinding, 0, len(vulnData))
	for _, vd := range vulnData {
		finding := triage.ScanFinding{
			VulnerabilityID: vd.VulnerabilityID,
			PackagePurl:     vd.PackagePurl,
			CurrentVersion:  vd.CurrentVersion,
			FixedVersion:    vd.FixedVersion,
			Ecosystem:       vd.Ecosystem,
			ServerLabel:     serverLabel,
			ProjectID:       projectID,
		}

		// Enrich with triage results if available
		if result, ok := resultMap[vd.VulnerabilityID]; ok {
			finding.CompositeScore = result.CompositeScore
			finding.PriorityLevel = result.PriorityLevel
		}

		findings = append(findings, finding)
	}

	return findings
}
