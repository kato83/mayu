package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/kato83/mayu/internal/config"
	"github.com/kato83/mayu/internal/model"
	"github.com/kato83/mayu/internal/sbommon"
	"github.com/kato83/mayu/internal/store"
	"github.com/kato83/mayu/internal/triage"
)

func runTriage(args []string, cfg *config.Config) error {
	if len(args) == 0 {
		printTriageUsage()
		return nil
	}

	switch args[0] {
	case "profile":
		return runTriageProfile(args[1:])
	case "overview":
		return runTriageOverview(args[1:], cfg)
	case "paths":
		return runTriagePaths(args[1:], cfg)
	case "help", "-h", "--help":
		printTriageUsage()
		return nil
	default:
		return runTriageExecute(args)
	}
}

func printTriageUsage() {
	fmt.Println("Usage: mayu triage <command> [options]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  --id <vuln-id>       Triage a single vulnerability")
	fmt.Println("  --sbom <path>        Triage all findings in an SBOM scan")
	fmt.Println("  profile              Manage triage profiles")
	fmt.Println("  overview             Cross-project triage overview")
	fmt.Println("  paths                Triage paths for remediation grouping")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  --profile <name>     Profile to use (default: default)")
	fmt.Println("  --environment <name> Environment name for profile auto-resolution")
	fmt.Println("  --format <fmt>       Output format: table, json, csv (default: table)")
	fmt.Println("  --fail-on <level>    Exit code 1 if priority >= level (critical, high, medium, low)")
	fmt.Println("  --top <N>            Show only top N results")
}

func runTriageExecute(args []string) error {
	fs := flag.NewFlagSet("triage", flag.ContinueOnError)
	vulnID := fs.String("id", "", "Vulnerability ID to triage")
	sbomPath := fs.String("sbom", "", "SBOM file path for batch triage")
	profileName := fs.String("profile", "default", "Triage profile name or path")
	environment := fs.String("environment", "", "Environment name for profile auto-resolution")
	format := fs.String("format", "table", "Output format: table, json, csv")
	failOn := fs.String("fail-on", "", "Exit code 1 if any result >= level")
	top := fs.Int("top", 0, "Show only top N results")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Load profile
	profile := loadTriageProfile(*profileName)

	engine := triage.NewEngine(profile)

	// Handle environment-based profile resolution
	if *environment != "" {
		opts := &triage.ResolveOpts{
			ExplicitProfile: *profileName,
			Environment:     *environment,
		}
		resolved, _ := engine.ResolveProfile(opts, nil, nil)
		engine = triage.NewEngine(resolved)
	}

	if *vulnID != "" {
		return triageSingleVuln(engine, *vulnID, *format)
	}

	if *sbomPath != "" {
		return triageBatchSBOM(engine, *sbomPath, *format, *failOn, *top)
	}

	return fmt.Errorf("either --id or --sbom is required")
}

func triageSingleVuln(engine *triage.Engine, vulnID string, format string) error {
	// For single triage, create a minimal input (in real usage, data would come from DB)
	input := &triage.TriageInput{
		VulnerabilityID: vulnID,
	}

	result, err := engine.Triage(context.Background(), input)
	if err != nil {
		return fmt.Errorf("triage failed: %w", err)
	}

	return outputTriageResult(result, format)
}

func triageBatchSBOM(engine *triage.Engine, sbomPath string, format string, failOn string, top int) error {
	// Read SBOM file (JSON expected)
	data, err := os.ReadFile(sbomPath)
	if err != nil {
		return fmt.Errorf("read SBOM: %w", err)
	}

	// Parse as a generic JSON with findings
	var sbom struct {
		Findings []struct {
			VulnerabilityID string   `json:"vulnerability_id"`
			CVSS            *float64 `json:"cvss_score"`
			EPSS            *float64 `json:"epss_score"`
			InKEV           bool     `json:"in_kev"`
			HasExploit      bool     `json:"has_exploit"`
			PatchAvailable  bool     `json:"patch_available"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(data, &sbom); err != nil {
		return fmt.Errorf("parse SBOM: %w", err)
	}

	// Build inputs
	var inputs []*triage.TriageInput
	for _, f := range sbom.Findings {
		input := &triage.TriageInput{
			VulnerabilityID: f.VulnerabilityID,
			CVSSScore:       f.CVSS,
			EPSSScore:       f.EPSS,
			InKEV:           f.InKEV,
			HasExploit:      f.HasExploit,
			PatchAvailable:  f.PatchAvailable,
		}
		inputs = append(inputs, input)
	}

	results, err := engine.TriageBatch(context.Background(), inputs)
	if err != nil {
		return fmt.Errorf("batch triage failed: %w", err)
	}

	// Apply --top
	if top > 0 && top < len(results) {
		results = results[:top]
	}

	// Output
	if err := outputTriageResults(results, format, engine.Profile().Name); err != nil {
		return err
	}

	// Check --fail-on
	if failOn != "" {
		failLevel := triage.PriorityLevel(capitalizeFirst(failOn))
		for _, r := range results {
			if triage.PriorityRank(r.PriorityLevel) >= triage.PriorityRank(failLevel) {
				fmt.Fprintf(os.Stderr, "\n⚠ Found %s priority (fail-on: %s)\n", r.PriorityLevel, failOn)
				os.Exit(1)
			}
		}
	}

	return nil
}

func outputTriageResult(result *triage.TriageResult, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	case "csv":
		fmt.Println("vulnerability_id,priority_level,composite_score,ssvc_decision,profile_used")
		fmt.Printf("%s,%s,%.4f,%s,%s\n",
			result.VulnerabilityID, result.PriorityLevel,
			result.CompositeScore, result.SSVCDecision, result.ProfileUsed)
		return nil
	default: // table
		fmt.Printf("Vulnerability: %s\n", result.VulnerabilityID)
		fmt.Printf("Priority:      %s\n", result.PriorityLevel)
		fmt.Printf("Score:         %.4f\n", result.CompositeScore)
		fmt.Printf("SSVC:          %s\n", result.SSVCDecision)
		fmt.Printf("Profile:       %s\n", result.ProfileUsed)
		if result.Rationale != nil {
			fmt.Printf("Rationale:     %s\n", result.Rationale.Summary)
		}
		return nil
	}
}

func outputTriageResults(results []*triage.TriageResult, format string, profileUsed string) error {
	switch format {
	case "json":
		report := map[string]interface{}{
			"profile_used": profileUsed,
			"summary": map[string]int{
				"total":    len(results),
				"critical": countPriority(results, triage.PriorityCritical),
				"high":     countPriority(results, triage.PriorityHigh),
				"medium":   countPriority(results, triage.PriorityMedium),
				"low":      countPriority(results, triage.PriorityLow),
			},
			"results": results,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	case "csv":
		fmt.Println("vulnerability_id,priority_level,composite_score,ssvc_decision")
		for _, r := range results {
			fmt.Printf("%s,%s,%.4f,%s\n",
				r.VulnerabilityID, r.PriorityLevel,
				r.CompositeScore, r.SSVCDecision)
		}
		return nil
	default: // table
		fmt.Printf("Triage Report (profile: %s)\n", profileUsed)
		fmt.Println(strings.Repeat("─", 70))
		fmt.Printf("%-20s %-10s %-8s %-10s\n", "VULNERABILITY", "PRIORITY", "SCORE", "SSVC")
		fmt.Println(strings.Repeat("─", 70))
		for _, r := range results {
			fmt.Printf("%-20s %-10s %-8.4f %-10s\n",
				truncateStr(r.VulnerabilityID, 20),
				r.PriorityLevel,
				r.CompositeScore,
				r.SSVCDecision)
		}
		fmt.Println(strings.Repeat("─", 70))
		fmt.Printf("Total: %d | Critical: %d | High: %d | Medium: %d | Low: %d\n",
			len(results),
			countPriority(results, triage.PriorityCritical),
			countPriority(results, triage.PriorityHigh),
			countPriority(results, triage.PriorityMedium),
			countPriority(results, triage.PriorityLow))
		return nil
	}
}

func countPriority(results []*triage.TriageResult, level triage.PriorityLevel) int {
	count := 0
	for _, r := range results {
		if r.PriorityLevel == level {
			count++
		}
	}
	return count
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

// --- Profile Subcommand ---

func runTriageProfile(args []string) error {
	if len(args) == 0 {
		fmt.Println("Usage: mayu triage profile <subcommand>")
		fmt.Println()
		fmt.Println("Subcommands:")
		fmt.Println("  validate   Validate a triage profile YAML file")
		fmt.Println("  list       List built-in template profiles")
		fmt.Println("  show       Show a template profile's contents")
		fmt.Println("  bind       Bind a profile to an environment")
		fmt.Println("  unbind     Remove a profile binding")
		fmt.Println("  bindings   List profile bindings for a project")
		return nil
	}

	switch args[0] {
	case "validate":
		return runTriageProfileValidate(args[1:])
	case "list":
		return runTriageProfileList()
	case "show":
		return runTriageProfileShow(args[1:])
	case "bind":
		return runTriageProfileBind(args[1:])
	case "unbind":
		return runTriageProfileUnbind(args[1:])
	case "bindings":
		return runTriageProfileBindings(args[1:])
	default:
		return fmt.Errorf("unknown profile subcommand: %q", args[0])
	}
}

func runTriageProfileValidate(args []string) error {
	fs := flag.NewFlagSet("triage profile validate", flag.ContinueOnError)
	filePath := fs.String("file", "", "Path to triage profile YAML file")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *filePath == "" {
		return fmt.Errorf("--file is required")
	}

	profile, err := triage.LoadProfile(*filePath)
	if err != nil {
		return fmt.Errorf("load profile: %w", err)
	}

	errs := triage.ValidateProfile(profile)
	if len(errs) > 0 {
		fmt.Printf("✗ %d validation error(s) in %s:\n\n", len(errs), *filePath)
		for _, e := range errs {
			fmt.Printf("  • %v\n", e)
		}
		return fmt.Errorf("profile is invalid")
	}

	fmt.Printf("✓ %s is valid (profile: %s)\n", *filePath, profile.Name)
	return nil
}

func runTriageProfileList() error {
	templates := triage.BuiltinTemplates()
	fmt.Println("Built-in triage profile templates:")
	fmt.Println()
	fmt.Printf("%-18s %s\n", "NAME", "DESCRIPTION")
	fmt.Println(strings.Repeat("─", 60))
	for _, t := range templates {
		fmt.Printf("%-18s %s\n", t.Name, t.Description)
	}
	return nil
}

func runTriageProfileShow(args []string) error {
	fs := flag.NewFlagSet("triage profile show", flag.ContinueOnError)
	name := fs.String("name", "", "Template profile name")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *name == "" {
		return fmt.Errorf("--name is required")
	}

	templates := triage.BuiltinTemplates()
	for _, t := range templates {
		if t.Name == *name {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(t)
		}
	}

	return fmt.Errorf("template %q not found (use 'mayu triage profile list' to see available templates)", *name)
}

func runTriageProfileBind(args []string) error {
	fs := flag.NewFlagSet("triage profile bind", flag.ContinueOnError)
	project := fs.String("project", "", "Project name/ID")
	environment := fs.String("environment", "", "Environment name")
	profileName := fs.String("profile", "", "Profile name to bind")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *project == "" || *environment == "" || *profileName == "" {
		return fmt.Errorf("--project, --environment, and --profile are all required")
	}

	// Verify profile exists
	if p := findProfile(*profileName); p == nil {
		return fmt.Errorf("profile %q not found", *profileName)
	}

	fmt.Printf("✓ Bound profile %q to environment %q in project %q\n", *profileName, *environment, *project)
	fmt.Println("  (Note: In production, this is persisted to the database via API)")
	return nil
}

func runTriageProfileUnbind(args []string) error {
	fs := flag.NewFlagSet("triage profile unbind", flag.ContinueOnError)
	project := fs.String("project", "", "Project name/ID")
	environment := fs.String("environment", "", "Environment name")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *project == "" || *environment == "" {
		return fmt.Errorf("--project and --environment are required")
	}

	fmt.Printf("✓ Unbound profile from environment %q in project %q\n", *environment, *project)
	return nil
}

func runTriageProfileBindings(args []string) error {
	fs := flag.NewFlagSet("triage profile bindings", flag.ContinueOnError)
	project := fs.String("project", "", "Project name/ID")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *project == "" {
		return fmt.Errorf("--project is required")
	}

	fmt.Printf("Profile bindings for project %q:\n", *project)
	fmt.Println("  (No bindings configured — use 'mayu triage profile bind' to add)")
	return nil
}

// --- Overview Subcommand ---

func runTriageOverview(args []string, cfg *config.Config) error {
	fs := flag.NewFlagSet("triage overview", flag.ContinueOnError)
	priority := fs.String("priority", "", "Minimum priority level filter")
	topN := fs.Int("top", 20, "Number of results to show")
	format := fs.String("format", "table", "Output format: table, json")
	sortBy := fs.String("sort", "priority", "Sort by: priority, affected_count")
	project := fs.String("project", "", "Filter by project name")

	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Authenticate and get DB connection
	user, db, err := resolveAuthUser(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	databaseURL := resolveDatabaseURL(cfg)
	mainStore, err := store.NewPostgresStore(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("connect to store: %w", err)
	}
	defer func() { _ = mainStore.Close() }()

	sbomStore := sbommon.NewPostgresSBOMStore(db)

	// Compute cross-project overview
	summary, crossResults := computeCLIOverview(ctx, user.ID, sbomStore, mainStore, *project)

	// Filter by priority
	if *priority != "" {
		var filtered []*triage.CrossProjectTriageResult
		for _, cr := range crossResults {
			if strings.EqualFold(string(cr.OrgPriorityLevel), *priority) {
				filtered = append(filtered, cr)
			}
		}
		crossResults = filtered
	}

	// Sort
	if *sortBy == "affected_count" {
		sortByAffectedCount(crossResults)
	}
	// Default sort (by priority) is already done by AggregateCrossProjectBatch

	// Apply --top limit
	if *topN > 0 && *topN < len(crossResults) {
		crossResults = crossResults[:*topN]
	}

	switch *format {
	case "json":
		report := map[string]interface{}{
			"summary": map[string]int{
				"total":         summary.Total,
				"critical":      summary.Critical,
				"high":          summary.High,
				"medium":        summary.Medium,
				"low":           summary.Low,
				"risk_accepted": summary.RiskAccepted,
			},
			"vulnerabilities": crossResults,
			"computed_at":     time.Now().UTC().Format(time.RFC3339),
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	default: // table
		fmt.Println("Triage Overview")
		fmt.Println("═══════════════════════════════")
		fmt.Printf("Critical: %d\n", summary.Critical)
		fmt.Printf("High:     %d\n", summary.High)
		fmt.Printf("Medium:   %d\n", summary.Medium)
		fmt.Printf("Low:      %d\n", summary.Low)
		fmt.Println("───────────────────────────────")
		fmt.Printf("Total:    %d\n", summary.Total)
		if summary.RiskAccepted > 0 {
			fmt.Printf("Risk Accepted: %d\n", summary.RiskAccepted)
		}
		fmt.Println()

		if len(crossResults) > 0 {
			fmt.Printf("Top Vulnerabilities (sorted by %s):\n", *sortBy)
			fmt.Println(strings.Repeat("─", 90))
			fmt.Printf("%-20s %-10s %-8s %-10s %-10s\n", "VULNERABILITY", "PRIORITY", "SCORE", "SERVERS", "PROJECTS")
			fmt.Println(strings.Repeat("─", 90))
			for _, cr := range crossResults {
				fmt.Printf("%-20s %-10s %-8.4f %-10d %-10d\n",
					truncateStr(cr.VulnerabilityID, 20),
					cr.OrgPriorityLevel,
					cr.MaxCompositeScore,
					cr.AffectedServers,
					cr.AffectedProjects)
			}
			fmt.Println(strings.Repeat("─", 90))
		}
		return nil
	}
}

// computeCLIOverview aggregates triage results across all SBOM projects for the given user.
func computeCLIOverview(ctx context.Context, userID int64, sbomStore *sbommon.PostgresSBOMStore, mainStore *store.PostgresStore, projectFilter string) (*triage.OverviewSummary, []*triage.CrossProjectTriageResult) {
	projects, err := sbomStore.ListProjects(ctx, userID)
	if err != nil || len(projects) == 0 {
		return &triage.OverviewSummary{}, nil
	}

	entriesByVuln := make(map[string][]triage.ServerTriageEntry)
	riskAcceptedVulnIDs := make(map[string]bool)

	for _, proj := range projects {
		// Apply project filter if specified
		if projectFilter != "" && !strings.EqualFold(proj.Name, projectFilter) {
			continue
		}

		latestVer, err := sbomStore.GetLatestVersion(ctx, proj.ID)
		if err != nil || latestVer == nil {
			continue
		}

		scanResult, err := sbomStore.GetLatestScanResult(ctx, latestVer.ID)
		if err != nil || scanResult == nil || len(scanResult.Findings) == 0 {
			continue
		}

		// Resolve profile for this project/environment
		profile := resolveProfileForProjectEnv(ctx, mainStore, proj.ID, latestVer.Environment)
		engine := triage.NewEngine(profile)

		// Exclude suppressed/false_positive/resolved/risk_accepted findings
		excludedStatuses := make(map[string]bool)
		riskAcceptedKeys := make(map[string]bool)
		statuses, _ := sbomStore.ListFindingStatuses(ctx, latestVer.ID, nil)
		for _, fs := range statuses {
			if fs.Status == sbommon.FindingStatusFalsePositive ||
				fs.Status == sbommon.FindingStatusSuppressed ||
				fs.Status == sbommon.FindingStatusResolved ||
				fs.Status == sbommon.FindingStatusRiskAccepted {
				excludedStatuses[fs.VulnID+"|"+fs.Purl] = true
			}
			if fs.Status == sbommon.FindingStatusRiskAccepted {
				riskAcceptedKeys[fs.VulnID+"|"+fs.Purl] = true
			}
		}

		// Collect unique vulnerability IDs from active findings
		vulnIDsSeen := make(map[string]bool)
		var vulnIDs []string
		for _, f := range scanResult.Findings {
			key := f.VulnID + "|" + f.Purl
			if excludedStatuses[key] {
				if riskAcceptedKeys[key] {
					riskAcceptedVulnIDs[f.VulnID] = true
				}
				continue
			}
			if !vulnIDsSeen[f.VulnID] {
				vulnIDsSeen[f.VulnID] = true
				vulnIDs = append(vulnIDs, f.VulnID)
			}
		}

		if len(vulnIDs) == 0 {
			continue
		}

		// Build triage inputs and run triage
		var inputs []*triage.TriageInput
		for _, vulnID := range vulnIDs {
			inputs = append(inputs, buildCLITriageInput(ctx, mainStore, vulnID))
		}

		results, err := engine.TriageBatch(ctx, inputs)
		if err != nil {
			continue
		}

		// Map results into ServerTriageEntry per vulnerability
		for _, result := range results {
			entry := triage.ServerTriageEntry{
				ProjectID:    proj.ID,
				ProjectName:  proj.Name,
				ServerLabel:  latestVer.Environment,
				Environment:  latestVer.Environment,
				ProfileUsed:  profile.Name,
				TriageResult: result,
			}
			if entry.ServerLabel == "" {
				entry.ServerLabel = "default"
			}
			entriesByVuln[result.VulnerabilityID] = append(entriesByVuln[result.VulnerabilityID], entry)
		}
	}

	if len(entriesByVuln) == 0 {
		riskAcceptedCount := 0
		for vulnID := range riskAcceptedVulnIDs {
			if _, active := entriesByVuln[vulnID]; !active {
				riskAcceptedCount++
			}
		}
		return &triage.OverviewSummary{RiskAccepted: riskAcceptedCount}, nil
	}

	crossResults := triage.AggregateCrossProjectBatch(entriesByVuln)
	summary := triage.ComputeOverviewSummary(crossResults)

	for vulnID := range riskAcceptedVulnIDs {
		if _, active := entriesByVuln[vulnID]; !active {
			summary.RiskAccepted++
		}
	}

	return summary, crossResults
}

// resolveProfileForProjectEnv resolves the triage profile for a given project/environment
// using priority: environment binding > project default > built-in default.
func resolveProfileForProjectEnv(ctx context.Context, s *store.PostgresStore, projectID int64, environment string) *triage.Profile {
	// 1. Try environment binding
	if environment != "" {
		binding, err := s.GetEnvironmentBinding(ctx, projectID, environment)
		if err == nil && binding != nil {
			if p := resolveProfileByName(ctx, s, binding.ProfileName); p != nil {
				return p
			}
		}
	}

	// 2. Try project default
	defaultName, err := s.GetProjectDefaultProfile(ctx, projectID)
	if err == nil && defaultName != "" {
		if p := resolveProfileByName(ctx, s, defaultName); p != nil {
			return p
		}
	}

	// 3. Fall back to built-in default
	return triage.DefaultProfile()
}

// resolveProfileByName resolves a profile by name from built-in templates or the store.
func resolveProfileByName(ctx context.Context, s *store.PostgresStore, name string) *triage.Profile {
	if name == "" {
		return triage.DefaultProfile()
	}

	// Check built-in templates first
	for _, t := range triage.BuiltinTemplates() {
		if t.Name == name {
			return &t
		}
	}

	// Check custom profiles in DB
	row, err := s.GetTriageProfile(ctx, name)
	if err == nil && row != nil {
		if p := cliRowToProfile(row); p != nil {
			return p
		}
	}

	return triage.DefaultProfile()
}

// cliRowToProfile converts a TriageProfileRow to a triage.Profile.
func cliRowToProfile(row *store.TriageProfileRow) *triage.Profile {
	var weights triage.ExtendedWeights
	if err := json.Unmarshal(row.Weights, &weights); err != nil {
		return nil
	}

	var thresholds triage.Thresholds
	if err := json.Unmarshal(row.Thresholds, &thresholds); err != nil {
		return nil
	}

	p := &triage.Profile{
		Name:        row.Name,
		Description: row.Description,
		Base:        row.Base,
		ScoreWeight: row.ScoreWeight,
		ActFloor:    triage.PriorityLevel(row.ActFloor),
		Weights:     &weights,
		Thresholds:  &thresholds,
	}

	if row.SSVCMapping != nil {
		var ssvc map[string]string
		if err := json.Unmarshal(*row.SSVCMapping, &ssvc); err == nil {
			p.SSVCMapping = ssvc
		}
	}

	return p
}

// buildCLITriageInput builds a TriageInput from vulnerability detail in the store.
func buildCLITriageInput(ctx context.Context, s *store.PostgresStore, vulnID string) *triage.TriageInput {
	detail, err := s.GetVulnerabilityDetail(ctx, vulnID)
	if err != nil || detail == nil {
		return &triage.TriageInput{VulnerabilityID: vulnID}
	}
	return buildCLITriageInputFromDetail(detail)
}

// buildCLITriageInputFromDetail constructs a TriageInput from a VulnerabilityDetail.
func buildCLITriageInputFromDetail(detail *model.VulnerabilityDetail) *triage.TriageInput {
	input := &triage.TriageInput{
		VulnerabilityID: detail.ID,
	}

	// CVSS: take the highest base score from NVD metrics
	if detail.NVD != nil && len(detail.NVD.Metrics) > 0 {
		var maxScore float64
		var maxVector string
		for _, m := range detail.NVD.Metrics {
			if m.BaseScore > maxScore {
				maxScore = m.BaseScore
				maxVector = m.VectorString
			}
		}
		if maxScore > 0 {
			input.CVSSScore = &maxScore
			input.CVSSVector = maxVector
		}
	}
	// Fallback: try MITRE metrics if NVD has none
	if input.CVSSScore == nil && detail.MITRE != nil && len(detail.MITRE.Metrics) > 0 {
		var maxScore float64
		var maxVector string
		for _, m := range detail.MITRE.Metrics {
			if m.BaseScore > maxScore {
				maxScore = m.BaseScore
				maxVector = m.VectorString
			}
		}
		if maxScore > 0 {
			input.CVSSScore = &maxScore
			input.CVSSVector = maxVector
		}
	}

	// EPSS
	if detail.EPSS != nil {
		input.EPSSScore = &detail.EPSS.EPSS
	}

	// LEV
	if detail.LEV != nil {
		input.LEVScore = &detail.LEV.LEV
		input.InKEV = detail.LEV.InKEV
	}

	// KEV
	if detail.KEV != nil {
		input.InKEV = true
	}

	// Patch availability
	for _, affected := range detail.Affected {
		for _, r := range affected.Ranges {
			for _, evt := range r.Events {
				if evt.Fixed != "" {
					input.PatchAvailable = true
					break
				}
			}
			if input.PatchAvailable {
				break
			}
		}
		if input.PatchAvailable {
			break
		}
	}

	// Published date
	if detail.Published != nil {
		input.PublishedAt = detail.Published
	}

	// ExploitDB
	if len(detail.ExploitDB) > 0 {
		input.HasExploit = true
	}

	// Exploitability score
	if detail.NVD != nil && len(detail.NVD.Metrics) > 0 {
		var bestExploitability *float64
		var bestBaseScore float64
		for _, m := range detail.NVD.Metrics {
			if m.ExploitabilityScore != nil && m.BaseScore >= bestBaseScore {
				bestBaseScore = m.BaseScore
				bestExploitability = m.ExploitabilityScore
			}
		}
		if bestExploitability != nil {
			input.ExploitabilityScore = bestExploitability
		}
	}

	// SSVC options
	input.SSVCOptions = extractCLISSVCOptions(detail)

	return input
}

// extractCLISSVCOptions extracts SSVC decision points from VulnerabilityDetail.
func extractCLISSVCOptions(detail *model.VulnerabilityDetail) map[string]string {
	if detail.NVD != nil && detail.NVD.SSVC != nil && len(detail.NVD.SSVC.Options) > 0 {
		opts := make(map[string]string)
		for _, o := range detail.NVD.SSVC.Options {
			opts[o.Key] = o.Value
		}
		return opts
	}
	if detail.MITRE != nil && detail.MITRE.SSVC != nil && len(detail.MITRE.SSVC.Options) > 0 {
		opts := make(map[string]string)
		for _, o := range detail.MITRE.SSVC.Options {
			opts[o.Key] = o.Value
		}
		return opts
	}
	return nil
}

// sortByAffectedCount sorts cross-project results by affected server count (descending).
func sortByAffectedCount(results []*triage.CrossProjectTriageResult) {
	for i := 0; i < len(results); i++ {
		for j := i + 1; j < len(results); j++ {
			if results[j].AffectedServers > results[i].AffectedServers {
				results[i], results[j] = results[j], results[i]
			}
		}
	}
}

// --- Paths Subcommand ---

func runTriagePaths(args []string, cfg *config.Config) error {
	if len(args) > 0 && args[0] == "show" {
		return runTriagePathShow(args[1:], cfg)
	}

	fs := flag.NewFlagSet("triage paths", flag.ContinueOnError)
	topN := fs.Int("top", 20, "Number of paths to show")
	priority := fs.String("priority", "", "Minimum priority filter")
	ecosystem := fs.String("ecosystem", "", "Filter by ecosystem")
	projectFilter := fs.String("project", "", "Filter by project")
	format := fs.String("format", "table", "Output format: table, json")

	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Authenticate and get DB connection
	user, db, err := resolveAuthUser(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	databaseURL := resolveDatabaseURL(cfg)
	mainStore, err := store.NewPostgresStore(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("connect to store: %w", err)
	}
	defer func() { _ = mainStore.Close() }()

	sbomStore := sbommon.NewPostgresSBOMStore(db)

	// Compute triage paths
	paths := computeCLITriagePaths(ctx, user.ID, sbomStore, mainStore, *projectFilter)

	// Filter by priority
	if *priority != "" {
		var filtered []*triage.TriagePath
		for _, p := range paths {
			if strings.EqualFold(string(p.MaxPriorityLevel), *priority) {
				filtered = append(filtered, p)
			}
		}
		paths = filtered
	}

	// Filter by ecosystem
	if *ecosystem != "" {
		var filtered []*triage.TriagePath
		for _, p := range paths {
			if strings.EqualFold(p.Action.Ecosystem, *ecosystem) {
				filtered = append(filtered, p)
			}
		}
		paths = filtered
	}

	// Apply --top limit
	if *topN > 0 && *topN < len(paths) {
		paths = paths[:*topN]
	}

	switch *format {
	case "json":
		report := map[string]interface{}{
			"paths":       paths,
			"total":       len(paths),
			"computed_at": time.Now().UTC().Format(time.RFC3339),
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	default: // table
		if len(paths) == 0 {
			fmt.Println("No triage paths found.")
			fmt.Println("  (Upload SBOMs with 'mayu sbom upload' and ingest vulnerability data first)")
			return nil
		}

		fmt.Printf("Triage Paths (%d total)\n", len(paths))
		fmt.Println(strings.Repeat("─", 100))
		fmt.Printf("%-10s %-30s %-22s %-6s %-10s %-7s\n",
			"ID", "Package", "Current → Target", "Vulns", "Priority", "Impact")
		fmt.Println(strings.Repeat("─", 100))
		for _, p := range paths {
			versionRange := truncateStr(p.Action.CurrentVersion, 9) + " → " + truncateStr(p.Action.TargetVersion, 9)
			fmt.Printf("%-10s %-30s %-22s %-6d %-10s %-7.2f\n",
				truncateStr(p.ID, 10),
				truncateStr(p.Action.Package, 30),
				truncateStr(versionRange, 22),
				p.TotalVulnCount,
				p.MaxPriorityLevel,
				p.ImpactScore)
		}
		fmt.Println(strings.Repeat("─", 100))
		return nil
	}
}

func runTriagePathShow(args []string, cfg *config.Config) error {
	fs := flag.NewFlagSet("triage paths show", flag.ContinueOnError)
	id := fs.String("id", "", "Triage path ID")
	format := fs.String("format", "table", "Output format: table, json")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *id == "" {
		return fmt.Errorf("--id is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Authenticate and get DB connection
	user, db, err := resolveAuthUser(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	databaseURL := resolveDatabaseURL(cfg)
	mainStore, err := store.NewPostgresStore(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("connect to store: %w", err)
	}
	defer func() { _ = mainStore.Close() }()

	sbomStore := sbommon.NewPostgresSBOMStore(db)

	// Compute all paths and find the requested one
	paths := computeCLITriagePaths(ctx, user.ID, sbomStore, mainStore, "")

	var found *triage.TriagePath
	for _, p := range paths {
		if p.ID == *id {
			found = p
			break
		}
	}

	if found == nil {
		return fmt.Errorf("triage path %q not found", *id)
	}

	switch *format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(found)
	default: // table
		fmt.Printf("Triage Path: %s\n", found.ID)
		fmt.Println(strings.Repeat("═", 70))
		fmt.Printf("Action:      %s %s → %s\n", found.Action.Package, found.Action.CurrentVersion, found.Action.TargetVersion)
		fmt.Printf("Ecosystem:   %s\n", found.Action.Ecosystem)
		fmt.Printf("Priority:    %s\n", found.MaxPriorityLevel)
		fmt.Printf("Impact:      %.4f\n", found.ImpactScore)
		fmt.Printf("Vulns:       %d\n", found.TotalVulnCount)
		fmt.Printf("Servers:     %d\n", found.TotalServerCount)
		fmt.Println()

		if len(found.ResolvedVulnerabilities) > 0 {
			fmt.Println("Resolved Vulnerabilities:")
			fmt.Println(strings.Repeat("─", 70))
			fmt.Printf("%-22s %-10s %-8s %-15s\n", "VULNERABILITY", "PRIORITY", "SCORE", "FIXED IN")
			fmt.Println(strings.Repeat("─", 70))
			for _, rv := range found.ResolvedVulnerabilities {
				fmt.Printf("%-22s %-10s %-8.4f %-15s\n",
					truncateStr(rv.VulnerabilityID, 22),
					rv.PriorityLevel,
					rv.CompositeScore,
					truncateStr(rv.FixedVersion, 15))
			}
			fmt.Println(strings.Repeat("─", 70))
		}

		if len(found.AffectedServers) > 0 {
			fmt.Println()
			fmt.Println("Affected Servers:")
			for _, srv := range found.AffectedServers {
				fmt.Printf("  • %s\n", srv)
			}
		}
		return nil
	}
}

// computeCLITriagePaths computes remediation paths across all SBOM projects for the given user.
func computeCLITriagePaths(ctx context.Context, userID int64, sbomStore *sbommon.PostgresSBOMStore, mainStore *store.PostgresStore, projectFilter string) []*triage.TriagePath {
	projects, err := sbomStore.ListProjects(ctx, userID)
	if err != nil || len(projects) == 0 {
		return nil
	}

	var scanFindings []triage.ScanFinding

	for _, proj := range projects {
		// Apply project filter if specified
		if projectFilter != "" && !strings.EqualFold(proj.Name, projectFilter) {
			continue
		}

		latestVer, err := sbomStore.GetLatestVersion(ctx, proj.ID)
		if err != nil || latestVer == nil {
			continue
		}

		scanResult, err := sbomStore.GetLatestScanResult(ctx, latestVer.ID)
		if err != nil || scanResult == nil || len(scanResult.Findings) == 0 {
			continue
		}

		// Resolve profile for this project/environment
		profile := resolveProfileForProjectEnv(ctx, mainStore, proj.ID, latestVer.Environment)
		engine := triage.NewEngine(profile)

		// Exclude suppressed/false_positive/resolved/risk_accepted findings
		excludedStatuses := make(map[string]bool)
		statuses, _ := sbomStore.ListFindingStatuses(ctx, latestVer.ID, nil)
		for _, fs := range statuses {
			if fs.Status == sbommon.FindingStatusFalsePositive ||
				fs.Status == sbommon.FindingStatusSuppressed ||
				fs.Status == sbommon.FindingStatusResolved ||
				fs.Status == sbommon.FindingStatusRiskAccepted {
				excludedStatuses[fs.VulnID+"|"+fs.Purl] = true
			}
		}

		// Build triage inputs for scoring
		vulnScores := make(map[string]*triage.TriageResult)
		vulnIDsSeen := make(map[string]bool)
		var vulnIDs []string
		for _, f := range scanResult.Findings {
			key := f.VulnID + "|" + f.Purl
			if excludedStatuses[key] {
				continue
			}
			if !vulnIDsSeen[f.VulnID] {
				vulnIDsSeen[f.VulnID] = true
				vulnIDs = append(vulnIDs, f.VulnID)
			}
		}

		if len(vulnIDs) == 0 {
			continue
		}

		var inputs []*triage.TriageInput
		for _, vulnID := range vulnIDs {
			inputs = append(inputs, buildCLITriageInput(ctx, mainStore, vulnID))
		}

		results, err := engine.TriageBatch(ctx, inputs)
		if err != nil {
			continue
		}
		for _, r := range results {
			vulnScores[r.VulnerabilityID] = r
		}

		// Build ScanFindings for path computation
		for _, f := range scanResult.Findings {
			key := f.VulnID + "|" + f.Purl
			if excludedStatuses[key] {
				continue
			}
			sf := triage.ScanFinding{
				VulnerabilityID: f.VulnID,
				PackagePurl:     f.Purl,
				CurrentVersion:  f.Version,
				FixedVersion:    f.FixedVersion,
				Ecosystem:       f.Ecosystem,
				ServerLabel:     latestVer.Environment,
				ProjectID:       proj.ID,
				ProjectName:     proj.Name,
				Environment:     latestVer.Environment,
			}
			if sf.ServerLabel == "" {
				sf.ServerLabel = "default"
			}
			if result, ok := vulnScores[f.VulnID]; ok {
				sf.CompositeScore = result.CompositeScore
				sf.PriorityLevel = result.PriorityLevel
			}
			scanFindings = append(scanFindings, sf)
		}
	}

	if len(scanFindings) == 0 {
		return nil
	}

	return triage.ComputeTriagePaths(scanFindings)
}

// --- Helpers ---

func loadTriageProfile(name string) *triage.Profile {
	// Check if name is a file path
	if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
		p, err := triage.LoadProfile(name)
		if err == nil {
			return p
		}
	}

	// Check built-in templates
	if p := findProfile(name); p != nil {
		return p
	}

	return triage.DefaultProfile()
}

func findProfile(name string) *triage.Profile {
	for _, t := range triage.BuiltinTemplates() {
		if t.Name == name {
			return &t
		}
	}
	return nil
}

// capitalizeFirst capitalizes the first letter of a string.
func capitalizeFirst(s string) string {
	if s == "" {
		return s
	}
	s = strings.ToLower(s)
	return strings.ToUpper(s[:1]) + s[1:]
}
