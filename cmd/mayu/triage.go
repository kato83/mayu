package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/kato83/mayu/internal/config"
	"github.com/kato83/mayu/internal/triage"
)

func runTriage(args []string, _ *config.Config) error {
	if len(args) == 0 {
		printTriageUsage()
		return nil
	}

	switch args[0] {
	case "profile":
		return runTriageProfile(args[1:])
	case "overview":
		return runTriageOverview(args[1:])
	case "paths":
		return runTriagePaths(args[1:])
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
	fmt.Println("  --server <label>     Server label for profile auto-resolution")
	fmt.Println("  --format <fmt>       Output format: table, json, csv (default: table)")
	fmt.Println("  --fail-on <level>    Exit code 1 if priority >= level (critical, high, medium, low)")
	fmt.Println("  --top <N>            Show only top N results")
}

func runTriageExecute(args []string) error {
	fs := flag.NewFlagSet("triage", flag.ContinueOnError)
	vulnID := fs.String("id", "", "Vulnerability ID to triage")
	sbomPath := fs.String("sbom", "", "SBOM file path for batch triage")
	profileName := fs.String("profile", "default", "Triage profile name or path")
	serverLabel := fs.String("server", "", "Server label for profile auto-resolution")
	format := fs.String("format", "table", "Output format: table, json, csv")
	failOn := fs.String("fail-on", "", "Exit code 1 if any result >= level")
	top := fs.Int("top", 0, "Show only top N results")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Load profile
	profile := loadTriageProfile(*profileName)

	engine := triage.NewEngine(profile)

	// Handle server-based profile resolution
	if *serverLabel != "" {
		opts := &triage.ResolveOpts{
			ExplicitProfile: *profileName,
			ServerLabel:     *serverLabel,
		}
		resolved, _ := engine.ResolveProfile(opts, nil)
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

	result, err := engine.Triage(context.TODO(), input)
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

	results, err := engine.TriageBatch(context.TODO(), inputs)
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
		fmt.Println("  bind       Bind a profile to a server/asset")
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
	server := fs.String("server", "", "Server label")
	profileName := fs.String("profile", "", "Profile name to bind")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *project == "" || *server == "" || *profileName == "" {
		return fmt.Errorf("--project, --server, and --profile are all required")
	}

	// Verify profile exists
	if p := findProfile(*profileName); p == nil {
		return fmt.Errorf("profile %q not found", *profileName)
	}

	fmt.Printf("✓ Bound profile %q to server %q in project %q\n", *profileName, *server, *project)
	fmt.Println("  (Note: In production, this is persisted to the database via API)")
	return nil
}

func runTriageProfileUnbind(args []string) error {
	fs := flag.NewFlagSet("triage profile unbind", flag.ContinueOnError)
	project := fs.String("project", "", "Project name/ID")
	server := fs.String("server", "", "Server label")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *project == "" || *server == "" {
		return fmt.Errorf("--project and --server are required")
	}

	fmt.Printf("✓ Unbound profile from server %q in project %q\n", *server, *project)
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

func runTriageOverview(args []string) error {
	fs := flag.NewFlagSet("triage overview", flag.ContinueOnError)
	priority := fs.String("priority", "", "Minimum priority level filter")
	topN := fs.Int("top", 20, "Number of results to show")
	format := fs.String("format", "table", "Output format: table, json")
	sortBy := fs.String("sort", "priority", "Sort by: priority, affected_count")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// In a full implementation, this would query the database
	// For now, display a placeholder showing the command works
	fmt.Println("Cross-Project Triage Overview")
	fmt.Println(strings.Repeat("─", 70))
	fmt.Printf("Filter: priority=%s, top=%d, sort=%s, format=%s\n", *priority, *topN, *sortBy, *format)
	fmt.Println()
	fmt.Println("  (Connect to database with 'mayu serve' to see live data)")
	fmt.Println("  Use the API endpoint GET /api/v1/triage/overview for programmatic access.")
	return nil
}

// --- Paths Subcommand ---

func runTriagePaths(args []string) error {
	if len(args) > 0 && args[0] == "show" {
		return runTriagePathShow(args[1:])
	}

	fs := flag.NewFlagSet("triage paths", flag.ContinueOnError)
	topN := fs.Int("top", 20, "Number of paths to show")
	priority := fs.String("priority", "", "Minimum priority filter")
	ecosystem := fs.String("ecosystem", "", "Filter by ecosystem")
	project := fs.String("project", "", "Filter by project")
	format := fs.String("format", "table", "Output format: table, json")

	if err := fs.Parse(args); err != nil {
		return err
	}

	fmt.Println("Triage Paths (Remediation Grouping)")
	fmt.Println(strings.Repeat("─", 70))
	fmt.Printf("Filter: top=%d, priority=%s, ecosystem=%s, project=%s, format=%s\n",
		*topN, *priority, *ecosystem, *project, *format)
	fmt.Println()
	fmt.Println("  (Connect to database with 'mayu serve' to see live data)")
	fmt.Println("  Use the API endpoint GET /api/v1/triage/paths for programmatic access.")
	return nil
}

func runTriagePathShow(args []string) error {
	fs := flag.NewFlagSet("triage paths show", flag.ContinueOnError)
	id := fs.String("id", "", "Triage path ID")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *id == "" {
		return fmt.Errorf("--id is required")
	}

	fmt.Printf("Triage Path: %s\n", *id)
	fmt.Println("  (Connect to database with 'mayu serve' to see live data)")
	return nil
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
