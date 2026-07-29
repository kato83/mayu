package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/kato83/mayu/internal/audit"
	"github.com/kato83/mayu/internal/config"
	"github.com/kato83/mayu/internal/policy"
	"github.com/kato83/mayu/internal/sbom"
	"github.com/kato83/mayu/internal/store"
	"github.com/kato83/mayu/internal/vex"
)

// auditPolicyResult pairs a finding with its policy evaluation outcome.
type auditPolicyResult struct {
	Finding audit.Finding
	Action  policy.Action
	Policy  string
}

func runAudit(args []string, cfg *config.Config) (int, error) {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)

	sbomPath := fs.String("sbom", "", "Path to SBOM file (CycloneDX 1.7 or SPDX 2.3 JSON)")
	format := fs.String("format", "table", "Output format: table, json, csv, sarif")
	includeDev := fs.Bool("include-dev", false, "Include development dependencies in audit")
	noVersionCheck := fs.Bool("no-version-check", false, "Skip version matching, report all vulnerabilities for package name")
	failOn := fs.String("fail-on", "", "Fail with exit code 1 only for findings at or above severity (e.g., critical,high)")
	ignorePath := fs.String("ignore", "", "Path to ignore file containing vulnerability IDs to suppress")
	vexPath := fs.String("vex", "", "Path to OpenVEX file to suppress not_affected findings")
	policyPath := fs.String("policy", "", "Path to policy YAML file for custom gating (block/warn/suppress)")

	fs.Usage = func() {
		fmt.Println("Usage: mayu audit [options]")
		fmt.Println()
		fmt.Println("Audit an SBOM for known vulnerabilities.")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Supported SBOM formats:")
		fmt.Println("  - CycloneDX 1.7 (JSON)")
		fmt.Println("  - SPDX 2.3 (JSON)")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  mayu audit --sbom ./sbom.cdx.json")
		fmt.Println("  mayu audit --sbom ./sbom.spdx.json --include-dev")
		fmt.Println("  mayu audit --sbom ./sbom.cdx.json --no-version-check")
		fmt.Println("  mayu audit --sbom ./sbom.cdx.json --format json")
		fmt.Println("  mayu audit --sbom ./sbom.cdx.json --format csv")
		fmt.Println("  mayu audit --sbom ./sbom.cdx.json --format sarif > results.sarif")
		fmt.Println("  mayu audit --sbom ./sbom.cdx.json --fail-on critical,high")
		fmt.Println("  mayu audit --sbom ./sbom.cdx.json --fail-on critical --ignore .mayu-ignore")
		fmt.Println("  mayu audit --sbom ./sbom.cdx.json --vex product.vex.json")
		fmt.Println("  mayu audit --sbom ./sbom.cdx.json --policy policy.yaml")
	}

	if err := fs.Parse(args); err != nil {
		return 2, err
	}

	if *sbomPath == "" {
		return 2, fmt.Errorf("--sbom is required")
	}

	// Validate --fail-on early before any I/O
	var failOnLevel int
	if *failOn != "" {
		level, err := audit.ParseFailOn(*failOn)
		if err != nil {
			return 2, err
		}
		failOnLevel = level
	}

	// Load and validate policy file early before any I/O
	var policyEval *policy.Evaluator
	if *policyPath != "" {
		pf, err := policy.LoadFile(*policyPath)
		if err != nil {
			return 2, err
		}
		if errs := policy.Validate(pf); len(errs) > 0 {
			for _, e := range errs {
				fmt.Fprintf(os.Stderr, "policy validation: %v\n", e)
			}
			return 2, fmt.Errorf("policy file has %d validation error(s)", len(errs))
		}
		policyEval = policy.NewEvaluator(pf)
	}

	// Read SBOM file
	data, err := os.ReadFile(*sbomPath)
	if err != nil {
		return 2, fmt.Errorf("read SBOM file: %w", err)
	}

	// Parse SBOM
	bom, err := sbom.Parse(data)
	if err != nil {
		return 2, fmt.Errorf("parse SBOM: %w", err)
	}

	// Resolve database URL
	databaseURL := resolveDatabaseURL(cfg)

	// Setup context with signal handling
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Connect to database
	s, err := store.NewPostgresStore(ctx, databaseURL)
	if err != nil {
		return 2, fmt.Errorf("connect to database: %w", err)
	}
	defer func() { _ = s.Close() }()

	// Run audit
	auditor := audit.NewAuditor(s)
	result, err := auditor.Audit(ctx, bom.Components, audit.AuditOptions{
		IncludeDev:     *includeDev,
		NoVersionCheck: *noVersionCheck,
	})
	if err != nil {
		return 2, fmt.Errorf("audit: %w", err)
	}

	// Apply ignore file filtering
	if *ignorePath != "" {
		ignored, err := audit.ParseIgnoreFile(*ignorePath)
		if err != nil {
			return 2, fmt.Errorf("parse ignore file: %w", err)
		}
		result.Findings = audit.FilterFindings(result.Findings, ignored)

		// Recalculate VulnerablePackages from remaining findings
		pkgSet := make(map[string]bool)
		for _, f := range result.Findings {
			pkgSet[f.Component.Ecosystem+"/"+f.Component.Name+"/"+f.Component.Version] = true
		}
		result.VulnerablePackages = len(pkgSet)
	}

	// Apply VEX filtering
	if *vexPath != "" {
		vexData, err := os.ReadFile(*vexPath)
		if err != nil {
			return 2, fmt.Errorf("read VEX file: %w", err)
		}
		result.Findings, err = vex.FilterFindingsByVEX(result.Findings, vexData)
		if err != nil {
			return 2, fmt.Errorf("apply VEX filter: %w", err)
		}

		// Recalculate VulnerablePackages from remaining findings
		pkgSet := make(map[string]bool)
		for _, f := range result.Findings {
			pkgSet[f.Component.Ecosystem+"/"+f.Component.Name+"/"+f.Component.Version] = true
		}
		result.VulnerablePackages = len(pkgSet)
	}

	// Apply policy evaluation
	var policyResults []auditPolicyResult
	var hasBlock bool

	if policyEval != nil {
		for _, f := range result.Findings {
			ctx := policy.FindingContext{
				Severity:  f.Severity,
				HasFix:    f.FixedVersion != "",
				Ecosystem: f.Component.Ecosystem,
			}
			evalResult := policyEval.Evaluate(ctx)
			if evalResult.Action == policy.ActionSuppress {
				continue // excluded from output
			}
			if evalResult.Action == policy.ActionBlock {
				hasBlock = true
			}
			policyResults = append(policyResults, auditPolicyResult{
				Finding: f,
				Action:  evalResult.Action,
				Policy:  evalResult.PolicyName,
			})
		}

		// Recalculate findings (remove suppressed)
		filtered := make([]audit.Finding, 0, len(policyResults))
		for _, pr := range policyResults {
			filtered = append(filtered, pr.Finding)
		}
		result.Findings = filtered

		// Recalculate VulnerablePackages from remaining findings
		pkgSet := make(map[string]bool)
		for _, f := range result.Findings {
			pkgSet[f.Component.Ecosystem+"/"+f.Component.Name+"/"+f.Component.Version] = true
		}
		result.VulnerablePackages = len(pkgSet)
	}

	// Output results
	switch *format {
	case "json":
		if policyEval != nil {
			outputAuditJSONWithPolicy(result, policyResults)
		} else {
			outputAuditJSON(result)
		}
	case "csv":
		if policyEval != nil {
			outputAuditCSVWithPolicy(result, policyResults)
		} else {
			outputAuditCSV(result)
		}
	case "table":
		if policyEval != nil {
			outputAuditTableWithPolicy(result, bom.Format, policyResults)
		} else {
			outputAuditTable(result, bom.Format)
		}
	case "sarif":
		data, err := audit.GenerateSARIF(result, version)
		if err != nil {
			return 2, fmt.Errorf("generate SARIF: %w", err)
		}
		fmt.Println(string(data))
	default:
		return 2, fmt.Errorf("unknown format: %q (supported: table, json, csv, sarif)", *format)
	}

	// Exit code logic
	// Policy --policy takes precedence for block decisions
	if policyEval != nil {
		// Also check --fail-on if specified (both apply)
		if *failOn != "" && audit.ShouldFail(result.Findings, failOnLevel) {
			return 1, nil
		}
		if hasBlock {
			return 1, nil
		}
		return 0, nil
	}

	if *failOn != "" {
		if audit.ShouldFail(result.Findings, failOnLevel) {
			return 1, nil
		}
		return 0, nil
	}

	// Default behavior: exit 1 if any findings
	if len(result.Findings) > 0 {
		return 1, nil
	}
	return 0, nil
}

func outputAuditTable(result *audit.AuditResult, sbomFormat string) {
	fmt.Printf("\n=== SBOM Audit Results (format: %s) ===\n\n", sbomFormat)

	if len(result.Findings) == 0 {
		fmt.Printf("✓ No vulnerabilities found (%d packages audited)\n", result.TotalPackages)
		return
	}

	// Header
	fmt.Printf("%-40s %-12s %-20s %-10s %-14s %s\n", "PACKAGE", "VERSION", "VULN ID", "SEVERITY", "FIXED", "SUMMARY")
	fmt.Printf("%-40s %-12s %-20s %-10s %-14s %s\n",
		strings.Repeat("-", 40),
		strings.Repeat("-", 12),
		strings.Repeat("-", 20),
		strings.Repeat("-", 10),
		strings.Repeat("-", 14),
		strings.Repeat("-", 40))

	for _, f := range result.Findings {
		pkg := truncateString(f.Component.Name, 40)
		ver := truncateString(f.Component.Version, 12)
		vulnID := truncateString(f.VulnID, 20)
		fixed := truncateString(f.FixedVersion, 14)
		summary := truncateString(f.Summary, 60)
		fmt.Printf("%-40s %-12s %-20s %-10s %-14s %s\n", pkg, ver, vulnID, f.Severity, fixed, summary)
	}

	fmt.Printf("\n✗ %d vulnerability finding(s) in %d package(s) (%d total packages audited)\n",
		len(result.Findings), result.VulnerablePackages, result.TotalPackages)
}

func outputAuditJSON(result *audit.AuditResult) {
	type jsonFinding struct {
		Package      string   `json:"package"`
		Version      string   `json:"version"`
		Ecosystem    string   `json:"ecosystem"`
		VulnID       string   `json:"vuln_id"`
		Aliases      []string `json:"aliases,omitempty"`
		Severity     string   `json:"severity"`
		Summary      string   `json:"summary"`
		FixedVersion string   `json:"fixed_version,omitempty"`
	}

	type jsonOutput struct {
		Findings []jsonFinding `json:"findings"`
		Summary  struct {
			TotalPackages      int `json:"total_packages"`
			VulnerablePackages int `json:"vulnerable_packages"`
			TotalFindings      int `json:"total_findings"`
		} `json:"summary"`
	}

	out := jsonOutput{}
	for _, f := range result.Findings {
		out.Findings = append(out.Findings, jsonFinding{
			Package:      f.Component.Name,
			Version:      f.Component.Version,
			Ecosystem:    f.Component.Ecosystem,
			VulnID:       f.VulnID,
			Aliases:      f.Aliases,
			Severity:     f.Severity,
			Summary:      f.Summary,
			FixedVersion: f.FixedVersion,
		})
	}
	out.Summary.TotalPackages = result.TotalPackages
	out.Summary.VulnerablePackages = result.VulnerablePackages
	out.Summary.TotalFindings = len(result.Findings)

	data, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(data))
}

func outputAuditCSV(result *audit.AuditResult) {
	fmt.Println("package,version,ecosystem,vuln_id,severity,fixed_version,summary")
	for _, f := range result.Findings {
		fmt.Printf("%s,%s,%s,%s,%s,%s,%s\n",
			csvEscape(f.Component.Name),
			csvEscape(f.Component.Version),
			csvEscape(f.Component.Ecosystem),
			csvEscape(f.VulnID),
			csvEscape(f.Severity),
			csvEscape(f.FixedVersion),
			csvEscape(f.Summary),
		)
	}
}

func outputAuditTableWithPolicy(result *audit.AuditResult, sbomFormat string, policyResults []auditPolicyResult) {
	fmt.Printf("\n=== SBOM Audit Results (format: %s) ===\n\n", sbomFormat)

	if len(policyResults) == 0 {
		fmt.Printf("✓ No vulnerabilities found (%d packages audited)\n", result.TotalPackages)
		return
	}

	// Header with ACTION column
	fmt.Printf("%-40s %-12s %-20s %-10s %-10s %-14s %s\n", "PACKAGE", "VERSION", "VULN ID", "SEVERITY", "ACTION", "FIXED", "SUMMARY")
	fmt.Printf("%-40s %-12s %-20s %-10s %-10s %-14s %s\n",
		strings.Repeat("-", 40),
		strings.Repeat("-", 12),
		strings.Repeat("-", 20),
		strings.Repeat("-", 10),
		strings.Repeat("-", 10),
		strings.Repeat("-", 14),
		strings.Repeat("-", 40))

	for _, pr := range policyResults {
		f := pr.Finding
		pkg := truncateString(f.Component.Name, 40)
		ver := truncateString(f.Component.Version, 12)
		vulnID := truncateString(f.VulnID, 20)
		fixed := truncateString(f.FixedVersion, 14)
		summary := truncateString(f.Summary, 60)
		action := strings.ToUpper(string(pr.Action))
		fmt.Printf("%-40s %-12s %-20s %-10s %-10s %-14s %s\n", pkg, ver, vulnID, f.Severity, action, fixed, summary)
	}

	// Count by action
	var blocks, warns, allows int
	for _, pr := range policyResults {
		switch pr.Action {
		case policy.ActionBlock:
			blocks++
		case policy.ActionWarn:
			warns++
		case policy.ActionAllow:
			allows++
		}
	}

	fmt.Printf("\n✗ %d finding(s) in %d package(s) (%d total packages audited)\n",
		len(policyResults), result.VulnerablePackages, result.TotalPackages)
	fmt.Printf("  Policy: %d blocked, %d warned, %d allowed\n", blocks, warns, allows)
}

func outputAuditJSONWithPolicy(result *audit.AuditResult, policyResults []auditPolicyResult) {
	type jsonFinding struct {
		Package      string   `json:"package"`
		Version      string   `json:"version"`
		Ecosystem    string   `json:"ecosystem"`
		VulnID       string   `json:"vuln_id"`
		Aliases      []string `json:"aliases,omitempty"`
		Severity     string   `json:"severity"`
		Summary      string   `json:"summary"`
		FixedVersion string   `json:"fixed_version,omitempty"`
		Action       string   `json:"action"`
		PolicyName   string   `json:"policy_name,omitempty"`
	}

	type jsonOutput struct {
		Findings []jsonFinding `json:"findings"`
		Summary  struct {
			TotalPackages      int `json:"total_packages"`
			VulnerablePackages int `json:"vulnerable_packages"`
			TotalFindings      int `json:"total_findings"`
			Blocked            int `json:"blocked"`
			Warned             int `json:"warned"`
			Allowed            int `json:"allowed"`
		} `json:"summary"`
	}

	out := jsonOutput{}
	for _, pr := range policyResults {
		f := pr.Finding
		out.Findings = append(out.Findings, jsonFinding{
			Package:      f.Component.Name,
			Version:      f.Component.Version,
			Ecosystem:    f.Component.Ecosystem,
			VulnID:       f.VulnID,
			Aliases:      f.Aliases,
			Severity:     f.Severity,
			Summary:      f.Summary,
			FixedVersion: f.FixedVersion,
			Action:       string(pr.Action),
			PolicyName:   pr.Policy,
		})
		switch pr.Action {
		case policy.ActionBlock:
			out.Summary.Blocked++
		case policy.ActionWarn:
			out.Summary.Warned++
		case policy.ActionAllow:
			out.Summary.Allowed++
		}
	}
	out.Summary.TotalPackages = result.TotalPackages
	out.Summary.VulnerablePackages = result.VulnerablePackages
	out.Summary.TotalFindings = len(policyResults)

	data, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(data))
}

func outputAuditCSVWithPolicy(result *audit.AuditResult, policyResults []auditPolicyResult) {
	fmt.Println("package,version,ecosystem,vuln_id,severity,action,policy_name,fixed_version,summary")
	for _, pr := range policyResults {
		f := pr.Finding
		fmt.Printf("%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
			csvEscape(f.Component.Name),
			csvEscape(f.Component.Version),
			csvEscape(f.Component.Ecosystem),
			csvEscape(f.VulnID),
			csvEscape(f.Severity),
			csvEscape(string(pr.Action)),
			csvEscape(pr.Policy),
			csvEscape(f.FixedVersion),
			csvEscape(f.Summary),
		)
	}
}
