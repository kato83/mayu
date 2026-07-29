package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/kato83/mayu/internal/audit"
	"github.com/kato83/mayu/internal/config"
	"github.com/kato83/mayu/internal/lockfile"
	"github.com/kato83/mayu/internal/policy"
	"github.com/kato83/mayu/internal/sbom"
	"github.com/kato83/mayu/internal/store"
)

// scanPolicyResult pairs a finding with its policy evaluation outcome.
type scanPolicyResult struct {
	Finding audit.Finding
	Action  policy.Action
	Policy  string
}

func runScan(args []string, cfg *config.Config) (int, error) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)

	lockfilePath := fs.String("lockfile", "", "Path to a lockfile to scan")
	dirPath := fs.String("dir", "", "Directory to scan for lockfiles")
	format := fs.String("format", "table", "Output format: table, json, csv, sarif")
	failOn := fs.String("fail-on", "", "Fail with exit code 1 only for findings at or above severity (e.g., critical,high)")
	ignorePath := fs.String("ignore", "", "Path to ignore file containing vulnerability IDs to suppress")
	includeDev := fs.Bool("include-dev", false, "Include development dependencies in scan")
	noVersionCheck := fs.Bool("no-version-check", false, "Skip version matching, report all vulnerabilities for package name")
	policyPath := fs.String("policy", "", "Path to policy YAML file for custom gating (block/warn/suppress)")

	fs.Usage = func() {
		fmt.Println("Usage: mayu scan [options]")
		fmt.Println()
		fmt.Println("Scan lockfiles for known vulnerabilities.")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Supported lockfile formats:")
		fmt.Println("  - go.sum (Go)")
		fmt.Println("  - package-lock.json (npm)")
		fmt.Println("  - yarn.lock (Yarn)")
		fmt.Println("  - pnpm-lock.yaml (pnpm)")
		fmt.Println("  - Pipfile.lock (Python/pipenv)")
		fmt.Println("  - poetry.lock (Python/poetry)")
		fmt.Println("  - Gemfile.lock (Ruby)")
		fmt.Println("  - Cargo.lock (Rust)")
		fmt.Println("  - requirements.txt (Python/pip)")
		fmt.Println("  - composer.lock (PHP)")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  mayu scan --lockfile ./go.sum")
		fmt.Println("  mayu scan --dir .")
		fmt.Println("  mayu scan --lockfile ./package-lock.json --format json")
		fmt.Println("  mayu scan --dir . --fail-on critical,high")
		fmt.Println("  mayu scan --lockfile ./Cargo.lock --ignore .mayu-ignore")
	}

	if err := fs.Parse(args); err != nil {
		return 2, err
	}

	if *lockfilePath == "" && *dirPath == "" {
		return 2, fmt.Errorf("either --lockfile or --dir is required")
	}

	if *lockfilePath != "" && *dirPath != "" {
		return 2, fmt.Errorf("--lockfile and --dir are mutually exclusive")
	}

	// Validate --fail-on early
	var failOnLevel int
	if *failOn != "" {
		level, err := audit.ParseFailOn(*failOn)
		if err != nil {
			return 2, err
		}
		failOnLevel = level
	}

	// Load and validate policy file early
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

	// Collect lockfiles to parse
	var lockfiles []string
	if *lockfilePath != "" {
		lockfiles = []string{*lockfilePath}
	} else {
		found, err := lockfile.FindLockfiles(*dirPath)
		if err != nil {
			return 2, fmt.Errorf("scan directory: %w", err)
		}
		if len(found) == 0 {
			return 2, fmt.Errorf("no recognized lockfiles found in %q", *dirPath)
		}
		lockfiles = found
	}

	// Parse all lockfiles into components
	var allComponents []sbom.Component
	for _, path := range lockfiles {
		components, err := parseLockfile(path)
		if err != nil {
			return 2, fmt.Errorf("parse %s: %w", filepath.Base(path), err)
		}
		allComponents = append(allComponents, components...)
	}

	if len(allComponents) == 0 {
		fmt.Println("No packages found in lockfile(s).")
		return 0, nil
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

	// Run audit using the existing auditor
	auditor := audit.NewAuditor(s)
	result, err := auditor.Audit(ctx, allComponents, audit.AuditOptions{
		IncludeDev:     *includeDev,
		NoVersionCheck: *noVersionCheck,
	})
	if err != nil {
		return 2, fmt.Errorf("scan: %w", err)
	}

	// Apply ignore file filtering
	if *ignorePath != "" {
		ignored, err := audit.ParseIgnoreFile(*ignorePath)
		if err != nil {
			return 2, fmt.Errorf("parse ignore file: %w", err)
		}
		result.Findings = audit.FilterFindings(result.Findings, ignored)

		// Recalculate VulnerablePackages
		pkgSet := make(map[string]bool)
		for _, f := range result.Findings {
			pkgSet[f.Component.Ecosystem+"/"+f.Component.Name+"/"+f.Component.Version] = true
		}
		result.VulnerablePackages = len(pkgSet)
	}

	// Apply policy evaluation
	var policyResults []scanPolicyResult
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
				continue
			}
			if evalResult.Action == policy.ActionBlock {
				hasBlock = true
			}
			policyResults = append(policyResults, scanPolicyResult{
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

		pkgSet := make(map[string]bool)
		for _, f := range result.Findings {
			pkgSet[f.Component.Ecosystem+"/"+f.Component.Name+"/"+f.Component.Version] = true
		}
		result.VulnerablePackages = len(pkgSet)
	}

	// Output results
	var formatLabel string
	if len(lockfiles) == 1 {
		formatLabel = filepath.Base(lockfiles[0])
	} else {
		formatLabel = fmt.Sprintf("%d lockfiles", len(lockfiles))
	}

	switch *format {
	case "json":
		if policyEval != nil {
			outputScanJSONWithPolicy(result, policyResults)
		} else {
			outputAuditJSON(result)
		}
	case "csv":
		if policyEval != nil {
			outputScanCSVWithPolicy(policyResults)
		} else {
			outputAuditCSV(result)
		}
	case "table":
		if policyEval != nil {
			outputScanTableWithPolicy(result, formatLabel, policyResults)
		} else {
			outputScanTable(result, formatLabel)
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
	if policyEval != nil {
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

func outputScanTable(result *audit.AuditResult, source string) {
	fmt.Printf("\n=== Lockfile Scan Results (source: %s) ===\n\n", source)

	if len(result.Findings) == 0 {
		fmt.Printf("✓ No vulnerabilities found (%d packages scanned)\n", result.TotalPackages)
		return
	}

	fmt.Printf("%-40s %-12s %-20s %-10s %-14s %s\n", "PACKAGE", "VERSION", "VULN ID", "SEVERITY", "FIXED", "SUMMARY")
	fmt.Printf("%-40s %-12s %-20s %-10s %-14s %s\n",
		"----------------------------------------",
		"------------",
		"--------------------",
		"----------",
		"--------------",
		"----------------------------------------")

	for _, f := range result.Findings {
		pkg := truncateString(f.Component.Name, 40)
		ver := truncateString(f.Component.Version, 12)
		vulnID := truncateString(f.VulnID, 20)
		fixed := truncateString(f.FixedVersion, 14)
		summary := truncateString(f.Summary, 60)
		fmt.Printf("%-40s %-12s %-20s %-10s %-14s %s\n", pkg, ver, vulnID, f.Severity, fixed, summary)
	}

	fmt.Printf("\n✗ %d vulnerability finding(s) in %d package(s) (%d total packages scanned)\n",
		len(result.Findings), result.VulnerablePackages, result.TotalPackages)
}

func parseLockfile(path string) ([]sbom.Component, error) {
	parser, err := lockfile.Detect(path)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer func() { _ = f.Close() }()

	return parser.Parse(filepath.Base(path), f)
}

func outputScanTableWithPolicy(result *audit.AuditResult, source string, policyResults []scanPolicyResult) {
	fmt.Printf("\n=== Lockfile Scan Results (source: %s) ===\n\n", source)

	if len(policyResults) == 0 {
		fmt.Printf("✓ No vulnerabilities found (%d packages scanned)\n", result.TotalPackages)
		return
	}

	fmt.Printf("%-40s %-12s %-20s %-10s %-10s %-14s %s\n", "PACKAGE", "VERSION", "VULN ID", "SEVERITY", "ACTION", "FIXED", "SUMMARY")
	fmt.Printf("%-40s %-12s %-20s %-10s %-10s %-14s %s\n",
		"----------------------------------------",
		"------------",
		"--------------------",
		"----------",
		"----------",
		"--------------",
		"----------------------------------------")

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

	fmt.Printf("\n✗ %d finding(s) in %d package(s) (%d total packages scanned)\n",
		len(policyResults), result.VulnerablePackages, result.TotalPackages)
	fmt.Printf("  Policy: %d blocked, %d warned, %d allowed\n", blocks, warns, allows)
}

func outputScanJSONWithPolicy(result *audit.AuditResult, policyResults []scanPolicyResult) {
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

func outputScanCSVWithPolicy(policyResults []scanPolicyResult) {
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
