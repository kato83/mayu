package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/kato83/mayu/internal/audit"
	"github.com/kato83/mayu/internal/config"
	"github.com/kato83/mayu/internal/lockfile"
	"github.com/kato83/mayu/internal/sbom"
	"github.com/kato83/mayu/internal/store"
)

func runScan(args []string, cfg *config.Config) (int, error) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)

	lockfilePath := fs.String("lockfile", "", "Path to a lockfile to scan")
	dirPath := fs.String("dir", "", "Directory to scan for lockfiles")
	format := fs.String("format", "table", "Output format: table, json, csv, sarif")
	failOn := fs.String("fail-on", "", "Fail with exit code 1 only for findings at or above severity (e.g., critical,high)")
	ignorePath := fs.String("ignore", "", "Path to ignore file containing vulnerability IDs to suppress")
	includeDev := fs.Bool("include-dev", false, "Include development dependencies in scan")
	noVersionCheck := fs.Bool("no-version-check", false, "Skip version matching, report all vulnerabilities for package name")

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

	// Output results
	var formatLabel string
	if len(lockfiles) == 1 {
		formatLabel = filepath.Base(lockfiles[0])
	} else {
		formatLabel = fmt.Sprintf("%d lockfiles", len(lockfiles))
	}

	switch *format {
	case "json":
		outputAuditJSON(result)
	case "csv":
		outputAuditCSV(result)
	case "table":
		outputScanTable(result, formatLabel)
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

	fmt.Printf("%-40s %-12s %-20s %-10s %s\n", "PACKAGE", "VERSION", "VULN ID", "SEVERITY", "SUMMARY")
	fmt.Printf("%-40s %-12s %-20s %-10s %s\n",
		"----------------------------------------",
		"------------",
		"--------------------",
		"----------",
		"----------------------------------------")

	for _, f := range result.Findings {
		pkg := truncateString(f.Component.Name, 40)
		ver := truncateString(f.Component.Version, 12)
		vulnID := truncateString(f.VulnID, 20)
		summary := truncateString(f.Summary, 60)
		fmt.Printf("%-40s %-12s %-20s %-10s %s\n", pkg, ver, vulnID, f.Severity, summary)
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
