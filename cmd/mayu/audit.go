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
	"github.com/kato83/mayu/internal/sbom"
	"github.com/kato83/mayu/internal/store"
)

func runAudit(args []string, cfg *config.Config) (int, error) {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)

	sbomPath := fs.String("sbom", "", "Path to SBOM file (CycloneDX 1.7 or SPDX 2.3 JSON)")
	format := fs.String("format", "table", "Output format: table, json, csv, sarif")
	includeDev := fs.Bool("include-dev", false, "Include development dependencies in audit")
	noVersionCheck := fs.Bool("no-version-check", false, "Skip version matching, report all vulnerabilities for package name")
	failOn := fs.String("fail-on", "", "Fail with exit code 1 only for findings at or above severity (e.g., critical,high)")
	ignorePath := fs.String("ignore", "", "Path to ignore file containing vulnerability IDs to suppress")

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

	// Output results
	switch *format {
	case "json":
		outputAuditJSON(result)
	case "csv":
		outputAuditCSV(result)
	case "table":
		outputAuditTable(result, bom.Format)
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
