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
	format := fs.String("format", "table", "Output format: table, json, csv")
	includeDev := fs.Bool("include-dev", false, "Include development dependencies in audit")
	noVersionCheck := fs.Bool("no-version-check", false, "Skip version matching, report all vulnerabilities for package name")
	dbURL := fs.String("db-url", "", "PostgreSQL connection URL (default: $DATABASE_URL or localhost)")

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
	}

	if err := fs.Parse(args); err != nil {
		return 2, err
	}

	if *sbomPath == "" {
		return 2, fmt.Errorf("--sbom is required")
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
	databaseURL := resolveDatabaseURL(*dbURL, cfg)

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

	// Output results
	switch *format {
	case "json":
		outputAuditJSON(result)
	case "csv":
		outputAuditCSV(result)
	case "table":
		outputAuditTable(result, bom.Format)
	default:
		return 2, fmt.Errorf("unknown format: %q (supported: table, json, csv)", *format)
	}

	// Exit code: 1 if vulnerabilities found, 0 if clean
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
	fmt.Printf("%-40s %-12s %-20s %-10s %s\n", "PACKAGE", "VERSION", "VULN ID", "SEVERITY", "SUMMARY")
	fmt.Printf("%-40s %-12s %-20s %-10s %s\n",
		strings.Repeat("-", 40),
		strings.Repeat("-", 12),
		strings.Repeat("-", 20),
		strings.Repeat("-", 10),
		strings.Repeat("-", 40))

	for _, f := range result.Findings {
		pkg := truncateString(f.Component.Name, 40)
		ver := truncateString(f.Component.Version, 12)
		vulnID := truncateString(f.VulnID, 20)
		summary := truncateString(f.Summary, 60)
		fmt.Printf("%-40s %-12s %-20s %-10s %s\n", pkg, ver, vulnID, f.Severity, summary)
	}

	fmt.Printf("\n✗ %d vulnerability finding(s) in %d package(s) (%d total packages audited)\n",
		len(result.Findings), result.VulnerablePackages, result.TotalPackages)
}

func outputAuditJSON(result *audit.AuditResult) {
	type jsonFinding struct {
		Package   string   `json:"package"`
		Version   string   `json:"version"`
		Ecosystem string   `json:"ecosystem"`
		VulnID    string   `json:"vuln_id"`
		Aliases   []string `json:"aliases,omitempty"`
		Severity  string   `json:"severity"`
		Summary   string   `json:"summary"`
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
			Package:   f.Component.Name,
			Version:   f.Component.Version,
			Ecosystem: f.Component.Ecosystem,
			VulnID:    f.VulnID,
			Aliases:   f.Aliases,
			Severity:  f.Severity,
			Summary:   f.Summary,
		})
	}
	out.Summary.TotalPackages = result.TotalPackages
	out.Summary.VulnerablePackages = result.VulnerablePackages
	out.Summary.TotalFindings = len(result.Findings)

	data, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(data))
}

func outputAuditCSV(result *audit.AuditResult) {
	fmt.Println("package,version,ecosystem,vuln_id,severity,summary")
	for _, f := range result.Findings {
		fmt.Printf("%s,%s,%s,%s,%s,%s\n",
			csvEscape(f.Component.Name),
			csvEscape(f.Component.Version),
			csvEscape(f.Component.Ecosystem),
			csvEscape(f.VulnID),
			csvEscape(f.Severity),
			csvEscape(f.Summary),
		)
	}
}
