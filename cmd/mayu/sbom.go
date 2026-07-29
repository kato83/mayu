package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/kato83/mayu/internal/config"
	"github.com/kato83/mayu/internal/sbommon"
	"github.com/kato83/mayu/internal/store"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func runSBOM(args []string, cfg *config.Config) error {
	if len(args) == 0 {
		printSBOMUsage()
		return fmt.Errorf("no subcommand specified (use 'upload', 'scan', or 'list')")
	}

	switch args[0] {
	case "upload":
		return runSBOMUpload(args[1:], cfg)
	case "scan":
		return runSBOMScan(args[1:], cfg)
	case "list":
		return runSBOMList(args[1:], cfg)
	case "suppress":
		return runSBOMSetStatus(args[1:], cfg, sbommon.FindingStatusSuppressed)
	case "accept":
		return runSBOMSetStatus(args[1:], cfg, sbommon.FindingStatusRiskAccepted)
	case "status":
		return runSBOMStatus(args[1:], cfg)
	case "help", "-h", "--help":
		printSBOMUsage()
		return nil
	default:
		printSBOMUsage()
		return fmt.Errorf("unknown sbom subcommand: %q (use 'upload', 'scan', 'list', 'suppress', 'accept', or 'status')", args[0])
	}
}

func runSBOMUpload(args []string, cfg *config.Config) error {
	fs := flag.NewFlagSet("sbom upload", flag.ContinueOnError)

	project := fs.String("project", "", "Project name (required)")
	version := fs.String("version", "", "SBOM version (required)")
	sbomPath := fs.String("sbom", "", "Path to SBOM file (required)")
	environment := fs.String("environment", "", "Environment (e.g., 'production', 'staging')")

	fs.Usage = func() {
		fmt.Println("Usage: mayu sbom upload [options]")
		fmt.Println()
		fmt.Println("Upload an SBOM file and run vulnerability scan.")
		fmt.Println()
		fmt.Println("Authentication:")
		fmt.Println("  Set MAYU_API_KEY environment variable with a valid API key.")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  export MAYU_API_KEY=your-api-key")
		fmt.Println("  mayu sbom upload --project my-app --version 1.0.0 --sbom bom.json")
		fmt.Println("  mayu sbom upload --project my-app --version 2.0.0 --sbom bom.json --environment production")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *project == "" {
		return fmt.Errorf("--project is required")
	}
	if *version == "" {
		return fmt.Errorf("--version is required")
	}
	if *sbomPath == "" {
		return fmt.Errorf("--sbom is required")
	}

	// Read SBOM file
	sbomData, err := os.ReadFile(*sbomPath)
	if err != nil {
		return fmt.Errorf("read SBOM file: %w", err)
	}

	// Connect to database
	databaseURL := resolveDatabaseURL(cfg)
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}

	// Authenticate user (API key, session token, or error)
	user, err := resolveAuthUserWithDB(ctx, cfg, db)
	if err != nil {
		return err
	}
	userID := user.ID

	// Initialize stores
	sbomStore := sbommon.NewPostgresSBOMStore(db)
	mainStore, err := store.NewPostgresStore(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("connect to main store: %w", err)
	}
	defer func() { _ = mainStore.Close() }()

	scanner := sbommon.NewScanner(mainStore)

	// Get or create project
	proj, err := sbomStore.GetProjectByName(ctx, *project, userID)
	if err != nil {
		return fmt.Errorf("get project: %w", err)
	}
	if proj == nil {
		id, err := sbomStore.CreateProject(ctx, &sbommon.SBOMProject{
			UserID: userID,
			Name:   *project,
		})
		if err != nil {
			return fmt.Errorf("create project: %w", err)
		}
		proj, err = sbomStore.GetProject(ctx, id, userID)
		if err != nil {
			return fmt.Errorf("get created project: %w", err)
		}
	}

	// Run scan
	scanResult, err := scanner.Scan(ctx, sbomData)
	if err != nil {
		return fmt.Errorf("scan SBOM: %w", err)
	}

	// Create version
	ver := &sbommon.SBOMVersion{
		ProjectID:      proj.ID,
		Version:        *version,
		Environment:    *environment,
		SBOMFormat:     scanResult.Status, // will be overwritten below
		RawSBOM:        sbomData,
		ComponentCount: scanResult.TotalPackages,
	}
	// Detect format
	ver.SBOMFormat = detectSBOMFormat(sbomData)

	versionID, err := sbomStore.CreateVersion(ctx, ver)
	if err != nil {
		return fmt.Errorf("create version: %w", err)
	}

	// Get previous version's scan for cross-version diff
	prevResult, _ := sbomStore.GetPreviousVersionScanResult(ctx, proj.ID, versionID)
	diff := sbommon.ComputeDiff(scanResult, prevResult)

	scanResult.VersionID = versionID
	scanResult.Trigger = "manual"
	scanResult.NewFindings = len(diff.NewFindings)
	scanResult.ResolvedFindings = len(diff.ResolvedFindings)

	scanID, err := sbomStore.CreateScanResult(ctx, scanResult)
	if err != nil {
		return fmt.Errorf("store scan result: %w", err)
	}

	fmt.Printf("SBOM uploaded and scanned successfully:\n")
	fmt.Printf("  Project:       %s (ID: %d)\n", proj.Name, proj.ID)
	fmt.Printf("  Version:       %s (ID: %d)\n", *version, versionID)
	fmt.Printf("  Scan ID:       %d\n", scanID)
	fmt.Printf("  Total Packages: %d\n", scanResult.TotalPackages)
	fmt.Printf("  Vulnerable:    %d\n", scanResult.VulnerablePackages)
	fmt.Printf("  Findings:      %d\n", scanResult.TotalFindings)
	if len(diff.NewFindings) > 0 {
		fmt.Printf("  New Findings:  %d\n", len(diff.NewFindings))
	}
	if len(diff.ResolvedFindings) > 0 {
		fmt.Printf("  Resolved:      %d\n", len(diff.ResolvedFindings))
	}

	return nil
}

func runSBOMScan(args []string, cfg *config.Config) error {
	fs := flag.NewFlagSet("sbom scan", flag.ContinueOnError)

	project := fs.String("project", "", "Project name (required)")
	version := fs.String("version", "", "Version to scan (default: latest)")

	fs.Usage = func() {
		fmt.Println("Usage: mayu sbom scan [options]")
		fmt.Println()
		fmt.Println("Re-scan an existing SBOM version for vulnerabilities.")
		fmt.Println()
		fmt.Println("Authentication:")
		fmt.Println("  Set MAYU_API_KEY environment variable with a valid API key.")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  export MAYU_API_KEY=your-api-key")
		fmt.Println("  mayu sbom scan --project my-app")
		fmt.Println("  mayu sbom scan --project my-app --version 1.0.0")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *project == "" {
		return fmt.Errorf("--project is required")
	}

	// Connect to database
	databaseURL := resolveDatabaseURL(cfg)
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}

	// Authenticate user (API key, session token, or error)
	user, err := resolveAuthUserWithDB(ctx, cfg, db)
	if err != nil {
		return err
	}
	userID := user.ID

	// Initialize stores
	sbomStore := sbommon.NewPostgresSBOMStore(db)
	mainStore, err := store.NewPostgresStore(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("connect to main store: %w", err)
	}
	defer func() { _ = mainStore.Close() }()

	scanner := sbommon.NewScanner(mainStore)

	// Find project
	proj, err := sbomStore.GetProjectByName(ctx, *project, userID)
	if err != nil {
		return fmt.Errorf("get project: %w", err)
	}
	if proj == nil {
		return fmt.Errorf("project %q not found", *project)
	}

	// Find version
	var ver *sbommon.SBOMVersion
	if *version != "" {
		versions, err := sbomStore.ListVersions(ctx, proj.ID)
		if err != nil {
			return fmt.Errorf("list versions: %w", err)
		}
		for _, v := range versions {
			if v.Version == *version {
				// Need to load full version with RawSBOM
				ver, err = sbomStore.GetVersion(ctx, v.ID)
				if err != nil {
					return fmt.Errorf("get version: %w", err)
				}
				break
			}
		}
		if ver == nil {
			return fmt.Errorf("version %q not found in project %q", *version, *project)
		}
	} else {
		ver, err = sbomStore.GetLatestVersion(ctx, proj.ID)
		if err != nil {
			return fmt.Errorf("get latest version: %w", err)
		}
		if ver == nil {
			return fmt.Errorf("no versions found for project %q", *project)
		}
	}

	// Run scan
	scanResult, err := scanner.ScanVersion(ctx, ver)
	if err != nil {
		return fmt.Errorf("scan version: %w", err)
	}

	// Get previous scan for diff
	prevResult, _ := sbomStore.GetLatestScanResult(ctx, ver.ID)
	diff := sbommon.ComputeDiff(scanResult, prevResult)

	scanResult.Trigger = "manual"
	scanResult.NewFindings = len(diff.NewFindings)
	scanResult.ResolvedFindings = len(diff.ResolvedFindings)

	scanID, err := sbomStore.CreateScanResult(ctx, scanResult)
	if err != nil {
		return fmt.Errorf("store scan result: %w", err)
	}

	fmt.Printf("Scan completed:\n")
	fmt.Printf("  Project:       %s\n", proj.Name)
	fmt.Printf("  Version:       %s\n", ver.Version)
	fmt.Printf("  Scan ID:       %d\n", scanID)
	fmt.Printf("  Total Packages: %d\n", scanResult.TotalPackages)
	fmt.Printf("  Vulnerable:    %d\n", scanResult.VulnerablePackages)
	fmt.Printf("  Findings:      %d\n", scanResult.TotalFindings)
	if len(diff.NewFindings) > 0 {
		fmt.Printf("  New Findings:  %d\n", len(diff.NewFindings))
	}
	if len(diff.ResolvedFindings) > 0 {
		fmt.Printf("  Resolved:      %d\n", len(diff.ResolvedFindings))
	}

	return nil
}

func runSBOMList(args []string, cfg *config.Config) error {
	fs := flag.NewFlagSet("sbom list", flag.ContinueOnError)

	project := fs.String("project", "", "Project name (if omitted, lists all projects)")

	fs.Usage = func() {
		fmt.Println("Usage: mayu sbom list [options]")
		fmt.Println()
		fmt.Println("List SBOM projects or versions.")
		fmt.Println()
		fmt.Println("Authentication:")
		fmt.Println("  Set MAYU_API_KEY environment variable with a valid API key.")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  export MAYU_API_KEY=your-api-key")
		fmt.Println("  mayu sbom list")
		fmt.Println("  mayu sbom list --project my-app")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Connect to database
	databaseURL := resolveDatabaseURL(cfg)
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}

	// Authenticate user (API key, session token, or error)
	user, err := resolveAuthUserWithDB(ctx, cfg, db)
	if err != nil {
		return err
	}
	userID := user.ID

	sbomStore := sbommon.NewPostgresSBOMStore(db)

	if *project == "" {
		// List all projects
		projects, err := sbomStore.ListProjects(ctx, userID)
		if err != nil {
			return fmt.Errorf("list projects: %w", err)
		}

		if len(projects) == 0 {
			fmt.Println("No SBOM projects found.")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		_, _ = fmt.Fprintf(w, "ID\tNAME\tCREATED\n")
		for _, p := range projects {
			_, _ = fmt.Fprintf(w, "%d\t%s\t%s\n", p.ID, p.Name, p.CreatedAt.Format("2006-01-02 15:04"))
		}
		return w.Flush()
	}

	// List versions for a project
	proj, err := sbomStore.GetProjectByName(ctx, *project, userID)
	if err != nil {
		return fmt.Errorf("get project: %w", err)
	}
	if proj == nil {
		return fmt.Errorf("project %q not found", *project)
	}

	versions, err := sbomStore.ListVersions(ctx, proj.ID)
	if err != nil {
		return fmt.Errorf("list versions: %w", err)
	}

	if len(versions) == 0 {
		fmt.Printf("No versions found for project %q.\n", *project)
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintf(w, "ID\tVERSION\tFORMAT\tCOMPONENTS\tENVIRONMENT\tCREATED\n")
	for _, v := range versions {
		_, _ = fmt.Fprintf(w, "%d\t%s\t%s\t%d\t%s\t%s\n",
			v.ID, v.Version, v.SBOMFormat, v.ComponentCount, v.Environment, v.CreatedAt.Format("2006-01-02 15:04"))
	}
	return w.Flush()
}

func printSBOMUsage() {
	fmt.Println("Usage: mayu sbom <subcommand> [options]")
	fmt.Println()
	fmt.Println("Manage SBOM continuous monitoring.")
	fmt.Println()
	fmt.Println("Authentication:")
	fmt.Println("  All subcommands require the MAYU_API_KEY environment variable to be set.")
	fmt.Println()
	fmt.Println("Subcommands:")
	fmt.Println("  upload    Upload an SBOM file and run vulnerability scan")
	fmt.Println("  scan      Re-scan an existing SBOM version")
	fmt.Println("  list      List projects or versions")
	fmt.Println("  suppress  Suppress a finding (mark as not applicable)")
	fmt.Println("  accept    Accept risk for a finding")
	fmt.Println("  status    View or reset finding statuses")
	fmt.Println()
	fmt.Println("Run 'mayu sbom <subcommand> --help' for more information.")
}

// detectSBOMFormat detects the SBOM format from raw data.
func detectSBOMFormat(data []byte) string {
	var probe struct {
		BomFormat   string `json:"bomFormat"`
		SpdxVersion string `json:"spdxVersion"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return ""
	}
	if probe.BomFormat == "CycloneDX" {
		return "CycloneDX"
	}
	if probe.SpdxVersion != "" {
		return "SPDX"
	}
	return ""
}

func runSBOMSetStatus(args []string, cfg *config.Config, targetStatus string) error {
	cmdName := "suppress"
	if targetStatus == sbommon.FindingStatusRiskAccepted {
		cmdName = "accept"
	}

	fs := flag.NewFlagSet("sbom "+cmdName, flag.ContinueOnError)

	project := fs.String("project", "", "Project name (required)")
	version := fs.String("version", "", "Version (default: latest)")
	vuln := fs.String("vuln", "", "Vulnerability ID (required)")
	purl := fs.String("purl", "", "Package URL (if omitted, applies to first matching finding)")
	reason := fs.String("reason", "", "Justification (required for accept)")
	expires := fs.String("expires", "", "Expiration duration (e.g., 90d, 1y) — only for accept")

	fs.Usage = func() {
		if cmdName == "suppress" {
			fmt.Println("Usage: mayu sbom suppress [options]")
			fmt.Println()
			fmt.Println("Suppress a finding (mark as not applicable to this context).")
		} else {
			fmt.Println("Usage: mayu sbom accept [options]")
			fmt.Println()
			fmt.Println("Accept risk for a finding (known vulnerability that cannot be patched).")
		}
		fmt.Println()
		fmt.Println("Authentication:")
		fmt.Println("  Set MAYU_API_KEY environment variable or run 'mayu login'.")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  export MAYU_API_KEY=your-api-key")
		if cmdName == "suppress" {
			fmt.Println("  mayu sbom suppress --project my-app --vuln CVE-2024-1234 --reason \"not applicable\"")
		} else {
			fmt.Println("  mayu sbom accept --project my-app --vuln CVE-2024-1234 --reason \"isolated environment\" --expires 90d")
		}
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *project == "" {
		return fmt.Errorf("--project is required")
	}
	if *vuln == "" {
		return fmt.Errorf("--vuln is required")
	}
	if targetStatus == sbommon.FindingStatusRiskAccepted && *reason == "" {
		return fmt.Errorf("--reason is required for risk acceptance")
	}

	// Connect to database
	databaseURL := resolveDatabaseURL(cfg)
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}

	// Authenticate user
	user, err := resolveAuthUserWithDB(ctx, cfg, db)
	if err != nil {
		return err
	}
	userID := user.ID

	// Initialize store
	sbomStore := sbommon.NewPostgresSBOMStore(db)

	// Find project
	proj, err := sbomStore.GetProjectByName(ctx, *project, userID)
	if err != nil {
		return fmt.Errorf("get project: %w", err)
	}
	if proj == nil {
		return fmt.Errorf("project %q not found", *project)
	}

	// Find version
	var ver *sbommon.SBOMVersion
	if *version != "" {
		versions, err := sbomStore.ListVersions(ctx, proj.ID)
		if err != nil {
			return fmt.Errorf("list versions: %w", err)
		}
		for _, v := range versions {
			if v.Version == *version {
				ver, err = sbomStore.GetVersion(ctx, v.ID)
				if err != nil {
					return fmt.Errorf("get version: %w", err)
				}
				break
			}
		}
		if ver == nil {
			return fmt.Errorf("version %q not found in project %q", *version, *project)
		}
	} else {
		ver, err = sbomStore.GetLatestVersion(ctx, proj.ID)
		if err != nil {
			return fmt.Errorf("get latest version: %w", err)
		}
		if ver == nil {
			return fmt.Errorf("no versions found for project %q", *project)
		}
	}

	// Resolve purl: if not provided, look up from latest scan
	targetPurl := *purl
	if targetPurl == "" {
		latestScan, err := sbomStore.GetLatestScanResult(ctx, ver.ID)
		if err != nil {
			return fmt.Errorf("get latest scan: %w", err)
		}
		if latestScan == nil {
			return fmt.Errorf("no scan results found for version %q", ver.Version)
		}
		for _, f := range latestScan.Findings {
			if f.VulnID == *vuln {
				targetPurl = f.Purl
				break
			}
		}
		if targetPurl == "" {
			return fmt.Errorf("vulnerability %q not found in latest scan for version %q", *vuln, ver.Version)
		}
	}

	// Parse expiration
	var expiresAt *time.Time
	if *expires != "" {
		duration, err := parseFindingExpires(*expires)
		if err != nil {
			return fmt.Errorf("invalid --expires: %w", err)
		}
		t := time.Now().Add(duration)
		expiresAt = &t
	}

	// Upsert status
	result, err := sbomStore.UpsertFindingStatus(ctx, &sbommon.FindingStatus{
		VersionID:     ver.ID,
		VulnID:        *vuln,
		Purl:          targetPurl,
		Status:        targetStatus,
		Justification: *reason,
		UpdatedBy:     userID,
		ExpiresAt:     expiresAt,
	})
	if err != nil {
		return fmt.Errorf("set finding status: %w", err)
	}

	statusLabel := "Suppressed"
	if targetStatus == sbommon.FindingStatusRiskAccepted {
		statusLabel = "Risk accepted"
	}

	fmt.Printf("%s finding:\n", statusLabel)
	fmt.Printf("  Project:    %s\n", proj.Name)
	fmt.Printf("  Version:    %s\n", ver.Version)
	fmt.Printf("  Vuln ID:    %s\n", result.VulnID)
	fmt.Printf("  Package:    %s\n", result.Purl)
	fmt.Printf("  Status:     %s\n", result.Status)
	if result.Justification != "" {
		fmt.Printf("  Reason:     %s\n", result.Justification)
	}
	if result.ExpiresAt != nil {
		fmt.Printf("  Expires at: %s\n", result.ExpiresAt.Format("2006-01-02"))
	}

	return nil
}

func runSBOMStatus(args []string, cfg *config.Config) error {
	fs := flag.NewFlagSet("sbom status", flag.ContinueOnError)

	project := fs.String("project", "", "Project name (required)")
	version := fs.String("version", "", "Version (default: latest)")
	statusFilter := fs.String("filter", "", "Filter by status (comma-separated: open,in_triage,suppressed,false_positive,risk_accepted,resolved)")
	reset := fs.String("reset", "", "Reset status for vulnerability ID (requires --purl)")
	resetPurl := fs.String("purl", "", "Package URL for reset operation")

	fs.Usage = func() {
		fmt.Println("Usage: mayu sbom status [options]")
		fmt.Println()
		fmt.Println("View or reset finding statuses for an SBOM version.")
		fmt.Println()
		fmt.Println("Authentication:")
		fmt.Println("  Set MAYU_API_KEY environment variable or run 'mayu login'.")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  export MAYU_API_KEY=your-api-key")
		fmt.Println("  mayu sbom status --project my-app")
		fmt.Println("  mayu sbom status --project my-app --filter suppressed,risk_accepted")
		fmt.Println("  mayu sbom status --project my-app --reset CVE-2024-1234 --purl pkg:npm/example@1.0.0")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *project == "" {
		return fmt.Errorf("--project is required")
	}

	// Connect to database
	databaseURL := resolveDatabaseURL(cfg)
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}

	// Authenticate user
	user, err := resolveAuthUserWithDB(ctx, cfg, db)
	if err != nil {
		return err
	}
	userID := user.ID

	// Initialize store
	sbomStore := sbommon.NewPostgresSBOMStore(db)

	// Find project
	proj, err := sbomStore.GetProjectByName(ctx, *project, userID)
	if err != nil {
		return fmt.Errorf("get project: %w", err)
	}
	if proj == nil {
		return fmt.Errorf("project %q not found", *project)
	}

	// Find version
	var ver *sbommon.SBOMVersion
	if *version != "" {
		versions, err := sbomStore.ListVersions(ctx, proj.ID)
		if err != nil {
			return fmt.Errorf("list versions: %w", err)
		}
		for _, v := range versions {
			if v.Version == *version {
				ver, err = sbomStore.GetVersion(ctx, v.ID)
				if err != nil {
					return fmt.Errorf("get version: %w", err)
				}
				break
			}
		}
		if ver == nil {
			return fmt.Errorf("version %q not found in project %q", *version, *project)
		}
	} else {
		ver, err = sbomStore.GetLatestVersion(ctx, proj.ID)
		if err != nil {
			return fmt.Errorf("get latest version: %w", err)
		}
		if ver == nil {
			return fmt.Errorf("no versions found for project %q", *project)
		}
	}

	// Handle reset operation
	if *reset != "" {
		if *resetPurl == "" {
			return fmt.Errorf("--purl is required for reset operation")
		}
		if err := sbomStore.DeleteFindingStatus(ctx, ver.ID, *reset, *resetPurl); err != nil {
			return fmt.Errorf("reset finding status: %w", err)
		}
		fmt.Printf("Reset status for %s (%s) in version %s\n", *reset, *resetPurl, ver.Version)
		return nil
	}

	// Parse filter
	var filters []string
	if *statusFilter != "" {
		filters = strings.Split(*statusFilter, ",")
		for _, f := range filters {
			if !sbommon.ValidFindingStatuses[f] {
				return fmt.Errorf("invalid status filter: %q", f)
			}
		}
	}

	// List statuses
	statuses, err := sbomStore.ListFindingStatuses(ctx, ver.ID, filters)
	if err != nil {
		return fmt.Errorf("list finding statuses: %w", err)
	}

	if len(statuses) == 0 {
		fmt.Printf("No finding statuses set for project %q version %q.\n", proj.Name, ver.Version)
		return nil
	}

	fmt.Printf("Finding statuses for %s (version %s):\n\n", proj.Name, ver.Version)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintf(w, "VULN ID\tPACKAGE\tSTATUS\tJUSTIFICATION\tEXPIRES\n")
	for _, s := range statuses {
		expires := ""
		if s.ExpiresAt != nil {
			expires = s.ExpiresAt.Format("2006-01-02")
		}
		justification := s.Justification
		if len(justification) > 50 {
			justification = justification[:47] + "..."
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			s.VulnID, s.Purl, s.Status, justification, expires)
	}
	return w.Flush()
}

// parseFindingExpires parses a duration string like "90d", "1y", "24h".
func parseFindingExpires(s string) (time.Duration, error) {
	if len(s) < 2 {
		return 0, fmt.Errorf("invalid duration: %q", s)
	}

	suffix := s[len(s)-1]
	numStr := s[:len(s)-1]

	var num int
	for _, c := range numStr {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid duration: %q", s)
		}
		num = num*10 + int(c-'0')
	}

	switch suffix {
	case 'h':
		return time.Duration(num) * time.Hour, nil
	case 'd':
		return time.Duration(num) * 24 * time.Hour, nil
	case 'y':
		return time.Duration(num) * 365 * 24 * time.Hour, nil
	default:
		return 0, fmt.Errorf("invalid duration suffix %q (use h, d, or y)", string(suffix))
	}
}
