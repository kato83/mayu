package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kato83/mayu/internal/fetcher"
	"github.com/kato83/mayu/internal/ingest"
	"github.com/kato83/mayu/internal/model"
	"github.com/kato83/mayu/internal/parser"
	purlpkg "github.com/kato83/mayu/internal/purl"
	"github.com/kato83/mayu/internal/store"
)

var version = "dev"

const defaultDatabaseURL = "postgres://mayu:mayu@localhost:5432/mayu?sslmode=disable"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "version":
		fmt.Printf("mayu %s\n", version)
	case "ingest":
		if err := runIngest(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "search":
		if err := runSearch(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: mayu <command> [options]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  ingest     Import vulnerability data from OSV")
	fmt.Println("  search     Search for vulnerabilities")
	fmt.Println("  version    Print version information")
	fmt.Println("  help       Show this help message")
	fmt.Println()
	fmt.Println("Run 'mayu <command> --help' for more information on a command.")
}

func runIngest(args []string) error {
	fs := flag.NewFlagSet("ingest", flag.ExitOnError)

	ecosystem := fs.String("ecosystem", "", "Ecosystem to import (e.g., Go, PyPI, npm)")
	source := fs.String("source", "", "Import from converted source (nvd, debian)")
	all := fs.Bool("all", false, "Import all ecosystems")
	bulk := fs.Bool("bulk", false, "Use top-level all.zip for bulk import (with --all)")
	update := fs.Bool("update", false, "Perform delta update instead of full import")
	dbURL := fs.String("db-url", "", "PostgreSQL connection URL (default: $DATABASE_URL or localhost)")
	batchSize := fs.Int("batch-size", 100, "Number of vulnerabilities per batch insert")

	fs.Usage = func() {
		fmt.Println("Usage: mayu ingest [options]")
		fmt.Println()
		fmt.Println("Import vulnerability data from OSV into the local database.")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  mayu ingest --ecosystem Go")
		fmt.Println("  mayu ingest --ecosystem Go --update")
		fmt.Println("  mayu ingest --all")
		fmt.Println("  mayu ingest --all --bulk    # Download single all.zip (~1.3GB) for all ecosystems")
		fmt.Println("  mayu ingest --source nvd")
		fmt.Println("  mayu ingest --source debian")
		fmt.Println("  mayu ingest --ecosystem PyPI --db-url postgres://user:pass@host/db")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Validate flags
	if !*all && *ecosystem == "" && *source == "" {
		return fmt.Errorf("either --ecosystem, --source, or --all is required")
	}

	// Resolve database URL
	databaseURL := resolveDatabaseURL(*dbURL)

	// Setup context with signal handling
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Connect to database
	s, err := store.NewPostgresStore(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer func() { _ = s.Close() }()

	// Create fetcher and parser
	f := fetcher.New()
	p := parser.New()

	// Create ingester with progress output
	ing := ingest.New(f, p, s,
		ingest.WithBatchSize(*batchSize),
		ingest.WithProgress(printProgress),
	)

	// Handle --source (converted data sources)
	if *source != "" {
		src := ingest.GetConvertedSource(*source)
		if src == nil {
			return fmt.Errorf("unknown source: %q (supported: nvd, debian)", *source)
		}
		fmt.Printf("\n=== Importing %s (converted source: gs://%s/%s) ===\n", src.Name, src.Bucket, src.Prefix)
		stats, err := ing.ImportConvertedSource(ctx, *src)
		if err != nil {
			if ctx.Err() != nil {
				fmt.Fprintf(os.Stderr, "\nImport interrupted.\n")
				return nil
			}
			return fmt.Errorf("import %s: %w", src.Name, err)
		}
		printStats(stats)
		return nil
	}

	// Handle --all --bulk: download the single top-level all.zip (~1.3GB)
	if *all && *bulk {
		fmt.Println("\n=== Bulk import from top-level all.zip ===")
		stats, err := ing.BulkImportAll(ctx)
		if err != nil {
			if ctx.Err() != nil {
				fmt.Fprintf(os.Stderr, "\nImport interrupted.\n")
				return nil
			}
			return fmt.Errorf("bulk import: %w", err)
		}
		printStats(stats)
		return nil
	}

	// Determine ecosystems to import
	ecosystems, err := resolveEcosystems(ctx, f, *all, *ecosystem)
	if err != nil {
		return err
	}

	// Run import for each ecosystem
	for _, eco := range ecosystems {
		fmt.Printf("\n=== Importing %s ===\n", eco)

		var stats *ingest.Stats
		if *update {
			stats, err = ing.DeltaImport(ctx, eco)
		} else {
			stats, err = ing.FullImport(ctx, eco)
		}

		if err != nil {
			if ctx.Err() != nil {
				fmt.Fprintf(os.Stderr, "\nImport interrupted.\n")
				return nil
			}
			return fmt.Errorf("import %s: %w", eco, err)
		}

		printStats(stats)
	}

	return nil
}

// printProgress displays progress to the user.
func printProgress(p ingest.Progress) {
	switch p.Phase {
	case "download":
		if p.Total > 0 && p.Current > 0 {
			fmt.Printf("\r  [%s] %d/%d", p.Phase, p.Current, p.Total)
			if p.Current == p.Total {
				fmt.Println()
			}
		} else if p.Message != "" {
			fmt.Printf("  %s\n", p.Message)
		}
	case "parse":
		if p.Message != "" {
			fmt.Printf("  %s\n", p.Message)
		}
	case "store":
		if p.Total > 0 && p.Current > 0 && p.Message == "" {
			fmt.Printf("\r  [%s] %d/%d", p.Phase, p.Current, p.Total)
			if p.Current == p.Total {
				fmt.Println()
			}
		} else if p.Message != "" {
			fmt.Printf("  %s\n", p.Message)
		}
	}
}

// printStats displays the final import statistics.
func printStats(stats *ingest.Stats) {
	mode := "full"
	if !stats.IsFullSync {
		mode = "delta"
	}
	fmt.Printf("\n  Summary (%s sync):\n", mode)
	fmt.Printf("    Ecosystem:  %s\n", stats.Ecosystem)
	fmt.Printf("    Total:      %d\n", stats.Total)
	fmt.Printf("    Inserted:   %d\n", stats.Inserted)
	if stats.Errors > 0 {
		fmt.Printf("    Errors:     %d\n", stats.Errors)
	}
	fmt.Printf("    Duration:   %s\n", stats.Duration.Round(1e6))
}

// resolveDatabaseURL determines the database URL from flags, env, or default.
func resolveDatabaseURL(flagURL string) string {
	if flagURL != "" {
		warnInsecureDatabaseURL(flagURL)
		return flagURL
	}
	if envURL := os.Getenv("DATABASE_URL"); envURL != "" {
		warnInsecureDatabaseURL(envURL)
		return envURL
	}
	return defaultDatabaseURL
}

// warnInsecureDatabaseURL prints a warning to stderr when connecting to a
// non-local database without TLS (sslmode=disable or unset). Plaintext
// connections to remote hosts expose credentials and data in transit.
func warnInsecureDatabaseURL(dbURL string) {
	insecure, host, sslmode := isInsecureRemoteURL(dbURL)
	if insecure {
		fmt.Fprintf(os.Stderr,
			"warning: connecting to remote database host %q without enforced TLS (sslmode=%q). "+
				"Use sslmode=require (or verify-full) for production connections.\n",
			host, sslmode)
	}
}

// isInsecureRemoteURL reports whether dbURL targets a non-local host without
// enforced TLS. It returns the decision along with the parsed host and sslmode
// for diagnostics. Unparseable URLs are treated as not-insecure (the driver
// will surface the error later).
func isInsecureRemoteURL(dbURL string) (insecure bool, host, sslmode string) {
	u, err := url.Parse(dbURL)
	if err != nil {
		return false, "", ""
	}

	host = u.Hostname()
	if isLocalHost(host) {
		return false, host, u.Query().Get("sslmode")
	}

	sslmode = u.Query().Get("sslmode")
	switch sslmode {
	case "", "disable", "allow", "prefer":
		return true, host, sslmode
	}
	return false, host, sslmode
}

// isLocalHost reports whether the host refers to the local machine.
func isLocalHost(host string) bool {
	switch host {
	case "", "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

// resolveEcosystems returns the list of ecosystems to import.
// When all is true, it dynamically fetches the full list from the OSV GCS bucket.
func resolveEcosystems(ctx context.Context, f *fetcher.Fetcher, all bool, ecosystem string) ([]string, error) {
	if all {
		fmt.Println("Fetching ecosystem list from OSV GCS bucket...")
		ecosystems, err := f.ListEcosystems(ctx)
		if err != nil {
			return nil, fmt.Errorf("list ecosystems: %w", err)
		}
		fmt.Printf("Found %d ecosystems.\n", len(ecosystems))
		return ecosystems, nil
	}

	// Accept the ecosystem name as-is (GCS is case-sensitive).
	eco := strings.TrimSpace(ecosystem)
	if eco == "" {
		return nil, fmt.Errorf("ecosystem must not be empty")
	}
	return []string{eco}, nil
}

func runSearch(args []string) error {
	fs := flag.NewFlagSet("search", flag.ExitOnError)

	id := fs.String("id", "", "Search by vulnerability ID (e.g., CVE-2024-1234, GO-2024-2687)")
	pkg := fs.String("package", "", "Search by package name (e.g., golang.org/x/crypto)")
	ecosystem := fs.String("ecosystem", "", "Filter by ecosystem (e.g., Go, PyPI)")
	alias := fs.String("alias", "", "Search by alias (e.g., CVE-2024-24790)")
	purl := fs.String("purl", "", "Search by Package URL (e.g., pkg:golang/golang.org/x/crypto)")
	severity := fs.String("severity", "", "Filter by severity level (critical, high, medium, low, none). Note: filters by CVSS score range; entries without scores are excluded")
	since := fs.String("since", "", "Filter by modified date (YYYY-MM-DD or RFC3339)")
	version := fs.String("version", "", "Filter by affected version")
	format := fs.String("format", "table", "Output format: table, json, csv")
	limit := fs.Int("limit", 20, "Maximum number of results")
	offset := fs.Int("offset", 0, "Offset for pagination")
	count := fs.Bool("count", false, "Show only the result count")
	detail := fs.Bool("detail", false, "Show detailed information for each result")
	dbURL := fs.String("db-url", "", "PostgreSQL connection URL (default: $DATABASE_URL or localhost)")

	fs.Usage = func() {
		fmt.Println("Usage: mayu search [options] [query]")
		fmt.Println()
		fmt.Println("Search for vulnerabilities in the local database.")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  mayu search --id GO-2024-2687")
		fmt.Println("  mayu search --package golang.org/x/crypto")
		fmt.Println("  mayu search --ecosystem Go --limit 10")
		fmt.Println("  mayu search --alias CVE-2024-24790")
		fmt.Println("  mayu search --purl pkg:golang/golang.org/x/crypto")
		fmt.Println("  mayu search --severity critical --ecosystem Go")
		fmt.Println("  mayu search --since 2024-01-01 --ecosystem npm")
		fmt.Println("  mayu search --package net/http --version 1.21.0")
		fmt.Println("  mayu search --package net/http --format json")
		fmt.Println("  mayu search --package net/http --format csv")
		fmt.Println("  mayu search --ecosystem Go --count")
		fmt.Println("  mayu search --id GO-2024-2687 --detail")
		fmt.Println("  mayu search --ecosystem Go --offset 20 --limit 10")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Validate severity flag
	if *severity != "" {
		validSeverities := []string{"critical", "high", "medium", "low", "none"}
		valid := false
		for _, s := range validSeverities {
			if strings.ToLower(*severity) == s {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("invalid severity %q (valid: critical, high, medium, low, none)", *severity)
		}
	}

	// Validate --since date format
	if *since != "" {
		if err := validateDateInput(*since); err != nil {
			return fmt.Errorf("invalid --since value %q: %w", *since, err)
		}
	}

	// If positional argument provided and no flags set, treat as alias/ID search
	if *id == "" && *pkg == "" && *ecosystem == "" && *alias == "" && *purl == "" {
		if fs.NArg() > 0 {
			positional := strings.Join(fs.Args(), " ")
			// Heuristic: if it looks like a vuln ID, search by ID; otherwise alias
			if looksLikeVulnID(positional) {
				*id = positional
			} else {
				*alias = positional
			}
		} else if *severity == "" && *since == "" && *version == "" {
			fs.Usage()
			return fmt.Errorf("at least one search parameter is required")
		}
	}

	// Build search query
	searchPkg := *pkg
	searchEcosystem := strings.TrimSpace(*ecosystem)

	// If purl is specified, parse it into package name + ecosystem
	if *purl != "" {
		parsed, err := purlpkg.Parse(*purl)
		if err != nil {
			return fmt.Errorf("invalid purl %q: %w", *purl, err)
		}
		searchPkg = parsed.Package
		searchEcosystem = parsed.Ecosystem
	}

	query := store.SearchQuery{
		ID:          *id,
		Ecosystem:   searchEcosystem,
		PackageName: searchPkg,
		Alias:       *alias,
		Severity:    *severity,
		Since:       *since,
		Version:     *version,
		Limit:       *limit,
		Offset:      *offset,
	}

	// Resolve database URL
	databaseURL := resolveDatabaseURL(*dbURL)

	// Setup context
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Connect to database
	s, err := store.NewPostgresStore(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer func() { _ = s.Close() }()

	// If --count flag is set, just show the count
	if *count {
		n, err := s.Count(ctx, query)
		if err != nil {
			return fmt.Errorf("count: %w", err)
		}
		fmt.Printf("%d\n", n)
		return nil
	}

	// Execute search
	results, err := s.Search(ctx, query)
	if err != nil {
		return fmt.Errorf("search: %w", err)
	}

	if len(results) == 0 {
		fmt.Println("No results found.")
		return nil
	}

	// Output results
	switch *format {
	case "json":
		return outputJSON(results)
	case "csv":
		outputCSV(results)
	case "table":
		if *detail {
			outputDetail(results)
		} else {
			outputTable(results)
		}
	default:
		return fmt.Errorf("unknown format: %q (supported: table, json, csv)", *format)
	}

	return nil
}

// outputJSON prints results as a JSON array.
func outputJSON(vulns []*model.Vulnerability) error {
	// Output raw JSON for maximum fidelity
	fmt.Print("[")
	for i, vuln := range vulns {
		if i > 0 {
			fmt.Print(",")
		}
		if vuln.RawJSON != nil {
			fmt.Print(string(vuln.RawJSON))
		} else {
			data, err := json.Marshal(vuln)
			if err != nil {
				return err
			}
			fmt.Print(string(data))
		}
	}
	fmt.Println("]")
	return nil
}

// outputCSV prints results in CSV format suitable for spreadsheet import or scripting.
func outputCSV(vulns []*model.Vulnerability) {
	// Header
	fmt.Println("id,aliases,severity,modified,published,ecosystem,package,summary")

	for _, vuln := range vulns {
		aliases := strings.Join(vuln.Aliases, "; ")
		sevStr := formatSeverity(vuln)

		modified := vuln.Modified.Format("2006-01-02")
		published := ""
		if vuln.Published != nil {
			published = vuln.Published.Format("2006-01-02")
		}

		// Output one row per affected package (denormalized)
		if len(vuln.Affected) == 0 {
			fmt.Printf("%s,%s,%s,%s,%s,%s,%s,%s\n",
				csvEscape(vuln.ID),
				csvEscape(aliases),
				csvEscape(sevStr),
				csvEscape(modified),
				csvEscape(published),
				"",
				"",
				csvEscape(vuln.Summary),
			)
		} else {
			for _, affected := range vuln.Affected {
				fmt.Printf("%s,%s,%s,%s,%s,%s,%s,%s\n",
					csvEscape(vuln.ID),
					csvEscape(aliases),
					csvEscape(sevStr),
					csvEscape(modified),
					csvEscape(published),
					csvEscape(affected.Package.Ecosystem),
					csvEscape(affected.Package.Name),
					csvEscape(vuln.Summary),
				)
			}
		}
	}
}

// csvEscape wraps a value in double quotes if it contains commas, quotes, or newlines.
func csvEscape(s string) string {
	if strings.ContainsAny(s, ",\"\n\r") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}

// outputTable prints results in a human-readable table format.
func outputTable(vulns []*model.Vulnerability) {
	// Header
	fmt.Printf("%-20s %-15s %-8s %-12s %-30s %s\n", "ID", "ALIASES", "SEVERITY", "MODIFIED", "SUMMARY", "PACKAGES")
	fmt.Printf("%-20s %-15s %-8s %-12s %-30s %s\n",
		strings.Repeat("-", 20),
		strings.Repeat("-", 15),
		strings.Repeat("-", 8),
		strings.Repeat("-", 12),
		strings.Repeat("-", 30),
		strings.Repeat("-", 25))

	for _, vuln := range vulns {
		// Truncate summary (rune-safe)
		summary := truncateString(vuln.Summary, 30)

		// Collect aliases (show first CVE or first alias)
		aliasStr := formatAliases(vuln.Aliases, 15)

		// Extract severity
		sevStr := formatSeverity(vuln)

		// Collect package names
		var pkgs []string
		for _, a := range vuln.Affected {
			pkgs = append(pkgs, a.Package.Name)
		}
		pkgStr := truncateString(strings.Join(pkgs, ", "), 25)

		modified := vuln.Modified.Format("2006-01-02")

		fmt.Printf("%-20s %-15s %-8s %-12s %-30s %s\n", vuln.ID, aliasStr, sevStr, modified, summary, pkgStr)
	}

	fmt.Printf("\n%d result(s) found.\n", len(vulns))
}

// formatAliases returns a formatted alias string for table display.
// Prioritizes CVE IDs, truncated to maxLen.
func formatAliases(aliases []string, maxLen int) string {
	if len(aliases) == 0 {
		return "-"
	}

	// Prioritize CVE aliases
	var cves []string
	var others []string
	for _, a := range aliases {
		if strings.HasPrefix(strings.ToUpper(a), "CVE-") {
			cves = append(cves, a)
		} else {
			others = append(others, a)
		}
	}

	var display string
	if len(cves) > 0 {
		display = cves[0]
		if len(cves) > 1 {
			display += fmt.Sprintf(" +%d", len(cves)-1+len(others))
		} else if len(others) > 0 {
			display += fmt.Sprintf(" +%d", len(others))
		}
	} else {
		display = others[0]
		if len(others) > 1 {
			display += fmt.Sprintf(" +%d", len(others)-1)
		}
	}

	return truncateString(display, maxLen)
}

// formatSeverity extracts and formats the highest severity score from a vulnerability.
func formatSeverity(vuln *model.Vulnerability) string {
	var maxScore float64
	var found bool

	// Check top-level severity
	for _, sev := range vuln.Severity {
		score := parseCVSSScore(sev.Score)
		if score > maxScore {
			maxScore = score
			found = true
		}
	}

	// Check per-affected severity
	for _, affected := range vuln.Affected {
		for _, sev := range affected.Severity {
			score := parseCVSSScore(sev.Score)
			if score > maxScore {
				maxScore = score
				found = true
			}
		}
	}

	if !found {
		return "-"
	}

	return fmt.Sprintf("%.1f", maxScore)
}

// parseCVSSScore tries to extract a numeric score from a CVSS score string.
// It handles both plain numeric scores ("9.8") and CVSS vector strings.
func parseCVSSScore(score string) float64 {
	score = strings.TrimSpace(score)
	// Try plain numeric parse
	var f float64
	if _, err := fmt.Sscanf(score, "%f", &f); err == nil {
		return f
	}
	// Try to extract from CVSS vector (not typically stored as score, but handle defensively)
	return 0
}

// outputDetail prints detailed information for each vulnerability.
func outputDetail(vulns []*model.Vulnerability) {
	for i, vuln := range vulns {
		if i > 0 {
			fmt.Println(strings.Repeat("=", 80))
		}

		fmt.Printf("ID:        %s\n", vuln.ID)
		fmt.Printf("Modified:  %s\n", vuln.Modified.Format(time.RFC3339))
		if vuln.Published != nil {
			fmt.Printf("Published: %s\n", vuln.Published.Format(time.RFC3339))
		}
		if vuln.Withdrawn != nil {
			fmt.Printf("Withdrawn: %s\n", vuln.Withdrawn.Format(time.RFC3339))
		}

		// Aliases
		if len(vuln.Aliases) > 0 {
			fmt.Printf("Aliases:   %s\n", strings.Join(vuln.Aliases, ", "))
		}

		// Related
		if len(vuln.Related) > 0 {
			fmt.Printf("Related:   %s\n", strings.Join(vuln.Related, ", "))
		}

		// Summary & Details
		if vuln.Summary != "" {
			fmt.Printf("Summary:   %s\n", vuln.Summary)
		}
		if vuln.Details != "" {
			fmt.Printf("Details:\n")
			// Indent details for readability
			for _, line := range strings.Split(vuln.Details, "\n") {
				fmt.Printf("  %s\n", line)
			}
		}

		// Severity
		if len(vuln.Severity) > 0 {
			fmt.Printf("Severity:\n")
			for _, sev := range vuln.Severity {
				source := sev.Source
				if source == "" {
					source = "unspecified"
				}
				fmt.Printf("  - %s: %s (source: %s)\n", sev.Type, sev.Score, source)
			}
		}

		// Affected packages
		if len(vuln.Affected) > 0 {
			fmt.Printf("Affected Packages:\n")
			for _, affected := range vuln.Affected {
				fmt.Printf("  - %s/%s", affected.Package.Ecosystem, affected.Package.Name)
				if affected.Package.Purl != "" {
					fmt.Printf(" (%s)", affected.Package.Purl)
				}
				fmt.Println()

				// Per-affected severity
				for _, sev := range affected.Severity {
					fmt.Printf("    Severity: %s %s\n", sev.Type, sev.Score)
				}

				// Version ranges
				for _, r := range affected.Ranges {
					fmt.Printf("    Range (%s):", r.Type)
					if r.Repo != "" {
						fmt.Printf(" repo=%s", r.Repo)
					}
					fmt.Println()
					for _, ev := range r.Events {
						if ev.Introduced != "" {
							fmt.Printf("      introduced: %s\n", ev.Introduced)
						}
						if ev.Fixed != "" {
							fmt.Printf("      fixed: %s\n", ev.Fixed)
						}
						if ev.LastAffected != "" {
							fmt.Printf("      last_affected: %s\n", ev.LastAffected)
						}
						if ev.Limit != "" {
							fmt.Printf("      limit: %s\n", ev.Limit)
						}
					}
				}

				// Enumerated versions
				if len(affected.Versions) > 0 {
					versionsStr := strings.Join(affected.Versions, ", ")
					if len(versionsStr) > 100 {
						versionsStr = truncateString(versionsStr, 100)
						fmt.Printf("    Versions: %s (%d total)\n", versionsStr, len(affected.Versions))
					} else {
						fmt.Printf("    Versions: %s\n", versionsStr)
					}
				}
			}
		}

		// References
		if len(vuln.References) > 0 {
			fmt.Printf("References:\n")
			for _, ref := range vuln.References {
				fmt.Printf("  - [%s] %s\n", ref.Type, ref.URL)
			}
		}

		// Credits
		if len(vuln.Credits) > 0 {
			fmt.Printf("Credits:\n")
			for _, credit := range vuln.Credits {
				ctype := string(credit.Type)
				if ctype == "" {
					ctype = "OTHER"
				}
				fmt.Printf("  - %s (%s)\n", credit.Name, ctype)
			}
		}

		fmt.Println()
	}

	fmt.Printf("%d result(s) found.\n", len(vulns))
}

// truncateString truncates a string to maxRunes runes, appending "..." if truncated.
// This is safe for multi-byte UTF-8 characters.
func truncateString(s string, maxRunes int) string {
	runes := []rune(s)
	if len(runes) <= maxRunes {
		return s
	}
	if maxRunes <= 3 {
		return "..."
	}
	return string(runes[:maxRunes-3]) + "..."
}

// looksLikeVulnID returns true if the string looks like a vulnerability ID.
func looksLikeVulnID(s string) bool {
	// Common patterns: GO-2024-1234, CVE-2024-1234, GHSA-xxxx-xxxx-xxxx
	s = strings.TrimSpace(s)
	prefixes := []string{"GO-", "CVE-", "GHSA-", "PYSEC-", "RUSTSEC-", "DSA-", "DLA-", "USN-", "ALSA-", "RLSA-"}
	upper := strings.ToUpper(s)
	for _, p := range prefixes {
		if strings.HasPrefix(upper, p) {
			return true
		}
	}
	return false
}

// validateDateInput checks that a date string is valid (YYYY-MM-DD or RFC3339).
func validateDateInput(s string) error {
	// Try RFC3339 first
	if _, err := time.Parse(time.RFC3339, s); err == nil {
		return nil
	}
	// Try YYYY-MM-DD
	if _, err := time.Parse("2006-01-02", s); err == nil {
		return nil
	}
	return fmt.Errorf("expected format YYYY-MM-DD or RFC3339 (e.g., 2024-01-15 or 2024-01-15T00:00:00Z)")
}
