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

	"github.com/kato83/mayu/internal/fetcher"
	"github.com/kato83/mayu/internal/ingest"
	"github.com/kato83/mayu/internal/model"
	"github.com/kato83/mayu/internal/parser"
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

	// Determine ecosystems to import
	ecosystems, err := resolveEcosystems(*all, *ecosystem)
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
		return flagURL
	}
	if envURL := os.Getenv("DATABASE_URL"); envURL != "" {
		return envURL
	}
	return defaultDatabaseURL
}

// resolveEcosystems returns the list of ecosystems to import.
func resolveEcosystems(all bool, ecosystem string) ([]string, error) {
	if all {
		// Known ecosystems from OSV - a subset of the most common ones
		return knownEcosystems, nil
	}

	// Normalize: accept lowercase input
	eco := normalizeEcosystem(ecosystem)
	if eco == "" {
		return nil, fmt.Errorf("unknown ecosystem: %q", ecosystem)
	}
	return []string{eco}, nil
}

// normalizeEcosystem maps common lowercase inputs to the correct ecosystem name.
func normalizeEcosystem(input string) string {
	lower := strings.ToLower(strings.TrimSpace(input))
	for _, eco := range knownEcosystems {
		if strings.ToLower(eco) == lower {
			return eco
		}
	}
	// If not found in known list, return as-is (GCS may still have it)
	if input != "" {
		return input
	}
	return ""
}

// knownEcosystems is a list of ecosystems available in the OSV GCS bucket.
var knownEcosystems = []string{
	"AlmaLinux",
	"Alpine",
	"Android",
	"Bitnami",
	"crates.io",
	"Debian",
	"GitHub Actions",
	"Go",
	"Hackage",
	"Hex",
	"Linux",
	"Maven",
	"npm",
	"NuGet",
	"Packagist",
	"Pub",
	"PyPI",
	"Rocky Linux",
	"RubyGems",
	"SwiftURL",
	"Ubuntu",
}

func runSearch(args []string) error {
	fs := flag.NewFlagSet("search", flag.ExitOnError)

	id := fs.String("id", "", "Search by vulnerability ID (e.g., CVE-2024-1234, GO-2024-2687)")
	pkg := fs.String("package", "", "Search by package name (e.g., golang.org/x/crypto)")
	ecosystem := fs.String("ecosystem", "", "Filter by ecosystem (e.g., Go, PyPI)")
	alias := fs.String("alias", "", "Search by alias (e.g., CVE-2024-24790)")
	format := fs.String("format", "table", "Output format: table, json")
	limit := fs.Int("limit", 20, "Maximum number of results")
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
		fmt.Println("  mayu search --package net/http --format json")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// If positional argument provided and no flags set, treat as alias/ID search
	if *id == "" && *pkg == "" && *ecosystem == "" && *alias == "" {
		if fs.NArg() > 0 {
			query := strings.Join(fs.Args(), " ")
			// Heuristic: if it looks like a vuln ID, search by ID; otherwise alias
			if looksLikeVulnID(query) {
				*id = query
			} else {
				*alias = query
			}
		} else {
			fs.Usage()
			return fmt.Errorf("at least one search parameter is required")
		}
	}

	// Build search query
	query := store.SearchQuery{
		ID:          *id,
		Ecosystem:   normalizeEcosystem(*ecosystem),
		PackageName: *pkg,
		Alias:       *alias,
		Limit:       *limit,
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
	case "table":
		outputTable(results)
	default:
		return fmt.Errorf("unknown format: %q (supported: table, json)", *format)
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

// outputTable prints results in a human-readable table format.
func outputTable(vulns []*model.Vulnerability) {
	// Header
	fmt.Printf("%-20s %-12s %-40s %s\n", "ID", "MODIFIED", "SUMMARY", "PACKAGES")
	fmt.Printf("%-20s %-12s %-40s %s\n",
		strings.Repeat("-", 20),
		strings.Repeat("-", 12),
		strings.Repeat("-", 40),
		strings.Repeat("-", 30))

	for _, vuln := range vulns {
		// Truncate summary
		summary := vuln.Summary
		if len(summary) > 40 {
			summary = summary[:37] + "..."
		}

		// Collect package names
		var pkgs []string
		for _, a := range vuln.Affected {
			pkgs = append(pkgs, a.Package.Name)
		}
		pkgStr := strings.Join(pkgs, ", ")
		if len(pkgStr) > 30 {
			pkgStr = pkgStr[:27] + "..."
		}

		modified := vuln.Modified.Format("2006-01-02")

		fmt.Printf("%-20s %-12s %-40s %s\n", vuln.ID, modified, summary, pkgStr)
	}

	fmt.Printf("\n%d result(s) found.\n", len(vulns))
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
