package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/kato83/mayu/internal/cvss"
	"github.com/kato83/mayu/internal/fetcher"
	"github.com/kato83/mayu/internal/ingest"
	"github.com/kato83/mayu/internal/model"
	"github.com/kato83/mayu/internal/parser"
	purlpkg "github.com/kato83/mayu/internal/purl"
	"github.com/kato83/mayu/internal/server"
	"github.com/kato83/mayu/internal/store"
	"github.com/kato83/mayu/internal/validate"
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
	case "serve":
		if err := runServe(os.Args[2:]); err != nil {
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
	fmt.Println("  ingest     Import vulnerability data from OSV, NVD, MITRE, EPSS, KEV")
	fmt.Println("  search     Search for vulnerabilities")
	fmt.Println("  serve      Start the API server")
	fmt.Println("  version    Print version information")
	fmt.Println("  help       Show this help message")
	fmt.Println()
	fmt.Println("Run 'mayu <command> --help' for more information on a command.")
}

func runIngest(args []string) error {
	fs := flag.NewFlagSet("ingest", flag.ExitOnError)

	ecosystem := fs.String("ecosystem", "", "Ecosystem to import (e.g., Go, PyPI, npm)")
	source := fs.String("source", "", "Import from source (nvd, debian, mitre, epss, kev)")
	all := fs.Bool("all", false, "Import all ecosystems")
	bulk := fs.Bool("bulk", false, "Use top-level all.zip for bulk import (with --all)")
	update := fs.Bool("update", false, "Perform delta update instead of full import")
	backfill := fs.Bool("backfill", false, "Backfill historical data (with --source epss)")
	fromDate := fs.String("from", "", "Start date for backfill (YYYY-MM-DD, default: 2023-03-07 for EPSS v3)")
	toDate := fs.String("to", "", "End date for backfill (YYYY-MM-DD, default: today)")
	concurrency := fs.Int("concurrency", 3, "Number of ecosystems to import in parallel (with --all)")
	dbURL := fs.String("db-url", "", "PostgreSQL connection URL (default: $DATABASE_URL or localhost)")
	batchSize := fs.Int("batch-size", 100, "Number of vulnerabilities per batch insert")
	storeWorkers := fs.Int("store-workers", ingest.DefaultStoreWorkers(), "Number of parallel DB store workers per ecosystem")
	native := fs.Bool("native", false, "Use native data source feed instead of OSV conversion (with --source nvd)")
	fileMode := fs.Bool("file", false, "Import from local OSV JSON files (paths as positional arguments)")

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
		fmt.Println("  mayu ingest --source nvd --native        # Import directly from NVD JSON Feed 2.0")
		fmt.Println("  mayu ingest --source nvd --native --update  # Delta update from NVD modified feed")
		fmt.Println("  mayu ingest --source debian")
		fmt.Println("  mayu ingest --source mitre              # Import MITRE CVE from cvelistV5")
		fmt.Println("  mayu ingest --source mitre --update     # Delta update from hourly releases")
		fmt.Println("  mayu ingest --source epss               # Import EPSS scores (bulk CSV)")
		fmt.Println("  mayu ingest --source epss --update      # Update EPSS scores if outdated")
		fmt.Println("  mayu ingest --source epss --backfill    # Backfill all EPSS history (2023-03-07 to today)")
		fmt.Println("  mayu ingest --source epss --backfill --from 2024-01-01 --to 2025-07-19")
		fmt.Println("  mayu ingest --source kev                # Import CISA KEV catalog")
		fmt.Println("  mayu ingest --source kev --update       # Update KEV catalog if outdated")
		fmt.Println("  mayu ingest --file vuln1.json vuln2.json # Import local OSV JSON files")
		fmt.Println("  mayu ingest --ecosystem PyPI --db-url postgres://user:pass@host/db")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Validate flags
	if !*all && *ecosystem == "" && *source == "" && !*fileMode {
		return fmt.Errorf("either --ecosystem, --source, --all, or --file is required")
	}

	// Resolve database URL
	databaseURL := resolveDatabaseURL(*dbURL)

	// Setup context with signal handling
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Handle --file: import local OSV JSON files
	if *fileMode {
		files := fs.Args()
		if len(files) == 0 {
			return fmt.Errorf("--file requires at least one file path as positional argument")
		}

		// Connect to database
		s, err := store.NewPostgresStore(ctx, databaseURL)
		if err != nil {
			return fmt.Errorf("connect to database: %w", err)
		}
		defer func() { _ = s.Close() }()

		p := parser.New()
		var imported, failed int

		fmt.Printf("\n=== Importing %d local OSV JSON file(s) ===\n", len(files))
		for _, path := range files {
			data, err := os.ReadFile(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", path, err)
				failed++
				continue
			}

			var vuln *model.Vulnerability

			// Auto-detect GitHub REST API advisory format and convert to OSV
			if parser.IsGitHubAdvisoryJSON(data) {
				vuln, err = parser.ConvertGitHubToOSV(data)
				if err != nil {
					fmt.Fprintf(os.Stderr, "  ✗ %s: GitHub→OSV conversion error: %v\n", path, err)
					failed++
					continue
				}
				fmt.Printf("  ℹ %s: detected GitHub Advisory format, converted to OSV\n", path)
			} else {
				vuln, err = p.Parse(data)
				if err != nil {
					fmt.Fprintf(os.Stderr, "  ✗ %s: parse error: %v\n", path, err)
					failed++
					continue
				}
				// Set RawJSON for storage (preserves original JSON)
				vuln.RawJSON = data
			}

			if err := s.Insert(ctx, vuln); err != nil {
				fmt.Fprintf(os.Stderr, "  ✗ %s (id=%s): insert error: %v\n", path, vuln.ID, err)
				failed++
				continue
			}

			fmt.Printf("  ✓ %s (id=%s, aliases=%v)\n", path, vuln.ID, vuln.Aliases)
			imported++
		}

		fmt.Printf("\nDone: %d imported, %d failed\n", imported, failed)
		if failed > 0 {
			return fmt.Errorf("%d file(s) failed to import", failed)
		}
		return nil
	}

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
		ingest.WithStoreWorkers(*storeWorkers),
		ingest.WithProgress(printProgress),
	)

	// Handle --source (converted data sources)
	if *source != "" {
		// NVD native import via JSON Feed 2.0
		if *native {
			if strings.ToLower(*source) != "nvd" {
				return fmt.Errorf("--native flag is only supported with --source nvd")
			}
			fmt.Println("\n=== Importing NVD (native JSON Feed 2.0) ===")
			var stats *ingest.Stats
			var err error
			if *update {
				stats, err = ing.UpdateNVDNative(ctx)
			} else {
				stats, err = ing.ImportNVDNative(ctx)
			}
			if err != nil {
				if ctx.Err() != nil {
					fmt.Fprintf(os.Stderr, "\nImport interrupted.\n")
					return nil
				}
				return fmt.Errorf("NVD native import: %w", err)
			}
			printStats(stats)
			return nil
		}

		// MITRE CVE import from cvelistV5 GitHub Releases
		if strings.ToLower(*source) == "mitre" {
			fmt.Println("\n=== Importing MITRE CVE (cvelistV5 GitHub Releases) ===")
			var stats *ingest.Stats
			var err error
			if *update {
				stats, err = ing.UpdateMITRE(ctx)
			} else {
				stats, err = ing.ImportMITRE(ctx)
			}
			if err != nil {
				if ctx.Err() != nil {
					fmt.Fprintf(os.Stderr, "\nImport interrupted.\n")
					return nil
				}
				return fmt.Errorf("MITRE import: %w", err)
			}
			printStats(stats)
			return nil
		}

		// EPSS score import from FIRST bulk CSV
		if strings.ToLower(*source) == "epss" {
			var stats *ingest.Stats
			var err error
			if *backfill {
				// Backfill historical EPSS data for LEV computation
				from := *fromDate
				to := *toDate
				if from == "" {
					from = ingest.EPSSv3StartDate
				}
				if to == "" {
					to = time.Now().UTC().Format("2006-01-02")
				}
				fmt.Printf("\n=== Backfilling EPSS scores (%s to %s) ===\n", from, to)
				stats, err = ing.BackfillEPSSRange(ctx, from, to)
			} else if *update {
				fmt.Println("\n=== Updating EPSS scores ===")
				stats, err = ing.UpdateEPSS(ctx)
			} else {
				fmt.Println("\n=== Importing EPSS scores (FIRST bulk CSV) ===")
				stats, err = ing.ImportEPSS(ctx)
			}
			if err != nil {
				if ctx.Err() != nil {
					fmt.Fprintf(os.Stderr, "\nImport interrupted.\n")
					return nil
				}
				return fmt.Errorf("EPSS import: %w", err)
			}
			printStats(stats)
			return nil
		}

		// CISA KEV catalog import
		if strings.ToLower(*source) == "kev" {
			fmt.Println("\n=== Importing CISA KEV catalog ===")
			var stats *ingest.Stats
			var err error
			if *update {
				stats, err = ing.UpdateKEV(ctx)
			} else {
				stats, err = ing.ImportKEV(ctx)
			}
			if err != nil {
				if ctx.Err() != nil {
					fmt.Fprintf(os.Stderr, "\nImport interrupted.\n")
					return nil
				}
				return fmt.Errorf("KEV import: %w", err)
			}
			printStats(stats)
			return nil
		}

		// Existing converted source logic
		src := ingest.GetConvertedSource(*source)
		if src == nil {
			return fmt.Errorf("unknown source: %q (supported: nvd, debian, mitre, epss, kev)", *source)
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

	// Run import for each ecosystem (parallel with semaphore)
	maxConcurrency := *concurrency
	if maxConcurrency < 1 {
		maxConcurrency = 1
	}
	if len(ecosystems) == 1 {
		maxConcurrency = 1
	}

	sem := make(chan struct{}, maxConcurrency)
	g, gCtx := errgroup.WithContext(ctx)

	for _, eco := range ecosystems {
		eco := eco // capture loop var
		g.Go(func() error {
			sem <- struct{}{}        // acquire
			defer func() { <-sem }() // release

			select {
			case <-gCtx.Done():
				return gCtx.Err()
			default:
			}

			fmt.Printf("\n=== Importing %s ===\n", eco)

			// Each goroutine uses its own Ingester to avoid shared state issues
			ecoIng := ingest.New(f, p, s,
				ingest.WithBatchSize(*batchSize),
				ingest.WithStoreWorkers(*storeWorkers),
				ingest.WithProgress(func(prog ingest.Progress) {
					// Prefix progress with ecosystem name for parallel output
					switch prog.Phase {
					case "download":
						if prog.Total > 0 && prog.Current > 0 {
							fmt.Printf("\r  [%s/%s] %d/%d", eco, prog.Phase, prog.Current, prog.Total)
							if prog.Current == prog.Total {
								fmt.Println()
							}
						} else if prog.Message != "" {
							fmt.Printf("  [%s] %s\n", eco, prog.Message)
						}
					case "store":
						if prog.Total > 0 && prog.Current > 0 && prog.Message == "" {
							fmt.Printf("\r  [%s/%s] %d/%d", eco, prog.Phase, prog.Current, prog.Total)
							if prog.Current == prog.Total {
								fmt.Println()
							}
						} else if prog.Message != "" {
							fmt.Printf("  [%s] %s\n", eco, prog.Message)
						}
					default:
						if prog.Message != "" {
							fmt.Printf("  [%s] %s\n", eco, prog.Message)
						}
					}
				}),
			)

			var stats *ingest.Stats
			var err error
			if *update {
				stats, err = ecoIng.DeltaImport(gCtx, eco)
			} else {
				stats, err = ecoIng.FullImport(gCtx, eco)
			}

			if err != nil {
				if gCtx.Err() != nil {
					return gCtx.Err()
				}
				return fmt.Errorf("import %s: %w", eco, err)
			}

			printStats(stats)
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		if ctx.Err() != nil {
			fmt.Fprintf(os.Stderr, "\nImport interrupted.\n")
			return nil
		}
		return err
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
// When all is true, it dynamically fetches the full list from ecosystems.txt
// in the OSV GCS bucket (gs://osv-vulnerabilities/ecosystems.txt).
func resolveEcosystems(ctx context.Context, f *fetcher.Fetcher, all bool, ecosystem string) ([]string, error) {
	if all {
		fmt.Println("Fetching ecosystem list from ecosystems.txt...")
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
		if err := validate.DateInput(*since); err != nil {
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
		if *detail {
			return outputDetailJSON(ctx, s, results)
		}
		return outputJSON(results)
	case "csv":
		outputCSV(results)
	case "table":
		if *detail {
			return outputDetailEnriched(ctx, s, results)
		}
		outputTable(results)
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
	fmt.Printf("%-20s %-15s %-14s %-12s %-30s %s\n", "ID", "ALIASES", "SEVERITY", "MODIFIED", "SUMMARY", "PACKAGES")
	fmt.Printf("%-20s %-15s %-14s %-12s %-30s %s\n",
		strings.Repeat("-", 20),
		strings.Repeat("-", 15),
		strings.Repeat("-", 14),
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

		fmt.Printf("%-20s %-15s %-14s %-12s %-30s %s\n", vuln.ID, aliasStr, sevStr, modified, summary, pkgStr)
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
// Returns a string like "9.8 CRITICAL", "7.5 HIGH", etc.
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

	label := scoreToSeverityLabel(maxScore)
	return fmt.Sprintf("%.1f %s", maxScore, label)
}

// scoreToSeverityLabel converts a CVSS score to a severity label.
func scoreToSeverityLabel(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score >= 0.1:
		return "LOW"
	default:
		return "NONE"
	}
}

// parseCVSSScore tries to extract a numeric score from a CVSS score string.
// It handles both plain numeric scores ("9.8") and CVSS vector strings
// ("CVSS:3.1/AV:N/AC:L/...") by computing the base score from the vector.
func parseCVSSScore(score string) float64 {
	score = strings.TrimSpace(score)
	// Try plain numeric parse
	var f float64
	if _, err := fmt.Sscanf(score, "%f", &f); err == nil {
		return f
	}
	// Try to compute base score from CVSS vector string
	if baseScore, ok := cvss.BaseScore(score); ok {
		return baseScore
	}
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

// outputDetailEnriched prints enriched detail (with NVD/MITRE data) for each vulnerability.
func outputDetailEnriched(ctx context.Context, s *store.PostgresStore, results []*model.Vulnerability) error {
	for i, vuln := range results {
		if i > 0 {
			fmt.Println(strings.Repeat("=", 80))
		}

		detail, err := s.GetVulnerabilityDetail(ctx, vuln.ID)
		if err != nil {
			return fmt.Errorf("get detail for %s: %w", vuln.ID, err)
		}
		if detail == nil {
			// Fallback to basic output
			outputDetail([]*model.Vulnerability{vuln})
			continue
		}

		// Base info
		fmt.Printf("ID:        %s\n", detail.ID)
		fmt.Printf("Modified:  %s\n", detail.Modified.Format(time.RFC3339))
		if detail.Published != nil {
			fmt.Printf("Published: %s\n", detail.Published.Format(time.RFC3339))
		}
		if detail.Withdrawn != nil {
			fmt.Printf("Withdrawn: %s\n", detail.Withdrawn.Format(time.RFC3339))
		}

		if len(detail.Aliases) > 0 {
			fmt.Printf("Aliases:   %s\n", strings.Join(detail.Aliases, ", "))
		}
		if len(detail.Related) > 0 {
			fmt.Printf("Related:   %s\n", strings.Join(detail.Related, ", "))
		}

		if detail.Summary != "" {
			fmt.Printf("Summary:   %s\n", detail.Summary)
		}
		if detail.Details != "" {
			fmt.Printf("Details:\n")
			for _, line := range strings.Split(detail.Details, "\n") {
				fmt.Printf("  %s\n", line)
			}
		}

		// OSV Severity
		if len(detail.Severity) > 0 {
			fmt.Printf("Severity (OSV):\n")
			for _, sev := range detail.Severity {
				source := sev.Source
				if source == "" {
					source = "unspecified"
				}
				fmt.Printf("  - %s: %s (source: %s)\n", sev.Type, sev.Score, source)
			}
		}

		// NVD Enrichment
		if detail.NVD != nil {
			fmt.Printf("NVD:\n")
			fmt.Printf("  Status:     %s\n", detail.NVD.VulnStatus)
			if detail.NVD.SourceIdentifier != "" {
				fmt.Printf("  Source:     %s\n", detail.NVD.SourceIdentifier)
			}
			if detail.NVD.Description != "" {
				fmt.Printf("  Description: %s\n", detail.NVD.Description)
			}
			if len(detail.NVD.Metrics) > 0 {
				fmt.Printf("  CVSS Metrics:\n")
				for _, m := range detail.NVD.Metrics {
					fmt.Printf("    - %s %s (source: %s, type: %s)\n",
						m.BaseSeverity, fmt.Sprintf("%.1f", m.BaseScore), m.Source, m.Type)
					if m.VectorString != "" {
						fmt.Printf("      Vector: %s\n", m.VectorString)
					}
					if m.ExploitabilityScore != nil {
						fmt.Printf("      Exploitability: %.1f\n", *m.ExploitabilityScore)
					}
					if m.ImpactScore != nil {
						fmt.Printf("      Impact: %.1f\n", *m.ImpactScore)
					}
				}
			}
			if len(detail.NVD.Weaknesses) > 0 {
				fmt.Printf("  Weaknesses (CWE):\n")
				for _, w := range detail.NVD.Weaknesses {
					fmt.Printf("    - %s (source: %s, type: %s)\n", w.CWEID, w.Source, w.Type)
				}
			}
			if len(detail.NVD.References) > 0 {
				fmt.Printf("  References:\n")
				for _, r := range detail.NVD.References {
					tags := ""
					if len(r.Tags) > 0 {
						tags = " [" + strings.Join(r.Tags, ", ") + "]"
					}
					fmt.Printf("    - %s%s\n", r.URL, tags)
				}
			}
		}

		// MITRE Enrichment
		if detail.MITRE != nil {
			fmt.Printf("MITRE:\n")
			fmt.Printf("  State:    %s\n", detail.MITRE.State)
			if detail.MITRE.AssignerShortName != "" {
				fmt.Printf("  Assigner: %s\n", detail.MITRE.AssignerShortName)
			}
			if len(detail.MITRE.Metrics) > 0 {
				fmt.Printf("  CVSS Metrics:\n")
				for _, m := range detail.MITRE.Metrics {
					fmt.Printf("    - %s %s (v%s, source: %s)\n",
						m.BaseSeverity, fmt.Sprintf("%.1f", m.BaseScore), m.CvssVersion, m.Source)
					if m.VectorString != "" {
						fmt.Printf("      Vector: %s\n", m.VectorString)
					}
				}
			}
			if detail.MITRE.SSVC != nil {
				fmt.Printf("  SSVC Assessment:\n")
				if detail.MITRE.SSVC.Role != "" {
					fmt.Printf("    Role: %s\n", detail.MITRE.SSVC.Role)
				}
				if detail.MITRE.SSVC.Version != "" {
					fmt.Printf("    Version: %s\n", detail.MITRE.SSVC.Version)
				}
				for _, opt := range detail.MITRE.SSVC.Options {
					fmt.Printf("    - %s: %s\n", opt.Key, opt.Value)
				}
				if detail.MITRE.SSVC.Timestamp != "" {
					fmt.Printf("    Timestamp: %s\n", detail.MITRE.SSVC.Timestamp)
				}
			}
			if len(detail.MITRE.ProblemTypes) > 0 {
				fmt.Printf("  Problem Types (CWE):\n")
				for _, pt := range detail.MITRE.ProblemTypes {
					if pt.CWEID != "" {
						fmt.Printf("    - %s: %s\n", pt.CWEID, pt.Description)
					} else {
						fmt.Printf("    - %s\n", pt.Description)
					}
				}
			}
			if len(detail.MITRE.Credits) > 0 {
				fmt.Printf("  Credits:\n")
				for _, c := range detail.MITRE.Credits {
					ctype := c.Type
					if ctype == "" {
						ctype = "other"
					}
					fmt.Printf("    - %s (%s)\n", c.Value, ctype)
				}
			}
			if len(detail.MITRE.References) > 0 {
				fmt.Printf("  References:\n")
				for _, r := range detail.MITRE.References {
					tags := ""
					if len(r.Tags) > 0 {
						tags = " [" + strings.Join(r.Tags, ", ") + "]"
					}
					fmt.Printf("    - %s%s\n", r.URL, tags)
				}
			}
		}

		// EPSS Enrichment
		if detail.EPSS != nil {
			fmt.Printf("EPSS:\n")
			fmt.Printf("  Score:      %.5f (%.1f%%)\n", detail.EPSS.EPSS, detail.EPSS.EPSS*100)
			fmt.Printf("  Percentile: %.5f (%.1f%%)\n", detail.EPSS.Percentile, detail.EPSS.Percentile*100)
			fmt.Printf("  Score Date: %s\n", detail.EPSS.ScoreDate)
		}

		// KEV Enrichment
		if detail.KEV != nil {
			fmt.Printf("KEV (CISA Known Exploited Vulnerabilities):\n")
			fmt.Printf("  Vendor/Project: %s\n", detail.KEV.VendorProject)
			fmt.Printf("  Product:        %s\n", detail.KEV.Product)
			fmt.Printf("  Vuln Name:      %s\n", detail.KEV.VulnerabilityName)
			fmt.Printf("  Date Added:     %s\n", detail.KEV.DateAdded)
			fmt.Printf("  Due Date:       %s\n", detail.KEV.DueDate)
			fmt.Printf("  Required Action: %s\n", detail.KEV.RequiredAction)
			fmt.Printf("  Ransomware Use: %s\n", detail.KEV.KnownRansomwareCampaignUse)
		}

		// LEV (Likely Exploited Vulnerabilities) Score
		if detail.LEV != nil {
			fmt.Printf("LEV (Likely Exploited Vulnerabilities - NIST CSWP 41):\n")
			fmt.Printf("  Score:       %.5f (%.1f%%)\n", detail.LEV.LEV, detail.LEV.LEV*100)
			fmt.Printf("  In KEV:      %t\n", detail.LEV.InKEV)
			fmt.Printf("  EPSS Days:   %d\n", detail.LEV.EPSSScoreCount)
			if detail.LEV.FirstEPSSDate != "" {
				fmt.Printf("  First EPSS:  %s\n", detail.LEV.FirstEPSSDate)
			}
			if detail.LEV.LastEPSSDate != "" {
				fmt.Printf("  Last EPSS:   %s\n", detail.LEV.LastEPSSDate)
			}
			fmt.Printf("  Computed At: %s\n", detail.LEV.ComputedAt)
		}

		// Affected packages (from OSV)
		if len(detail.Affected) > 0 {
			fmt.Printf("Affected Packages:\n")
			for _, affected := range detail.Affected {
				fmt.Printf("  - %s/%s", affected.Package.Ecosystem, affected.Package.Name)
				if affected.Package.Purl != "" {
					fmt.Printf(" (%s)", affected.Package.Purl)
				}
				fmt.Println()
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
			}
		}

		// OSV References
		if len(detail.References) > 0 {
			fmt.Printf("References (OSV):\n")
			for _, ref := range detail.References {
				fmt.Printf("  - [%s] %s\n", ref.Type, ref.URL)
			}
		}

		// OSV Credits
		if len(detail.Credits) > 0 {
			fmt.Printf("Credits (OSV):\n")
			for _, credit := range detail.Credits {
				ctype := string(credit.Type)
				if ctype == "" {
					ctype = "OTHER"
				}
				fmt.Printf("  - %s (%s)\n", credit.Name, ctype)
			}
		}

		fmt.Println()
	}

	fmt.Printf("\n%d result(s) found.\n", len(results))
	return nil
}

// outputDetailJSON prints enriched detail as JSON for each vulnerability.
func outputDetailJSON(ctx context.Context, s *store.PostgresStore, results []*model.Vulnerability) error {
	var details []*model.VulnerabilityDetail
	for _, vuln := range results {
		detail, err := s.GetVulnerabilityDetail(ctx, vuln.ID)
		if err != nil {
			return fmt.Errorf("get detail for %s: %w", vuln.ID, err)
		}
		if detail != nil {
			details = append(details, detail)
		}
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(details); err != nil {
		return fmt.Errorf("encode JSON: %w", err)
	}
	return nil
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

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)

	addr := fs.String("addr", ":8080", "Address to listen on (host:port)")
	dbURL := fs.String("db-url", "", "PostgreSQL connection URL (default: $DATABASE_URL or localhost)")

	fs.Usage = func() {
		fmt.Println("Usage: mayu serve [options]")
		fmt.Println()
		fmt.Println("Start the Mayu API server.")
		fmt.Println()
		fmt.Println("The server exposes REST API endpoints for vulnerability search,")
		fmt.Println("matching the functionality of the 'mayu search' command.")
		fmt.Println()
		fmt.Println("Endpoints:")
		fmt.Println("  GET /api/v1/vulnerabilities       Search vulnerabilities")
		fmt.Println("  GET /api/v1/vulnerabilities/{id}  Get vulnerability by ID")
		fmt.Println("  GET /healthz                      Health check")
		fmt.Println("  GET /openapi.yaml                 OpenAPI specification")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  mayu serve")
		fmt.Println("  mayu serve --addr :3000")
		fmt.Println("  mayu serve --db-url postgres://user:pass@host/db")
	}

	if err := fs.Parse(args); err != nil {
		return err
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

	// Create and start server
	srv := server.New(server.Config{
		Addr:    *addr,
		Store:   s,
		Version: version,
	})

	// Start server in goroutine.
	// errCh is buffered (cap 1) so the goroutine never blocks on send.
	// On graceful shutdown (ErrServerClosed), the channel is closed without
	// sending an error, causing the select below to receive nil.
	errCh := make(chan error, 1)
	go func() {
		fmt.Printf("Mayu API server starting on %s\n", *addr)
		fmt.Printf("  API:     http://localhost%s/api/v1/vulnerabilities\n", *addr)
		fmt.Printf("  OpenAPI: http://localhost%s/openapi.yaml\n", *addr)
		fmt.Printf("  Health:  http://localhost%s/healthz\n", *addr)
		fmt.Println()
		fmt.Println("Press Ctrl+C to stop.")

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	// Wait for interrupt or error
	select {
	case <-ctx.Done():
		fmt.Println("\nShutting down server...")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("server shutdown: %w", err)
		}
		fmt.Println("Server stopped.")
		return nil
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("server error: %w", err)
		}
		return nil
	}
}
