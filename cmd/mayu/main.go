package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/kato83/mayu/internal/fetcher"
	"github.com/kato83/mayu/internal/ingest"
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
	fmt.Println("  version    Print version information")
	fmt.Println("  help       Show this help message")
	fmt.Println()
	fmt.Println("Run 'mayu <command> --help' for more information on a command.")
}

func runIngest(args []string) error {
	fs := flag.NewFlagSet("ingest", flag.ExitOnError)

	ecosystem := fs.String("ecosystem", "", "Ecosystem to import (e.g., Go, PyPI, npm)")
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
		fmt.Println("  mayu ingest --ecosystem go")
		fmt.Println("  mayu ingest --ecosystem go --update")
		fmt.Println("  mayu ingest --all")
		fmt.Println("  mayu ingest --ecosystem PyPI --db-url postgres://user:pass@host/db")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Validate flags
	if !*all && *ecosystem == "" {
		return fmt.Errorf("either --ecosystem or --all is required")
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
	defer s.Close()

	// Create fetcher and parser
	f := fetcher.New()
	p := parser.New()

	// Create ingester with progress output
	ing := ingest.New(f, p, s,
		ingest.WithBatchSize(*batchSize),
		ingest.WithProgress(printProgress),
	)

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
