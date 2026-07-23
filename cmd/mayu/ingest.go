package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/kato83/mayu/internal/config"
	"github.com/kato83/mayu/internal/fetcher"
	"github.com/kato83/mayu/internal/ingest"
	"github.com/kato83/mayu/internal/model"
	"github.com/kato83/mayu/internal/parser"
	"github.com/kato83/mayu/internal/store"
)

func runIngest(args []string, cfg *config.Config) error {
	fs := flag.NewFlagSet("ingest", flag.ExitOnError)

	ecosystem := fs.String("ecosystem", "", "Ecosystem to import (e.g., Go, PyPI, npm)")
	source := fs.String("source", "", "Import from source (nvd, debian, mitre, epss, kev, ghsa)")
	all := fs.Bool("all", false, "Import all ecosystems")
	bulk := fs.Bool("bulk", false, "Use top-level all.zip for bulk import (with --all)")
	update := fs.Bool("update", false, "Perform delta update instead of full import")
	backfill := fs.Bool("backfill", false, "Backfill historical data (with --source epss)")
	fromDate := fs.String("from", "", "Start date for backfill (YYYY-MM-DD, default: 2023-03-07 for EPSS v3)")
	toDate := fs.String("to", "", "End date for backfill (YYYY-MM-DD, default: today)")
	concurrency := fs.Int("concurrency", 3, "Number of ecosystems to import in parallel (with --all)")
	batchSize := fs.Int("batch-size", 100, "Number of vulnerabilities per batch insert")
	storeWorkers := fs.Int("store-workers", ingest.DefaultStoreWorkers(), "Number of parallel DB store workers per ecosystem")
	native := fs.Bool("native", false, "Use native data source feed instead of OSV conversion (with --source nvd)")
	year := fs.Int("year", 0, "Import only a specific year's NVD feed (e.g., 2024; with --source nvd --native)")
	fileMode := fs.Bool("file", false, "Import from local OSV JSON files (paths as positional arguments)")
	ghsaRepo := fs.String("repo", "", "GitHub repository (owner/repo) for --source ghsa")

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
		fmt.Println("  mayu ingest --source nvd --native --year 2024  # Import only 2024 NVD data")
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
		fmt.Println("  mayu ingest --source ghsa --repo WordPress/wordpress-develop  # Import GitHub repo advisories")
		fmt.Println("  mayu ingest --file vuln1.json vuln2.json # Import local OSV JSON files")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Validate flags
	if !*all && *ecosystem == "" && *source == "" && !*fileMode {
		return fmt.Errorf("either --ecosystem, --source, --all, or --file is required")
	}

	// Resolve database URL
	databaseURL := resolveDatabaseURL(cfg)

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

		// Record ingest job
		jobStart := time.Now().UTC()
		jobID, _ := s.CreateIngestJob(ctx, &store.IngestJob{
			CommandArgs: map[string]interface{}{"file": true, "files": files},
			Source:      "file",
			StartedAt:   jobStart,
			Status:      "running",
		})

		p := parser.New()
		var imported, failed int

		fmt.Printf("\n=== Importing %d local OSV JSON file(s) ===\n", len(files))
		for _, path := range files {
			data, err := os.ReadFile(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", path, err)
				failed++
				if jobID > 0 {
					_ = s.RecordIngestFailure(ctx, &store.IngestFailure{
						JobID: jobID, VulnID: path, ErrorType: "fetch_error",
						ErrorMessage: strPtr(err.Error()), FailedAt: time.Now().UTC(),
					})
				}
				continue
			}

			var vuln *model.Vulnerability

			// Auto-detect GitHub REST API advisory format and convert to OSV
			if parser.IsGitHubAdvisoryJSON(data) {
				vuln, err = parser.ConvertGitHubToOSV(data)
				if err != nil {
					fmt.Fprintf(os.Stderr, "  ✗ %s: GitHub→OSV conversion error: %v\n", path, err)
					failed++
					if jobID > 0 {
						_ = s.RecordIngestFailure(ctx, &store.IngestFailure{
							JobID: jobID, VulnID: path, ErrorType: "parse_error",
							ErrorMessage: strPtr(err.Error()), FailedAt: time.Now().UTC(),
						})
					}
					continue
				}
				fmt.Printf("  ℹ %s: detected GitHub Advisory format, converted to OSV\n", path)
			} else {
				vuln, err = p.Parse(data)
				if err != nil {
					fmt.Fprintf(os.Stderr, "  ✗ %s: parse error: %v\n", path, err)
					failed++
					if jobID > 0 {
						_ = s.RecordIngestFailure(ctx, &store.IngestFailure{
							JobID: jobID, VulnID: path, ErrorType: "parse_error",
							ErrorMessage: strPtr(err.Error()), FailedAt: time.Now().UTC(),
						})
					}
					continue
				}
				// Set RawJSON for storage (preserves original JSON)
				vuln.RawJSON = data
			}

			if err := s.Insert(ctx, vuln); err != nil {
				fmt.Fprintf(os.Stderr, "  ✗ %s (id=%s): insert error: %v\n", path, vuln.ID, err)
				failed++
				if jobID > 0 {
					_ = s.RecordIngestFailure(ctx, &store.IngestFailure{
						JobID: jobID, VulnID: vuln.ID, ErrorType: "store_error",
						ErrorMessage: strPtr(err.Error()), FailedAt: time.Now().UTC(),
					})
				}
				continue
			}

			fmt.Printf("  ✓ %s (id=%s, aliases=%v)\n", path, vuln.ID, vuln.Aliases)
			imported++
		}

		// Finalize job record
		if jobID > 0 {
			now := time.Now().UTC()
			total := imported + failed
			status := "success"
			if failed > 0 && imported > 0 {
				status = "partial"
			} else if failed > 0 {
				status = "failed"
			}
			_ = s.UpdateIngestJob(ctx, &store.IngestJob{
				ID: jobID, FinishedAt: &now, Status: status,
				TotalCount: &total, SuccessCount: &imported, FailureCount: &failed,
			})
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
		ingest.WithJobRecorder(s),
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
				if *year != 0 {
					return fmt.Errorf("--year cannot be used with --update (delta update covers all modified CVEs)")
				}
				stats, err = ing.UpdateNVDNative(ctx)
			} else {
				var years []int
				if *year != 0 {
					years = []int{*year}
					fmt.Printf("  Filtering to year: %d\n", *year)
				}
				stats, err = ing.ImportNVDNativeYears(ctx, years)
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

		// GitHub repository security advisories import
		if strings.ToLower(*source) == "ghsa" {
			if *ghsaRepo == "" {
				return fmt.Errorf("--repo is required with --source ghsa (format: owner/repo)")
			}
			parts := strings.SplitN(*ghsaRepo, "/", 2)
			if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
				return fmt.Errorf("--repo must be in owner/repo format (e.g., WordPress/wordpress-develop)")
			}
			owner, repo := parts[0], parts[1]

			// Use GITHUB_TOKEN environment variable if available
			token := os.Getenv("GITHUB_TOKEN")

			fmt.Printf("\n=== Importing GitHub Security Advisories (%s/%s) ===\n", owner, repo)

			// Record ingest job
			jobStart := time.Now().UTC()
			jobID, _ := s.CreateIngestJob(ctx, &store.IngestJob{
				CommandArgs: map[string]interface{}{"source": "ghsa", "repo": *ghsaRepo},
				Source:      "ghsa",
				StartedAt:   jobStart,
				Status:      "running",
			})

			// Fetch advisories from GitHub API
			advisoryData, err := f.FetchGitHubAdvisories(ctx, owner, repo, token)
			if err != nil {
				if ctx.Err() != nil {
					fmt.Fprintf(os.Stderr, "\nImport interrupted.\n")
					if jobID > 0 {
						now := time.Now().UTC()
						zero := 0
						_ = s.UpdateIngestJob(ctx, &store.IngestJob{
							ID: jobID, FinishedAt: &now, Status: "failed",
							TotalCount: &zero, SuccessCount: &zero, FailureCount: &zero,
							ErrorMessage: strPtr("import interrupted"),
						})
					}
					return nil
				}
				if jobID > 0 {
					now := time.Now().UTC()
					zero := 0
					msg := err.Error()
					_ = s.UpdateIngestJob(ctx, &store.IngestJob{
						ID: jobID, FinishedAt: &now, Status: "failed",
						TotalCount: &zero, SuccessCount: &zero, FailureCount: &zero,
						ErrorMessage: &msg,
					})
				}
				return fmt.Errorf("fetch GitHub advisories: %w", err)
			}

			if len(advisoryData) == 0 {
				fmt.Println("  No published advisories found.")
				if jobID > 0 {
					now := time.Now().UTC()
					zero := 0
					_ = s.UpdateIngestJob(ctx, &store.IngestJob{
						ID: jobID, FinishedAt: &now, Status: "success",
						TotalCount: &zero, SuccessCount: &zero, FailureCount: &zero,
					})
				}
				return nil
			}

			fmt.Printf("  Found %d published advisory(ies)\n", len(advisoryData))

			var imported, failed int
			for _, data := range advisoryData {
				vuln, err := parser.ConvertGitHubToOSV(data)
				if err != nil {
					fmt.Fprintf(os.Stderr, "  ✗ conversion error: %v\n", err)
					failed++
					if jobID > 0 {
						_ = s.RecordIngestFailure(ctx, &store.IngestFailure{
							JobID: jobID, VulnID: "unknown", ErrorType: "parse_error",
							ErrorMessage: strPtr(err.Error()), FailedAt: time.Now().UTC(),
						})
					}
					continue
				}

				if err := s.Insert(ctx, vuln); err != nil {
					fmt.Fprintf(os.Stderr, "  ✗ %s: insert error: %v\n", vuln.ID, err)
					failed++
					if jobID > 0 {
						_ = s.RecordIngestFailure(ctx, &store.IngestFailure{
							JobID: jobID, VulnID: vuln.ID, ErrorType: "store_error",
							ErrorMessage: strPtr(err.Error()), FailedAt: time.Now().UTC(),
						})
					}
					continue
				}

				fmt.Printf("  ✓ %s (aliases=%v)\n", vuln.ID, vuln.Aliases)
				imported++
			}

			// Finalize job record
			if jobID > 0 {
				now := time.Now().UTC()
				total := imported + failed
				status := "success"
				if failed > 0 && imported > 0 {
					status = "partial"
				} else if failed > 0 {
					status = "failed"
				}
				_ = s.UpdateIngestJob(ctx, &store.IngestJob{
					ID: jobID, FinishedAt: &now, Status: status,
					TotalCount: &total, SuccessCount: &imported, FailureCount: &failed,
				})
			}

			fmt.Printf("\nDone: %d imported, %d failed\n", imported, failed)
			if failed > 0 {
				return fmt.Errorf("%d advisory(ies) failed to import", failed)
			}
			return nil
		}

		// Existing converted source logic
		src := ingest.GetConvertedSource(*source)
		if src == nil {
			return fmt.Errorf("unknown source: %q (supported: nvd, debian, mitre, epss, kev, ghsa)", *source)
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
				ingest.WithJobRecorder(s),
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
	case "summary":
		if p.Total > 0 && p.Current > 0 {
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

// strPtr returns a pointer to the given string.
func strPtr(s string) *string {
	return &s
}
