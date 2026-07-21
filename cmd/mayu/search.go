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
	"time"

	"github.com/kato83/mayu/internal/config"
	"github.com/kato83/mayu/internal/model"
	purlpkg "github.com/kato83/mayu/internal/purl"
	"github.com/kato83/mayu/internal/store"
	"github.com/kato83/mayu/internal/validate"
)

func runSearch(args []string, cfg *config.Config) error {
	fs := flag.NewFlagSet("search", flag.ExitOnError)

	id := fs.String("id", "", "Search by vulnerability ID (e.g., CVE-2024-1234, GO-2024-2687)")
	pkg := fs.String("package", "", "Search by package name (e.g., golang.org/x/crypto)")
	ecosystem := fs.String("ecosystem", "", "Filter by ecosystem (e.g., Go, PyPI)")
	purl := fs.String("purl", "", "Search by Package URL (e.g., pkg:golang/golang.org/x/crypto)")
	severity := fs.String("severity", "", "Filter by severity level (critical, high, medium, low, none). Note: filters by CVSS score range; entries without scores are excluded")
	since := fs.String("since", "", "Filter by modified date (YYYY-MM-DD or RFC3339)")
	version := fs.String("version", "", "Filter by affected version")
	format := fs.String("format", "table", "Output format: table, json, csv")
	limit := fs.Int("limit", 20, "Maximum number of results")
	offset := fs.Int("offset", 0, "Offset for pagination (deprecated: use --starting-token)")
	startingToken := fs.String("starting-token", "", "Cursor token for pagination (from previous NextToken output)")
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
		fmt.Println("  mayu search --purl pkg:golang/golang.org/x/crypto")
		fmt.Println("  mayu search --severity critical --ecosystem Go")
		fmt.Println("  mayu search --since 2024-01-01 --ecosystem npm")
		fmt.Println("  mayu search --package net/http --version 1.21.0")
		fmt.Println("  mayu search --package net/http --format json")
		fmt.Println("  mayu search --package net/http --format csv")
		fmt.Println("  mayu search --ecosystem Go --count")
		fmt.Println("  mayu search --id GO-2024-2687 --detail")
		fmt.Println("  mayu search --ecosystem Go --offset 20 --limit 10")
		fmt.Println("  mayu search --ecosystem Go --starting-token <token>  # cursor-based pagination")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Validate severity flag
	if *severity != "" {
		validSeverities := []string{"critical", "high", "medium", "low", "none", "unknown"}
		valid := false
		for _, s := range validSeverities {
			if strings.ToLower(*severity) == s {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("invalid severity %q (valid: critical, high, medium, low, none, unknown)", *severity)
		}
	}

	// Validate --since date format
	if *since != "" {
		if err := validate.DateInput(*since); err != nil {
			return fmt.Errorf("invalid --since value %q: %w", *since, err)
		}
	}

	// If positional argument provided and no flags set, treat as ID search
	if *id == "" && *pkg == "" && *ecosystem == "" && *purl == "" {
		if fs.NArg() > 0 {
			*id = strings.Join(fs.Args(), " ")
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
		Severity:    *severity,
		Since:       *since,
		Version:     *version,
		Limit:       *limit,
		Offset:      *offset,
		Cursor:      *startingToken,
	}

	// Resolve database URL
	databaseURL := resolveDatabaseURL(*dbURL, cfg)

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

	// Compute NextToken if there are more results
	var nextToken string
	if len(results) == *limit {
		last := results[len(results)-1]
		nextToken = store.EncodeCursor(last.Published, last.ID)
	}

	// Output results
	switch *format {
	case "json":
		if *detail {
			if err := outputDetailJSON(ctx, s, results); err != nil {
				return err
			}
		} else {
			if err := outputJSON(results, nextToken); err != nil {
				return err
			}
		}
	case "csv":
		outputCSV(results)
	case "table":
		if *detail {
			if err := outputDetailEnriched(ctx, s, results); err != nil {
				return err
			}
		} else {
			outputTable(results)
		}
	default:
		return fmt.Errorf("unknown format: %q (supported: table, json, csv)", *format)
	}

	// Print NextToken to stderr for scripting (except JSON which includes it inline)
	if nextToken != "" && *format != "json" {
		fmt.Fprintf(os.Stderr, "\nNextToken: %s\n", nextToken)
	}

	return nil
}

// outputJSON prints results as a JSON object with vulnerabilities array and optional next_token.
func outputJSON(vulns []*model.Vulnerability, nextToken string) error {
	fmt.Print("{\"vulnerabilities\":[")
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
	fmt.Print("]")
	if nextToken != "" {
		fmt.Printf(",\"next_token\":%q", nextToken)
	}
	fmt.Println("}")
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
	fmt.Printf("%-20s %-15s %-10s %-12s %-30s %s\n", "ID", "ALIASES", "SEVERITY", "MODIFIED", "SUMMARY", "PACKAGES")
	fmt.Printf("%-20s %-15s %-10s %-12s %-30s %s\n",
		strings.Repeat("-", 20),
		strings.Repeat("-", 15),
		strings.Repeat("-", 10),
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

		fmt.Printf("%-20s %-15s %-10s %-12s %-30s %s\n", vuln.ID, aliasStr, sevStr, modified, summary, pkgStr)
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
// Returns a string like "CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE".
// Uses the pre-computed severity level from vulnerability_summary when available.
func formatSeverity(vuln *model.Vulnerability) string {
	if vuln.SeverityLevel > 0 {
		return model.SeverityLevelName(vuln.SeverityLevel)
	}
	return "-"
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
