package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"strings"
	"time"

	"github.com/kato83/mayu/internal/config"
	"github.com/kato83/mayu/internal/store"
)

// runStatus executes the 'status' subcommand which displays data source sync states
// and EPSS coverage information.
func runStatus(args []string, cfg *config.Config) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	format := fs.String("format", "table", "Output format: table, json")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: mayu status [options]\n\nShow data source sync status and EPSS coverage.\n\nOptions:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Validate format
	switch *format {
	case "table", "json":
	default:
		return fmt.Errorf("invalid format %q (valid: table, json)", *format)
	}

	// Connect to database
	dbURL := resolveDatabaseURL(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s, err := store.NewPostgresStore(ctx, dbURL)
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer func() { _ = s.Close() }()

	// Fetch data
	states, err := s.ListSyncStates(ctx)
	if err != nil {
		return fmt.Errorf("list sync states: %w", err)
	}

	coverage, err := s.GetEPSSCoverage(ctx)
	if err != nil {
		return fmt.Errorf("get EPSS coverage: %w", err)
	}

	switch *format {
	case "json":
		return printStatusJSON(states, coverage)
	default:
		printStatusTable(states, coverage)
		return nil
	}
}

// statusJSON is the JSON output structure for the status command.
type statusJSON struct {
	SyncStates   []syncStateJSON   `json:"sync_states"`
	EPSSCoverage *epssCoverageJSON `json:"epss_coverage"`
}

type syncStateJSON struct {
	Source         string `json:"source"`
	SourceType     string `json:"source_type"`
	LastModifiedAt string `json:"last_modified_at"`
	LastSyncedAt   string `json:"last_synced_at"`
	RecordCount    int64  `json:"record_count"`
}

type epssCoverageJSON struct {
	TotalDays    int      `json:"total_days"`
	FirstDate    string   `json:"first_date"`
	LastDate     string   `json:"last_date"`
	TotalScores  int64    `json:"total_scores"`
	MissingDates []string `json:"missing_dates"`
}

func printStatusJSON(states []store.SyncState, coverage *store.EPSSCoverage) error {
	out := statusJSON{
		SyncStates: make([]syncStateJSON, 0, len(states)),
	}
	for _, s := range states {
		out.SyncStates = append(out.SyncStates, syncStateJSON{
			Source:         s.Source,
			SourceType:     s.SourceType,
			LastModifiedAt: s.LastModifiedAt,
			LastSyncedAt:   s.LastSyncedAt,
			RecordCount:    s.RecordCount,
		})
	}
	if coverage != nil {
		missingDates := coverage.MissingDates
		if missingDates == nil {
			missingDates = []string{}
		}
		out.EPSSCoverage = &epssCoverageJSON{
			TotalDays:    coverage.TotalDays,
			FirstDate:    coverage.FirstDate,
			LastDate:     coverage.LastDate,
			TotalScores:  coverage.TotalScores,
			MissingDates: missingDates,
		}
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func printStatusTable(states []store.SyncState, coverage *store.EPSSCoverage) {
	fmt.Println("Data Source Status:")
	fmt.Println()

	if len(states) == 0 {
		fmt.Println("  No sync state records found. Run 'mayu ingest' to import data.")
		fmt.Println()
	} else {
		// Calculate column widths
		srcTypeW := len("Source Type")
		srcW := len("Source")
		for _, s := range states {
			if len(s.SourceType) > srcTypeW {
				srcTypeW = len(s.SourceType)
			}
			if len(s.Source) > srcW {
				srcW = len(s.Source)
			}
		}

		// Print header
		fmt.Printf("%-*s  %-*s  %-19s  %s\n", srcTypeW, "Source Type", srcW, "Source", "Last Synced", "Record Count")
		fmt.Printf("%s  %s  %s  %s\n",
			strings.Repeat("-", srcTypeW),
			strings.Repeat("-", srcW),
			strings.Repeat("-", 19),
			strings.Repeat("-", 12))

		// Print rows
		for _, s := range states {
			synced := formatTimestamp(s.LastSyncedAt)
			fmt.Printf("%-*s  %-*s  %-19s  %s\n",
				srcTypeW, s.SourceType,
				srcW, s.Source,
				synced,
				formatCount(s.RecordCount))
		}
		fmt.Println()
	}

	// EPSS Coverage
	if coverage != nil && coverage.TotalDays > 0 {
		fmt.Println("EPSS Coverage:")

		// Calculate expected days
		expectedDays := 0
		if coverage.FirstDate != "" && coverage.LastDate != "" {
			first, err1 := time.Parse("2006-01-02", coverage.FirstDate)
			last, err2 := time.Parse("2006-01-02", coverage.LastDate)
			if err1 == nil && err2 == nil {
				expectedDays = int(last.Sub(first).Hours()/24) + 1
			}
		}

		fmt.Printf("  Date Range: %s to %s\n", coverage.FirstDate, coverage.LastDate)
		if expectedDays > 0 {
			pct := float64(coverage.TotalDays) / float64(expectedDays) * 100
			pct = math.Min(pct, 100.0)
			fmt.Printf("  Days Covered: %s / %s (%.1f%%)\n",
				formatCount(int64(coverage.TotalDays)),
				formatCount(int64(expectedDays)),
				pct)
		} else {
			fmt.Printf("  Days Covered: %s\n", formatCount(int64(coverage.TotalDays)))
		}
		fmt.Printf("  Total Scores: %s\n", formatCount(coverage.TotalScores))
		if len(coverage.MissingDates) > 0 {
			fmt.Printf("  Missing Days: %d\n", len(coverage.MissingDates))
			// Show up to 20 missing dates, then summarize
			maxShow := 20
			for i, d := range coverage.MissingDates {
				if i >= maxShow {
					fmt.Printf("    ... and %d more\n", len(coverage.MissingDates)-maxShow)
					break
				}
				fmt.Printf("    %s\n", d)
			}
		}
	}
}

// formatTimestamp formats an RFC3339 timestamp into a human-readable local time.
func formatTimestamp(ts string) string {
	if ts == "" {
		return "-"
	}
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		t, err = time.Parse(time.RFC3339, ts)
		if err != nil {
			return ts
		}
	}
	return t.Local().Format("2006-01-02 15:04:05")
}

// formatCount formats a number with thousand separators.
func formatCount(n int64) string {
	if n < 0 {
		return "-" + formatCount(-n)
	}
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}

	// Insert commas from right
	var result strings.Builder
	remainder := len(s) % 3
	if remainder > 0 {
		result.WriteString(s[:remainder])
		if len(s) > remainder {
			result.WriteByte(',')
		}
	}
	for i := remainder; i < len(s); i += 3 {
		if i > remainder {
			result.WriteByte(',')
		}
		result.WriteString(s[i : i+3])
	}
	return result.String()
}
