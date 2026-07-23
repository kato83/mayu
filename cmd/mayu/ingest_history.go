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
	"github.com/kato83/mayu/internal/store"
)

func runIngestHistory(args []string, cfg *config.Config) error {
	fs := flag.NewFlagSet("ingest history", flag.ExitOnError)

	limit := fs.Int("limit", 20, "Number of recent jobs to display")
	jobID := fs.Int64("job-id", 0, "Show details for a specific job ID")
	formatFlag := fs.String("format", "table", "Output format: table, json")

	fs.Usage = func() {
		fmt.Println("Usage: mayu ingest history [options]")
		fmt.Println()
		fmt.Println("Show ingest job history.")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  mayu ingest history")
		fmt.Println("  mayu ingest history --limit 10")
		fmt.Println("  mayu ingest history --job-id 42")
		fmt.Println("  mayu ingest history --format json")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	databaseURL := resolveDatabaseURL(cfg)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	s, err := store.NewPostgresStore(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer func() { _ = s.Close() }()

	if *jobID > 0 {
		// Show single job detail
		job, err := s.GetIngestJob(ctx, *jobID)
		if err != nil {
			return fmt.Errorf("get job: %w", err)
		}
		if job == nil {
			return fmt.Errorf("job %d not found", *jobID)
		}
		if *formatFlag == "json" {
			return printIngestJobJSON(job)
		}
		printIngestJobDetail(job)
		return nil
	}

	// List recent jobs
	jobs, err := s.ListIngestJobs(ctx, *limit)
	if err != nil {
		return fmt.Errorf("list jobs: %w", err)
	}

	if len(jobs) == 0 {
		fmt.Println("No ingest jobs recorded.")
		return nil
	}

	if *formatFlag == "json" {
		return printIngestJobsJSON(jobs)
	}
	printIngestJobsTable(jobs)
	return nil
}

// printIngestJobsTable prints a formatted table of ingest jobs.
func printIngestJobsTable(jobs []store.IngestJob) {
	// Header
	fmt.Printf("%-6s %-16s %-9s %-20s %-12s %7s %7s %7s\n",
		"ID", "Source", "Status", "Started", "Duration", "Total", "OK", "Fail")
	fmt.Println(strings.Repeat("-", 96))

	for _, job := range jobs {
		duration := ""
		if job.FinishedAt != nil {
			d := job.FinishedAt.Sub(job.StartedAt)
			duration = formatDuration(d)
		} else if job.Status == "running" {
			duration = "running"
		}

		total := "-"
		if job.TotalCount != nil {
			total = fmt.Sprintf("%d", *job.TotalCount)
		}
		success := "-"
		if job.SuccessCount != nil {
			success = fmt.Sprintf("%d", *job.SuccessCount)
		}
		failed := "-"
		if job.FailureCount != nil {
			failed = fmt.Sprintf("%d", *job.FailureCount)
		}

		started := job.StartedAt.Local().Format("2006-01-02 15:04:05")

		fmt.Printf("%-6d %-16s %-9s %-20s %-12s %7s %7s %7s\n",
			job.ID, truncate(job.Source, 16), job.Status, started, duration, total, success, failed)
	}
}

// printIngestJobDetail prints detailed information about a single job.
func printIngestJobDetail(job *store.IngestJob) {
	fmt.Printf("Job #%d\n", job.ID)
	fmt.Println(strings.Repeat("=", 40))
	fmt.Printf("  Source:       %s\n", job.Source)
	fmt.Printf("  Status:       %s\n", job.Status)
	fmt.Printf("  Started:      %s\n", job.StartedAt.Local().Format(time.RFC3339))
	if job.FinishedAt != nil {
		fmt.Printf("  Finished:     %s\n", job.FinishedAt.Local().Format(time.RFC3339))
		fmt.Printf("  Duration:     %s\n", formatDuration(job.FinishedAt.Sub(job.StartedAt)))
	}
	if job.TotalCount != nil {
		fmt.Printf("  Total:        %d\n", *job.TotalCount)
	}
	if job.SuccessCount != nil {
		fmt.Printf("  Success:      %d\n", *job.SuccessCount)
	}
	if job.FailureCount != nil {
		fmt.Printf("  Failures:     %d\n", *job.FailureCount)
	}
	if job.CommandArgs != nil {
		argsJSON, _ := json.Marshal(job.CommandArgs)
		fmt.Printf("  Command Args: %s\n", string(argsJSON))
	}
	if job.ErrorMessage != nil {
		fmt.Printf("  Error:        %s\n", *job.ErrorMessage)
	}

	if len(job.Failures) > 0 {
		fmt.Printf("\n  Failures (%d):\n", len(job.Failures))
		fmt.Printf("  %-40s %-14s %s\n", "Vuln ID", "Error Type", "Message")
		fmt.Printf("  %s\n", strings.Repeat("-", 80))
		for _, f := range job.Failures {
			msg := ""
			if f.ErrorMessage != nil {
				msg = *f.ErrorMessage
				if len(msg) > 60 {
					msg = msg[:57] + "..."
				}
			}
			fmt.Printf("  %-40s %-14s %s\n", truncate(f.VulnID, 40), f.ErrorType, msg)
		}
	}
}

// printIngestJobJSON outputs a single job as JSON.
func printIngestJobJSON(job *store.IngestJob) error {
	data, err := json.MarshalIndent(jobToJSONMap(job), "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}
	_, err = os.Stdout.Write(data)
	if err != nil {
		return err
	}
	fmt.Println()
	return nil
}

// printIngestJobsJSON outputs a list of jobs as JSON.
func printIngestJobsJSON(jobs []store.IngestJob) error {
	var items []map[string]interface{}
	for i := range jobs {
		items = append(items, jobToJSONMap(&jobs[i]))
	}
	data, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}
	_, err = os.Stdout.Write(data)
	if err != nil {
		return err
	}
	fmt.Println()
	return nil
}

// jobToJSONMap converts an IngestJob to a map suitable for JSON output.
func jobToJSONMap(job *store.IngestJob) map[string]interface{} {
	m := map[string]interface{}{
		"id":         job.ID,
		"source":     job.Source,
		"status":     job.Status,
		"started_at": job.StartedAt.Format(time.RFC3339),
	}
	if job.FinishedAt != nil {
		m["finished_at"] = job.FinishedAt.Format(time.RFC3339)
		m["duration_seconds"] = job.FinishedAt.Sub(job.StartedAt).Seconds()
	}
	if job.CommandArgs != nil {
		m["command_args"] = job.CommandArgs
	}
	if job.TotalCount != nil {
		m["total_count"] = *job.TotalCount
	}
	if job.SuccessCount != nil {
		m["success_count"] = *job.SuccessCount
	}
	if job.FailureCount != nil {
		m["failure_count"] = *job.FailureCount
	}
	if job.ErrorMessage != nil {
		m["error_message"] = *job.ErrorMessage
	}
	if len(job.Failures) > 0 {
		var failures []map[string]interface{}
		for _, f := range job.Failures {
			fm := map[string]interface{}{
				"id":         f.ID,
				"vuln_id":    f.VulnID,
				"error_type": f.ErrorType,
				"failed_at":  f.FailedAt.Format(time.RFC3339),
			}
			if f.ErrorMessage != nil {
				fm["error_message"] = *f.ErrorMessage
			}
			failures = append(failures, fm)
		}
		m["failures"] = failures
	}
	return m
}

// formatDuration formats a duration in a human-readable way.
func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	if d < time.Hour {
		m := int(d.Minutes())
		s := int(d.Seconds()) % 60
		return fmt.Sprintf("%dm%ds", m, s)
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	return fmt.Sprintf("%dh%dm", h, m)
}

// truncate truncates a string to the given max length, appending "..." if needed.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
