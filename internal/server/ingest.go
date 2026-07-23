package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/kato83/mayu/internal/fetcher"
	"github.com/kato83/mayu/internal/ingest"
	"github.com/kato83/mayu/internal/parser"
	"github.com/kato83/mayu/internal/store"
)

// ingestRequest is the JSON request body for POST /api/v1/ingest.
type ingestRequest struct {
	Type      string `json:"type"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Repo      string `json:"repo,omitempty"` // owner/repo for ghsa type
	From      string `json:"from,omitempty"` // start date for epss_backfill (YYYY-MM-DD)
	To        string `json:"to,omitempty"`   // end date for epss_backfill (YYYY-MM-DD)
}

// ingestEvent is a single SSE event sent to the client during ingestion.
type ingestEvent struct {
	Phase   string `json:"phase"`
	Current int    `json:"current,omitempty"`
	Total   int    `json:"total,omitempty"`
	Message string `json:"message,omitempty"`
}

// ingestStartResponse is the immediate response from POST /api/v1/ingest.
type ingestStartResponse struct {
	JobID int64  `json:"job_id"`
	State string `json:"status"`
}

// allowedIngestTypes is the permit-list of valid ingest type values.
var allowedIngestTypes = map[string]bool{
	"ecosystem":        true,
	"ecosystem_update": true,
	"all":              true,
	"all_bulk":         true,
	"nvd":             true,
	"nvd_update":      true,
	"nvd_converted":   true,
	"mitre":           true,
	"mitre_update":    true,
	"epss":            true,
	"epss_update":     true,
	"epss_backfill":   true,
	"kev":             true,
	"kev_update":      true,
	"debian":          true,
	"ghsa":            true,
}

// ecosystemNameRe validates ecosystem names to prevent path traversal.
var ecosystemNameRe = regexp.MustCompile(`^[A-Za-z0-9.:\-]+$`)

// ghsaRepoRe validates GitHub repository names (owner/repo format).
// Only allows alphanumeric, hyphens, underscores, and dots.
var ghsaRepoRe = regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$`)

// dateRe validates date strings in YYYY-MM-DD format.
var dateRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// handleIngest handles POST /api/v1/ingest — starts an ingest job in the
// background and returns the job ID immediately.
func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	// Reject if no fetcher configured (ingest not available).
	if s.fetcher == nil {
		writeError(w, http.StatusServiceUnavailable, "ingest not available: fetcher not configured")
		return
	}

	// Parse request body.
	var req ingestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	// Validate type.
	if !allowedIngestTypes[req.Type] {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid type %q", req.Type))
		return
	}

	// Validate ecosystem for ecosystem types.
	if req.Type == "ecosystem" || req.Type == "ecosystem_update" {
		if req.Ecosystem == "" {
			writeError(w, http.StatusBadRequest, "ecosystem is required for type "+req.Type)
			return
		}
		if !ecosystemNameRe.MatchString(req.Ecosystem) {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid ecosystem name %q", req.Ecosystem))
			return
		}

		// Validate ecosystem against known list.
		valid, err := s.isValidEcosystem(r.Context(), req.Ecosystem)
		if err != nil {
			slog.Error("failed to validate ecosystem", "ecosystem", req.Ecosystem, "error", err)
			writeError(w, http.StatusInternalServerError, "failed to validate ecosystem")
			return
		}
		if !valid {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown ecosystem %q", req.Ecosystem))
			return
		}
	}

	// Validate repo for ghsa type.
	if req.Type == "ghsa" {
		if req.Repo == "" {
			writeError(w, http.StatusBadRequest, "repo is required for type ghsa (format: owner/repo)")
			return
		}
		if !ghsaRepoRe.MatchString(req.Repo) {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid repo format %q (expected: owner/repo)", req.Repo))
			return
		}
	}

	// Validate date params for epss_backfill type.
	if req.Type == "epss_backfill" {
		if req.From != "" && !dateRe.MatchString(req.From) {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid from date %q (expected: YYYY-MM-DD)", req.From))
			return
		}
		if req.To != "" && !dateRe.MatchString(req.To) {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid to date %q (expected: YYYY-MM-DD)", req.To))
			return
		}
	}

	// Acquire exclusive ingest lock.
	if !s.ingestRunning.CompareAndSwap(false, true) {
		writeError(w, http.StatusConflict, "an ingest job is already running")
		return
	}

	// Create job record in DB.
	cmdArgs := map[string]interface{}{"type": req.Type}
	if req.Ecosystem != "" {
		cmdArgs["ecosystem"] = req.Ecosystem
	}
	if req.Repo != "" {
		cmdArgs["repo"] = req.Repo
	}
	if req.From != "" {
		cmdArgs["from"] = req.From
	}
	if req.To != "" {
		cmdArgs["to"] = req.To
	}

	source := ingestTypeToSource(req.Type)
	job := &store.IngestJob{
		CommandArgs: cmdArgs,
		Source:      source,
		StartedAt:   time.Now().UTC(),
		Status:      "running",
	}

	jobID, err := s.store.CreateIngestJob(r.Context(), job)
	if err != nil {
		s.ingestRunning.Store(false)
		slog.Error("failed to create ingest job", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to create ingest job")
		return
	}

	// Create a runner for progress tracking.
	runner := newIngestRunner(jobID)
	s.runners.start(runner)

	// Launch the ingest in a background goroutine (independent of request context).
	go s.runIngestJob(runner, job, req)

	// Return job ID immediately.
	writeJSON(w, http.StatusAccepted, ingestStartResponse{
		JobID: jobID,
		State: "running",
	})
}

// runIngestJob executes the ingest operation in the background.
func (s *Server) runIngestJob(runner *ingestRunner, job *store.IngestJob, req ingestRequest) {
	defer func() {
		s.ingestRunning.Store(false)
		runner.finish()
	}()

	// Use a background context so the job is not tied to any HTTP request.
	ctx := context.Background()

	progressFn := runner.progressCallback()

	p := parser.New()
	ing := ingest.New(s.fetcher, p, s.store, ingest.WithProgress(progressFn))

	var stats *ingest.Stats
	var ingestErr error

	switch req.Type {
	case "ecosystem":
		stats, ingestErr = ing.FullImport(ctx, req.Ecosystem)
	case "ecosystem_update":
		stats, ingestErr = ing.DeltaImport(ctx, req.Ecosystem)
	case "all":
		stats, ingestErr = s.ingestAll(ctx, ing, progressFn)
	case "all_bulk":
		stats, ingestErr = ing.BulkImportAll(ctx)
	case "nvd":
		stats, ingestErr = ing.ImportNVDNative(ctx)
	case "nvd_update":
		stats, ingestErr = ing.UpdateNVDNative(ctx)
	case "nvd_converted":
		stats, ingestErr = ing.ImportConvertedSource(ctx, fetcher.SourceNVD)
	case "mitre":
		stats, ingestErr = ing.ImportMITRE(ctx)
	case "mitre_update":
		stats, ingestErr = ing.UpdateMITRE(ctx)
	case "epss":
		stats, ingestErr = ing.ImportEPSS(ctx)
	case "epss_update":
		stats, ingestErr = ing.UpdateEPSS(ctx)
	case "epss_backfill":
		from := req.From
		to := req.To
		if from == "" {
			from = ingest.EPSSv3StartDate
		}
		if to == "" {
			to = time.Now().UTC().Format("2006-01-02")
		}
		stats, ingestErr = ing.BackfillEPSSRange(ctx, from, to)
	case "kev":
		stats, ingestErr = ing.ImportKEV(ctx)
	case "kev_update":
		stats, ingestErr = ing.UpdateKEV(ctx)
	case "debian":
		stats, ingestErr = ing.ImportConvertedSource(ctx, fetcher.SourceDebian)
	case "ghsa":
		stats, ingestErr = s.ingestGHSA(ctx, req.Repo, progressFn)
	}

	// Send final event and update DB.
	if ingestErr != nil {
		runner.appendEvent(ingestEvent{
			Phase:   "error",
			Message: ingestErr.Error(),
		})
		errMsg := ingestErr.Error()
		job.Status = "failed"
		job.ErrorMessage = &errMsg
	} else {
		msg := "completed"
		if stats != nil {
			msg = fmt.Sprintf("completed: %d inserted, %d total, %d errors in %s",
				stats.Inserted, stats.Total, stats.Errors, stats.Duration.Round(1))
			totalCount := stats.Total
			successCount := stats.Inserted
			failureCount := stats.Errors
			job.TotalCount = &totalCount
			job.SuccessCount = &successCount
			job.FailureCount = &failureCount
		}
		runner.appendEvent(ingestEvent{
			Phase:   "done",
			Message: msg,
		})
		if stats != nil && stats.Errors > 0 {
			job.Status = "partial"
		} else {
			job.Status = "success"
		}
	}

	now := time.Now().UTC()
	job.FinishedAt = &now

	if err := s.store.UpdateIngestJob(ctx, job); err != nil {
		slog.Error("failed to update ingest job", "job_id", job.ID, "error", err)
	}
}

// handleIngestJobStream handles GET /api/v1/ingest/jobs/{id}/stream — streams
// progress events via SSE. Supports late-joining: sends all events from offset 0
// and then waits for new events until the job completes.
func (s *Server) handleIngestJobStream(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	jobID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid job ID")
		return
	}

	// Look for an active runner with this job ID.
	runner := s.runners.getByID(jobID)
	if runner == nil {
		// No active runner — the job may have already completed.
		// Return the final status from the DB.
		job, err := s.store.GetIngestJob(r.Context(), jobID)
		if err != nil {
			slog.Error("failed to get ingest job for stream", "id", jobID, "error", err)
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}
		if job == nil {
			writeError(w, http.StatusNotFound, "ingest job not found")
			return
		}
		// Send a single SSE event with the final status.
		flusher, ok := w.(http.Flusher)
		if !ok {
			writeError(w, http.StatusInternalServerError, "streaming not supported")
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)

		phase := "done"
		msg := fmt.Sprintf("job %d finished with status: %s", job.ID, job.Status)
		if job.Status == "failed" {
			phase = "error"
			if job.ErrorMessage != nil {
				msg = *job.ErrorMessage
			}
		}
		s.writeSSE(w, flusher, ingestEvent{Phase: phase, Message: msg})
		return
	}

	// Set up SSE streaming.
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ctx := r.Context()
	offset := 0

	for {
		events, done := runner.snapshot(offset)
		for _, evt := range events {
			s.writeSSE(w, flusher, evt)
		}
		offset += len(events)

		if done {
			return
		}

		// Wait for new events or client disconnect.
		runner.wait(ctx)
		if ctx.Err() != nil {
			return
		}
	}
}

// ingestAll imports all ecosystems sequentially (matching CLI --all behavior).
func (s *Server) ingestAll(ctx context.Context, ing *ingest.Ingester, progressFn func(ingest.Progress)) (*ingest.Stats, error) {
	ecosystems, err := s.fetcher.ListEcosystems(ctx)
	if err != nil {
		return nil, fmt.Errorf("list ecosystems: %w", err)
	}

	totalStats := &ingest.Stats{
		Ecosystem:  "all",
		IsFullSync: true,
	}

	for i, eco := range ecosystems {
		select {
		case <-ctx.Done():
			return totalStats, ctx.Err()
		default:
		}

		progressFn(ingest.Progress{
			Phase:   "download",
			Current: i + 1,
			Total:   len(ecosystems),
			Message: fmt.Sprintf("Importing ecosystem: %s", eco),
		})

		stats, err := ing.FullImport(ctx, eco)
		if err != nil {
			slog.Error("ingest ecosystem failed", "ecosystem", eco, "error", err)
			totalStats.Errors++
			continue
		}
		totalStats.Inserted += stats.Inserted
		totalStats.Total += stats.Total
		totalStats.Errors += stats.Errors
		totalStats.Duration += stats.Duration
	}

	return totalStats, nil
}

// isValidEcosystem checks whether the given ecosystem name is known
// (either in the local DB or from the GCS ecosystem list).
func (s *Server) isValidEcosystem(ctx context.Context, ecosystem string) (bool, error) {
	// Check DB first (fast path).
	known, err := s.store.ListOSVEcosystems(ctx)
	if err == nil {
		for _, e := range known {
			if e == ecosystem {
				return true, nil
			}
		}
	}

	// Fall back to GCS ecosystem list.
	ecosystems, err := s.fetcher.ListEcosystems(ctx)
	if err != nil {
		return false, err
	}
	for _, e := range ecosystems {
		if e == ecosystem {
			return true, nil
		}
	}

	return false, nil
}

// writeSSE writes a single SSE event to the response writer and flushes.
func (s *Server) writeSSE(w http.ResponseWriter, flusher http.Flusher, evt ingestEvent) {
	data, err := json.Marshal(evt)
	if err != nil {
		slog.Error("failed to marshal SSE event", "error", err)
		return
	}
	_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
	flusher.Flush()
}

// ingestGHSA fetches GitHub Security Advisories for a repo and imports them.
func (s *Server) ingestGHSA(ctx context.Context, repo string, progressFn func(ingest.Progress)) (*ingest.Stats, error) {
	parts := strings.SplitN(repo, "/", 2)
	owner, repoName := parts[0], parts[1]

	progressFn(ingest.Progress{Phase: "download", Message: fmt.Sprintf("Fetching GitHub Security Advisories for %s/%s...", owner, repoName)})

	// No token passed via API for security — use server-side env var if available.
	token := ""

	advisoryData, err := s.fetcher.FetchGitHubAdvisories(ctx, owner, repoName, token)
	if err != nil {
		return nil, fmt.Errorf("fetch GitHub advisories: %w", err)
	}

	stats := &ingest.Stats{
		Ecosystem:  "ghsa:" + repo,
		IsFullSync: true,
	}

	if len(advisoryData) == 0 {
		progressFn(ingest.Progress{Phase: "store", Message: "No published advisories found."})
		return stats, nil
	}

	stats.Total = len(advisoryData)
	progressFn(ingest.Progress{Phase: "download", Current: stats.Total, Total: stats.Total, Message: fmt.Sprintf("Found %d advisory(ies)", stats.Total)})

	for i, data := range advisoryData {
		vuln, err := parser.ConvertGitHubToOSV(data)
		if err != nil {
			slog.Error("GHSA conversion error", "error", err)
			stats.Errors++
			continue
		}

		if err := s.store.Insert(ctx, vuln); err != nil {
			slog.Error("GHSA insert error", "id", vuln.ID, "error", err)
			stats.Errors++
			continue
		}

		stats.Inserted++
		progressFn(ingest.Progress{Phase: "store", Current: i + 1, Total: stats.Total})
	}

	return stats, nil
}

// ingestTypeToSource maps ingest type strings to source names for job records.
func ingestTypeToSource(t string) string {
	switch t {
	case "ecosystem", "ecosystem_update", "all", "all_bulk":
		return "osv"
	case "nvd", "nvd_update", "nvd_converted":
		return "nvd"
	case "mitre", "mitre_update":
		return "mitre"
	case "epss", "epss_update", "epss_backfill":
		return "epss"
	case "kev", "kev_update":
		return "kev"
	case "debian":
		return "debian"
	case "ghsa":
		return "ghsa"
	default:
		return t
	}
}
