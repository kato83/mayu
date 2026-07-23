package server

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/kato83/mayu/internal/store"
)

// --- Response types for ingest jobs ---

// ingestJobResponse is the JSON representation of an ingest job (list view).
type ingestJobResponse struct {
	ID           int64                  `json:"id"`
	Source       string                 `json:"source"`
	CommandArgs  map[string]interface{} `json:"command_args"`
	StartedAt    time.Time              `json:"started_at"`
	FinishedAt   *time.Time             `json:"finished_at"`
	Status       string                 `json:"status"`
	TotalCount   *int                   `json:"total_count"`
	SuccessCount *int                   `json:"success_count"`
	FailureCount *int                   `json:"failure_count"`
}

// ingestJobDetailResponse is the JSON representation of an ingest job (detail view with failures).
type ingestJobDetailResponse struct {
	ID           int64                    `json:"id"`
	Source       string                   `json:"source"`
	CommandArgs  map[string]interface{}   `json:"command_args"`
	StartedAt    time.Time                `json:"started_at"`
	FinishedAt   *time.Time               `json:"finished_at"`
	Status       string                   `json:"status"`
	TotalCount   *int                     `json:"total_count"`
	SuccessCount *int                     `json:"success_count"`
	FailureCount *int                     `json:"failure_count"`
	ErrorMessage *string                  `json:"error_message"`
	ErrorStack   *string                  `json:"error_stack"`
	Failures     []ingestFailureResponse  `json:"failures"`
}

// ingestFailureResponse is the JSON representation of an ingest failure.
type ingestFailureResponse struct {
	ID           int64     `json:"id"`
	VulnID       string    `json:"vuln_id"`
	ErrorType    string    `json:"error_type"`
	ErrorMessage *string   `json:"error_message"`
	ErrorStack   *string   `json:"error_stack"`
	FailedAt     time.Time `json:"failed_at"`
}

// ingestJobsListResponse wraps the list of ingest jobs.
type ingestJobsListResponse struct {
	Jobs []ingestJobResponse `json:"jobs"`
}

// --- Handlers ---

// handleListIngestJobs handles GET /api/v1/ingest/jobs
func (s *Server) handleListIngestJobs(w http.ResponseWriter, r *http.Request) {
	// Parse limit parameter
	limit := 20
	if l := r.URL.Query().Get("limit"); l != "" {
		parsed, err := strconv.Atoi(l)
		if err != nil || parsed < 1 {
			writeError(w, http.StatusBadRequest, "invalid limit parameter: must be a positive integer")
			return
		}
		if parsed > 100 {
			parsed = 100
		}
		limit = parsed
	}

	jobs, err := s.store.ListIngestJobs(r.Context(), limit)
	if err != nil {
		slog.Error("failed to list ingest jobs", "error", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	resp := ingestJobsListResponse{
		Jobs: make([]ingestJobResponse, 0, len(jobs)),
	}
	for _, job := range jobs {
		resp.Jobs = append(resp.Jobs, toIngestJobResponse(job))
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleGetIngestJob handles GET /api/v1/ingest/jobs/{id}
func (s *Server) handleGetIngestJob(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	if idStr == "" {
		writeError(w, http.StatusBadRequest, "job ID is required")
		return
	}

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid job ID: must be an integer")
		return
	}

	job, err := s.store.GetIngestJob(r.Context(), id)
	if err != nil {
		slog.Error("failed to get ingest job", "id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	if job == nil {
		writeError(w, http.StatusNotFound, "ingest job not found")
		return
	}

	writeJSON(w, http.StatusOK, toIngestJobDetailResponse(*job))
}

// --- Converters ---

func toIngestJobResponse(job store.IngestJob) ingestJobResponse {
	args := job.CommandArgs
	if args == nil {
		args = make(map[string]interface{})
	}
	return ingestJobResponse{
		ID:           job.ID,
		Source:       job.Source,
		CommandArgs:  args,
		StartedAt:    job.StartedAt,
		FinishedAt:   job.FinishedAt,
		Status:       job.Status,
		TotalCount:   job.TotalCount,
		SuccessCount: job.SuccessCount,
		FailureCount: job.FailureCount,
	}
}

func toIngestJobDetailResponse(job store.IngestJob) ingestJobDetailResponse {
	args := job.CommandArgs
	if args == nil {
		args = make(map[string]interface{})
	}

	failures := make([]ingestFailureResponse, 0, len(job.Failures))
	for _, f := range job.Failures {
		failures = append(failures, ingestFailureResponse{
			ID:           f.ID,
			VulnID:       f.VulnID,
			ErrorType:    f.ErrorType,
			ErrorMessage: f.ErrorMessage,
			ErrorStack:   f.ErrorStack,
			FailedAt:     f.FailedAt,
		})
	}

	return ingestJobDetailResponse{
		ID:           job.ID,
		Source:       job.Source,
		CommandArgs:  args,
		StartedAt:    job.StartedAt,
		FinishedAt:   job.FinishedAt,
		Status:       job.Status,
		TotalCount:   job.TotalCount,
		SuccessCount: job.SuccessCount,
		FailureCount: job.FailureCount,
		ErrorMessage: job.ErrorMessage,
		ErrorStack:   job.ErrorStack,
		Failures:     failures,
	}
}
