package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/kato83/mayu/internal/store"
	"github.com/kato83/mayu/internal/translate"
)

// translateRequest is the request body for POST /api/v1/vulnerabilities/{id}/translate.
type translateRequest struct {
	// Locale is the target locale for translation (BCP 47 tag, e.g., "ja", "ko", "zh-Hans").
	Locale string `json:"locale"`
}

// translateStartResponse is the immediate response for a translation job submission.
type translateStartResponse struct {
	// JobID is the unique identifier for the background translation job.
	JobID int64 `json:"job_id"`
	// Status indicates the job has been accepted ("running").
	Status string `json:"status"`
	// VulnerabilityID is the vulnerability being translated.
	VulnerabilityID string `json:"vulnerability_id"`
	// Locale is the target locale.
	Locale string `json:"locale"`
}

// translationJobResponse is the JSON representation of a translation job.
type translationJobResponse struct {
	ID               int64      `json:"id"`
	VulnerabilityID  string     `json:"vulnerability_id"`
	Locale           string     `json:"locale"`
	StartedAt        time.Time  `json:"started_at"`
	FinishedAt       *time.Time `json:"finished_at,omitempty"`
	Status           string     `json:"status"`
	FieldsTranslated *int       `json:"fields_translated,omitempty"`
	ErrorMessage     *string    `json:"error_message,omitempty"`
}

// translationJobsListResponse wraps the list of translation jobs.
type translationJobsListResponse struct {
	Jobs []translationJobResponse `json:"jobs"`
}

// handleTranslateVulnerability handles POST /api/v1/vulnerabilities/{id}/translate.
// It validates the request, creates a background translation job, and returns 202 Accepted
// with the job ID immediately. The actual LLM translation runs in a background goroutine
// that is not tied to the HTTP request context, so it survives client disconnects/timeouts.
func (s *Server) handleTranslateVulnerability(w http.ResponseWriter, r *http.Request) {
	if s.translateService == nil {
		writeError(w, http.StatusServiceUnavailable, "translation is not configured; set translation.enabled=true in config.yaml")
		return
	}

	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "vulnerability ID is required")
		return
	}
	if decoded, err := url.PathUnescape(id); err == nil {
		id = decoded
	}

	// Parse request body
	var req translateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if req.Locale == "" {
		writeError(w, http.StatusBadRequest, "locale is required")
		return
	}

	ctx := r.Context()

	// Resolve vulnerability ID (handles aliases/OSV IDs)
	vulnID, err := s.store.ResolveVulnerabilityID(ctx, id)
	if err != nil {
		slog.Error("failed to resolve vulnerability ID for translation", "id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if vulnID == "" {
		writeError(w, http.StatusNotFound, fmt.Sprintf("vulnerability %q not found", id))
		return
	}

	// Create job record in DB
	job := &store.TranslationJob{
		VulnerabilityID: vulnID,
		Locale:          req.Locale,
		StartedAt:       time.Now().UTC(),
		Status:          "running",
	}

	jobID, err := s.store.CreateTranslationJob(ctx, job)
	if err != nil {
		slog.Error("failed to create translation job", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to create translation job")
		return
	}
	job.ID = jobID

	// Launch translation in a background goroutine (independent of request context).
	go s.runTranslationJob(job)

	// Return job ID immediately with 202 Accepted.
	writeJSON(w, http.StatusAccepted, translateStartResponse{
		JobID:           jobID,
		Status:          "running",
		VulnerabilityID: vulnID,
		Locale:          req.Locale,
	})
}

// runTranslationJob executes the LLM translation in the background.
// It uses context.Background() so it is not tied to any HTTP request.
func (s *Server) runTranslationJob(job *store.TranslationJob) {
	ctx := context.Background()

	slog.Info("starting background translation job",
		"job_id", job.ID,
		"vulnerability_id", job.VulnerabilityID,
		"locale", job.Locale,
	)

	// Get all translatable texts from the database
	texts, err := s.store.GetTranslatableTexts(ctx, job.VulnerabilityID)
	if err != nil {
		s.failTranslationJob(ctx, job, fmt.Sprintf("failed to get translatable texts: %v", err))
		return
	}
	if texts == nil {
		s.failTranslationJob(ctx, job, fmt.Sprintf("vulnerability %q not found", job.VulnerabilityID))
		return
	}

	// Perform translation via LLM
	translationTexts := translate.VulnerabilityTexts{
		VulnerabilityID:      job.VulnerabilityID,
		Summary:              texts.Summary,
		Details:              texts.Details,
		NVDDescription:       texts.NVDDescription,
		NVDDescriptionID:     texts.NVDDescriptionID,
		KEVEntryID:           texts.KEVEntryID,
		KEVVulnerabilityName: texts.KEVVulnerabilityName,
		KEVShortDescription:  texts.KEVShortDescription,
		KEVRequiredAction:    texts.KEVRequiredAction,
		KEVNotes:             texts.KEVNotes,
	}

	result, err := s.translateService.TranslateVulnerability(ctx, translationTexts, job.Locale)
	if err != nil {
		s.failTranslationJob(ctx, job, fmt.Sprintf("LLM translation failed: %v", err))
		return
	}

	// Save translations to database
	fieldsTranslated := 0

	// Save vulnerability summary/details
	if result.Summary != "" || result.Details != "" {
		if err := s.store.SaveVulnerabilityTranslation(ctx, job.VulnerabilityID, job.Locale, result.Summary, result.Details, result.TranslatedAt); err != nil {
			s.failTranslationJob(ctx, job, fmt.Sprintf("failed to save vulnerability translation: %v", err))
			return
		}
		if result.Summary != "" {
			fieldsTranslated++
		}
		if result.Details != "" {
			fieldsTranslated++
		}
	}

	// Save NVD description translation
	if result.NVDDescription != "" && texts.NVDDescriptionID > 0 {
		if err := s.store.SaveNVDDescriptionTranslation(ctx, texts.NVDDescriptionID, job.Locale, result.NVDDescription, result.TranslatedAt); err != nil {
			s.failTranslationJob(ctx, job, fmt.Sprintf("failed to save NVD description translation: %v", err))
			return
		}
		fieldsTranslated++
	}

	// Save KEV translation
	if texts.KEVEntryID > 0 && (result.KEVVulnName != "" || result.KEVShortDesc != "" || result.KEVReqAction != "" || result.KEVNotes != "") {
		if err := s.store.SaveKEVTranslation(ctx, texts.KEVEntryID, job.Locale, result.KEVVulnName, result.KEVShortDesc, result.KEVReqAction, result.KEVNotes, result.TranslatedAt); err != nil {
			s.failTranslationJob(ctx, job, fmt.Sprintf("failed to save KEV translation: %v", err))
			return
		}
		if result.KEVVulnName != "" {
			fieldsTranslated++
		}
		if result.KEVShortDesc != "" {
			fieldsTranslated++
		}
		if result.KEVReqAction != "" {
			fieldsTranslated++
		}
		if result.KEVNotes != "" {
			fieldsTranslated++
		}
	}

	// Mark job as success
	now := time.Now().UTC()
	job.FinishedAt = &now
	job.Status = "success"
	job.FieldsTranslated = &fieldsTranslated

	if err := s.store.UpdateTranslationJob(ctx, job); err != nil {
		slog.Error("failed to update translation job", "job_id", job.ID, "error", err)
	}

	slog.Info("background translation job completed",
		"job_id", job.ID,
		"vulnerability_id", job.VulnerabilityID,
		"locale", job.Locale,
		"fields_translated", fieldsTranslated,
	)
}

// failTranslationJob marks a translation job as failed with the given error message.
func (s *Server) failTranslationJob(ctx context.Context, job *store.TranslationJob, errMsg string) {
	slog.Error("translation job failed",
		"job_id", job.ID,
		"vulnerability_id", job.VulnerabilityID,
		"locale", job.Locale,
		"error", errMsg,
	)

	now := time.Now().UTC()
	job.FinishedAt = &now
	job.Status = "failed"
	job.ErrorMessage = &errMsg

	if err := s.store.UpdateTranslationJob(ctx, job); err != nil {
		slog.Error("failed to update translation job status", "job_id", job.ID, "error", err)
	}
}

// handleListTranslationJobs handles GET /api/v1/translations/jobs.
func (s *Server) handleListTranslationJobs(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}

	jobs, err := s.store.ListTranslationJobs(r.Context(), limit)
	if err != nil {
		slog.Error("failed to list translation jobs", "error", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	resp := translationJobsListResponse{
		Jobs: make([]translationJobResponse, 0, len(jobs)),
	}
	for _, j := range jobs {
		resp.Jobs = append(resp.Jobs, toTranslationJobResponse(j))
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleGetTranslationJob handles GET /api/v1/translations/jobs/{id}.
func (s *Server) handleGetTranslationJob(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid job ID")
		return
	}

	job, err := s.store.GetTranslationJob(r.Context(), id)
	if err != nil {
		slog.Error("failed to get translation job", "id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if job == nil {
		writeError(w, http.StatusNotFound, "translation job not found")
		return
	}

	writeJSON(w, http.StatusOK, toTranslationJobResponse(*job))
}

// toTranslationJobResponse converts a store.TranslationJob to the API response format.
func toTranslationJobResponse(j store.TranslationJob) translationJobResponse {
	return translationJobResponse{
		ID:               j.ID,
		VulnerabilityID:  j.VulnerabilityID,
		Locale:           j.Locale,
		StartedAt:        j.StartedAt,
		FinishedAt:       j.FinishedAt,
		Status:           j.Status,
		FieldsTranslated: j.FieldsTranslated,
		ErrorMessage:     j.ErrorMessage,
	}
}
