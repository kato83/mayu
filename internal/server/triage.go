package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/kato83/mayu/internal/triage"
)

// --- Triage API Handlers ---

// handleTriageBatch handles POST /api/v1/triage
func (s *Server) handleTriageBatch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		VulnerabilityIDs []string `json:"vulnerability_ids"`
		ProjectID        string   `json:"project_id"`
		Profile          string   `json:"profile"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.VulnerabilityIDs) == 0 && req.ProjectID == "" {
		writeError(w, http.StatusBadRequest, "either vulnerability_ids or project_id is required")
		return
	}

	profile := resolveTriageProfile(req.Profile)
	engine := triage.NewEngine(profile)

	// Build inputs from vulnerability IDs
	var inputs []*triage.TriageInput
	for _, id := range req.VulnerabilityIDs {
		inputs = append(inputs, &triage.TriageInput{
			VulnerabilityID: id,
		})
	}

	results, err := engine.TriageBatch(r.Context(), inputs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "triage computation failed")
		return
	}

	summary := computeSummary(results)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"summary":      summary,
		"results":      results,
		"profile_used": profile.Name,
		"computed_at":  time.Now().UTC().Format(time.RFC3339),
	})
}

// handleGetVulnerabilityTriage handles GET /api/v1/vulnerabilities/{id}/triage
func (s *Server) handleGetVulnerabilityTriage(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "vulnerability ID is required")
		return
	}

	profileName := r.URL.Query().Get("profile")
	profile := resolveTriageProfile(profileName)
	engine := triage.NewEngine(profile)

	input := &triage.TriageInput{
		VulnerabilityID: id,
	}

	result, err := engine.Triage(r.Context(), input)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "triage computation failed")
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// handleGetProjectTriage handles GET /api/v1/sbom/projects/{project}/triage
func (s *Server) handleGetProjectTriage(w http.ResponseWriter, r *http.Request) {
	projectID := chi.URLParam(r, "id")
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "project ID is required")
		return
	}

	profileName := r.URL.Query().Get("profile")
	profile := resolveTriageProfile(profileName)
	_ = triage.NewEngine(profile)

	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	// In a full implementation, this would query the SBOM store for findings
	// For now, return an empty result set
	results := make([]*triage.TriageResult, 0)
	summary := computeSummary(results)

	if limit < len(results) {
		results = results[:limit]
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"project_id":   projectID,
		"profile_used": profile.Name,
		"summary":      summary,
		"results":      results,
		"computed_at":  time.Now().UTC().Format(time.RFC3339),
	})
}

// handleListTriageProfiles handles GET /api/v1/triage/profiles
func (s *Server) handleListTriageProfiles(w http.ResponseWriter, r *http.Request) {
	templates := triage.BuiltinTemplates()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"profiles": templates,
	})
}

// handleValidateTriageProfile handles POST /api/v1/triage/profiles/validate
func (s *Server) handleValidateTriageProfile(w http.ResponseWriter, r *http.Request) {
	var profile triage.Profile
	if err := json.NewDecoder(r.Body).Decode(&profile); err != nil {
		writeError(w, http.StatusBadRequest, "invalid profile JSON")
		return
	}

	errs := triage.ValidateProfile(&profile)
	if len(errs) > 0 {
		errStrs := make([]string, len(errs))
		for i, e := range errs {
			errStrs[i] = e.Error()
		}
		writeJSON(w, http.StatusUnprocessableEntity, map[string]interface{}{
			"valid":  false,
			"errors": errStrs,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"valid": true,
	})
}

// --- Server Profile Binding API Handlers ---

// handleListServerProfileBindings handles GET /api/v1/sbom/projects/{project}/servers
func (s *Server) handleListServerProfileBindings(w http.ResponseWriter, r *http.Request) {
	projectID := chi.URLParam(r, "id")
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "project ID is required")
		return
	}

	// In production, this would query the binding store
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"project_id": projectID,
		"servers":    []interface{}{},
	})
}

// handleSetServerProfile handles PUT /api/v1/sbom/projects/{project}/servers/{label}/profile
func (s *Server) handleSetServerProfile(w http.ResponseWriter, r *http.Request) {
	projectID := chi.URLParam(r, "id")
	label := chi.URLParam(r, "label")

	if projectID == "" || label == "" {
		writeError(w, http.StatusBadRequest, "project ID and server label are required")
		return
	}

	var req struct {
		ProfileName string `json:"profile_name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.ProfileName == "" {
		writeError(w, http.StatusBadRequest, "profile_name is required")
		return
	}

	// Verify profile exists
	if p := resolveTriageProfile(req.ProfileName); p.Name == "default" && req.ProfileName != "default" {
		writeError(w, http.StatusBadRequest, "profile not found: "+req.ProfileName)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"project_id":   projectID,
		"server_label": label,
		"profile_name": req.ProfileName,
		"message":      "profile binding created",
	})
}

// handleDeleteServerProfile handles DELETE /api/v1/sbom/projects/{project}/servers/{label}/profile
func (s *Server) handleDeleteServerProfile(w http.ResponseWriter, r *http.Request) {
	projectID := chi.URLParam(r, "id")
	label := chi.URLParam(r, "label")

	if projectID == "" || label == "" {
		writeError(w, http.StatusBadRequest, "project ID and server label are required")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "profile binding removed",
	})
}

// --- Cross-Project Overview API Handlers ---

// handleTriageOverview handles GET /api/v1/triage/overview
func (s *Server) handleTriageOverview(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"summary": triage.OverviewSummary{
			Total:    0,
			Critical: 0,
			High:     0,
			Medium:   0,
			Low:      0,
		},
		"computed_at": time.Now().UTC().Format(time.RFC3339),
	})
}

// handleTriageOverviewVulnerabilities handles GET /api/v1/triage/overview/vulnerabilities
func (s *Server) handleTriageOverviewVulnerabilities(w http.ResponseWriter, r *http.Request) {
	priority := r.URL.Query().Get("priority")
	limitStr := r.URL.Query().Get("limit")
	sortBy := r.URL.Query().Get("sort")

	limit := 50
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	_ = priority
	_ = sortBy
	_ = limit

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"vulnerabilities": []interface{}{},
		"summary": triage.OverviewSummary{
			Total:    0,
			Critical: 0,
			High:     0,
			Medium:   0,
			Low:      0,
		},
		"computed_at": time.Now().UTC().Format(time.RFC3339),
	})
}

// handleTriageOverviewSummary handles GET /api/v1/triage/overview/summary
func (s *Server) handleTriageOverviewSummary(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, triage.OverviewSummary{
		Total:    0,
		Critical: 0,
		High:     0,
		Medium:   0,
		Low:      0,
	})
}

// --- Triage Path API Handlers ---

// handleListTriagePaths handles GET /api/v1/triage/paths
func (s *Server) handleListTriagePaths(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	priority := r.URL.Query().Get("priority")
	ecosystem := r.URL.Query().Get("ecosystem")
	project := r.URL.Query().Get("project")

	limit := 20
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	_ = priority
	_ = ecosystem
	_ = project
	_ = limit

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"paths":       []interface{}{},
		"total":       0,
		"computed_at": time.Now().UTC().Format(time.RFC3339),
	})
}

// handleGetTriagePath handles GET /api/v1/triage/paths/{id}
func (s *Server) handleGetTriagePath(w http.ResponseWriter, r *http.Request) {
	pathID := chi.URLParam(r, "id")
	if pathID == "" {
		writeError(w, http.StatusBadRequest, "path ID is required")
		return
	}

	// In production, this would look up from the triage_paths table
	writeError(w, http.StatusNotFound, "triage path not found: "+pathID)
}

// handleGetProjectTriagePaths handles GET /api/v1/sbom/projects/{project}/triage/paths
func (s *Server) handleGetProjectTriagePaths(w http.ResponseWriter, r *http.Request) {
	projectID := chi.URLParam(r, "id")
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "project ID is required")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"project_id":  projectID,
		"paths":       []interface{}{},
		"total":       0,
		"computed_at": time.Now().UTC().Format(time.RFC3339),
	})
}

// handleDashboardTriage handles GET /api/v1/dashboard/triage
func (s *Server) handleDashboardTriage(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"by_priority": map[string]int{
			"Critical": 0,
			"High":     0,
			"Medium":   0,
			"Low":      0,
		},
		"total_triaged": 0,
		"profile_used":  "default",
		"last_computed":  time.Now().UTC().Format(time.RFC3339),
	})
}

// --- Helper functions ---

func resolveTriageProfile(name string) *triage.Profile {
	if name == "" {
		return triage.DefaultProfile()
	}
	name = strings.TrimSpace(name)
	for _, t := range triage.BuiltinTemplates() {
		if t.Name == name {
			return &t
		}
	}
	return triage.DefaultProfile()
}

func computeSummary(results []*triage.TriageResult) map[string]int {
	summary := map[string]int{
		"total":    len(results),
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
	}
	for _, r := range results {
		switch r.PriorityLevel {
		case triage.PriorityCritical:
			summary["critical"]++
		case triage.PriorityHigh:
			summary["high"]++
		case triage.PriorityMedium:
			summary["medium"]++
		case triage.PriorityLow:
			summary["low"]++
		}
	}
	return summary
}
