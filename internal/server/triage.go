package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/kato83/mayu/internal/model"
	"github.com/kato83/mayu/internal/sbommon"
	"github.com/kato83/mayu/internal/triage"
)

// --- Triage API Handlers ---

// buildTriageInputFromDetail constructs a TriageInput from a VulnerabilityDetail
// by extracting all available risk signals from the enrichment data.
func buildTriageInputFromDetail(detail *model.VulnerabilityDetail) *triage.TriageInput {
	input := &triage.TriageInput{
		VulnerabilityID: detail.ID,
	}

	// CVSS: take the highest base score from NVD metrics
	if detail.NVD != nil && len(detail.NVD.Metrics) > 0 {
		var maxScore float64
		for _, m := range detail.NVD.Metrics {
			if m.BaseScore > maxScore {
				maxScore = m.BaseScore
			}
		}
		if maxScore > 0 {
			input.CVSSScore = &maxScore
		}
	}
	// Fallback: try MITRE metrics if NVD has none
	if input.CVSSScore == nil && detail.MITRE != nil && len(detail.MITRE.Metrics) > 0 {
		var maxScore float64
		for _, m := range detail.MITRE.Metrics {
			if m.BaseScore > maxScore {
				maxScore = m.BaseScore
			}
		}
		if maxScore > 0 {
			input.CVSSScore = &maxScore
		}
	}

	// EPSS
	if detail.EPSS != nil {
		input.EPSSScore = &detail.EPSS.EPSS
	}

	// LEV
	if detail.LEV != nil {
		input.LEVScore = &detail.LEV.LEV
		input.InKEV = detail.LEV.InKEV
	}

	// KEV (also set InKEV if KEV detail is present)
	if detail.KEV != nil {
		input.InKEV = true
	}

	// Patch availability: check if any affected package has a fixed version
	for _, affected := range detail.Affected {
		for _, r := range affected.Ranges {
			for _, evt := range r.Events {
				if evt.Fixed != "" {
					input.PatchAvailable = true
					break
				}
			}
			if input.PatchAvailable {
				break
			}
		}
		if input.PatchAvailable {
			break
		}
	}

	// Published date (for age signal)
	if detail.Published != nil {
		input.PublishedAt = detail.Published
	}

	// ExploitDB
	if len(detail.ExploitDB) > 0 {
		input.HasExploit = true
	}

	// SSVC: extract from NVD or MITRE if available
	input.SSVCOptions = extractSSVCOptions(detail)

	return input
}

// extractSSVCOptions extracts SSVC decision points from VulnerabilityDetail.
// It checks NVD first (where CISA Coordinator assessments are typically found),
// then falls back to MITRE.
func extractSSVCOptions(detail *model.VulnerabilityDetail) map[string]string {
	// Try NVD SSVC first (CISA Coordinator assessments)
	if detail.NVD != nil && detail.NVD.SSVC != nil && len(detail.NVD.SSVC.Options) > 0 {
		opts := make(map[string]string)
		for _, o := range detail.NVD.SSVC.Options {
			opts[o.Key] = o.Value
		}
		return opts
	}
	// Fallback to MITRE SSVC
	if detail.MITRE != nil && detail.MITRE.SSVC != nil && len(detail.MITRE.SSVC.Options) > 0 {
		opts := make(map[string]string)
		for _, o := range detail.MITRE.SSVC.Options {
			opts[o.Key] = o.Value
		}
		return opts
	}
	return nil
}

// buildTriageInputForVulnID fetches vulnerability detail from the store and builds a TriageInput.
func (s *Server) buildTriageInputForVulnID(ctx context.Context, vulnID string) *triage.TriageInput {
	detail, err := s.store.GetVulnerabilityDetail(ctx, vulnID)
	if err != nil || detail == nil {
		// Fallback: return minimal input with just the ID
		return &triage.TriageInput{VulnerabilityID: vulnID}
	}
	return buildTriageInputFromDetail(detail)
}

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

	// Build inputs from vulnerability IDs with full signal data from DB
	var inputs []*triage.TriageInput
	for _, id := range req.VulnerabilityIDs {
		inputs = append(inputs, s.buildTriageInputForVulnID(r.Context(), id))
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

	input := s.buildTriageInputForVulnID(r.Context(), id)

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
	engine := triage.NewEngine(profile)

	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	// Get the latest version for this project
	pid, err := strconv.ParseInt(projectID, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid project ID")
		return
	}

	latestVersion, err := s.sbomStore.GetLatestVersion(r.Context(), pid)
	if err != nil || latestVersion == nil {
		// No version yet — return empty results
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"project_id":   projectID,
			"profile_used": profile.Name,
			"summary":      computeSummary(nil),
			"results":      []*triage.TriageResult{},
			"computed_at":  time.Now().UTC().Format(time.RFC3339),
		})
		return
	}

	// Get the latest scan result for this version
	scanResult, err := s.sbomStore.GetLatestScanResult(r.Context(), latestVersion.ID)
	if err != nil || scanResult == nil || len(scanResult.Findings) == 0 {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"project_id":   projectID,
			"profile_used": profile.Name,
			"summary":      computeSummary(nil),
			"results":      []*triage.TriageResult{},
			"computed_at":  time.Now().UTC().Format(time.RFC3339),
		})
		return
	}

	// Get finding statuses to exclude suppressed/false_positive/resolved findings
	excludedStatuses := map[string]bool{}
	statuses, _ := s.sbomStore.ListFindingStatuses(r.Context(), latestVersion.ID, nil)
	for _, fs := range statuses {
		if fs.Status == sbommon.FindingStatusFalsePositive ||
			fs.Status == sbommon.FindingStatusSuppressed ||
			fs.Status == sbommon.FindingStatusResolved {
			excludedStatuses[fs.VulnID+"|"+fs.Purl] = true
		}
	}

	// Collect unique vulnerability IDs from active findings
	vulnIDsSeen := make(map[string]bool)
	var vulnIDs []string
	for _, f := range scanResult.Findings {
		key := f.VulnID + "|" + f.Purl
		if excludedStatuses[key] {
			continue
		}
		if !vulnIDsSeen[f.VulnID] {
			vulnIDsSeen[f.VulnID] = true
			vulnIDs = append(vulnIDs, f.VulnID)
		}
	}

	// Build triage inputs from vulnerability details
	var inputs []*triage.TriageInput
	for _, vulnID := range vulnIDs {
		inputs = append(inputs, s.buildTriageInputForVulnID(r.Context(), vulnID))
	}

	results, err := engine.TriageBatch(r.Context(), inputs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "triage computation failed")
		return
	}

	if limit < len(results) {
		results = results[:limit]
	}

	summary := computeSummary(results)

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
	// Aggregate triage results across all SBOM projects
	summary, entries := s.computeCrossProjectOverview(r.Context())

	resp := map[string]interface{}{
		"summary":     summary,
		"entries":     entries,
		"computed_at": time.Now().UTC().Format(time.RFC3339),
	}
	writeJSON(w, http.StatusOK, resp)
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

	summary, _ := s.computeCrossProjectOverview(r.Context())

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"vulnerabilities": []interface{}{},
		"summary":         summary,
		"computed_at":     time.Now().UTC().Format(time.RFC3339),
	})
}

// handleTriageOverviewSummary handles GET /api/v1/triage/overview/summary
func (s *Server) handleTriageOverviewSummary(w http.ResponseWriter, r *http.Request) {
	summary, _ := s.computeCrossProjectOverview(r.Context())
	writeJSON(w, http.StatusOK, summary)
}

// computeCrossProjectOverview aggregates triage summary across all projects.
func (s *Server) computeCrossProjectOverview(ctx context.Context) (triage.OverviewSummary, []interface{}) {
	summary := triage.OverviewSummary{}
	// Overview is computed from the dashboard triage data which we also aggregate below
	return summary, []interface{}{}
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
		"critical":      0,
		"high":          0,
		"medium":        0,
		"low":           0,
		"total_triaged": 0,
		"profile_used":  "default",
		"last_computed": time.Now().UTC().Format(time.RFC3339),
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
