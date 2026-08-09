package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/kato83/mayu/internal/auth"
	"github.com/kato83/mayu/internal/model"
	"github.com/kato83/mayu/internal/sbommon"
	"github.com/kato83/mayu/internal/store"
	"github.com/kato83/mayu/internal/triage"
)

// --- Triage API Handlers ---

// buildTriageInputFromDetail constructs a TriageInput from a VulnerabilityDetail
// by extracting all available risk signals from the enrichment data.
func buildTriageInputFromDetail(detail *model.VulnerabilityDetail) *triage.TriageInput {
	input := &triage.TriageInput{
		VulnerabilityID: detail.ID,
	}

	// CVSS: take the highest base score from NVD metrics (and capture vector string)
	if detail.NVD != nil && len(detail.NVD.Metrics) > 0 {
		var maxScore float64
		var maxVector string
		for _, m := range detail.NVD.Metrics {
			if m.BaseScore > maxScore {
				maxScore = m.BaseScore
				maxVector = m.VectorString
			}
		}
		if maxScore > 0 {
			input.CVSSScore = &maxScore
			input.CVSSVector = maxVector
		}
	}
	// Fallback: try MITRE metrics if NVD has none
	if input.CVSSScore == nil && detail.MITRE != nil && len(detail.MITRE.Metrics) > 0 {
		var maxScore float64
		var maxVector string
		for _, m := range detail.MITRE.Metrics {
			if m.BaseScore > maxScore {
				maxScore = m.BaseScore
				maxVector = m.VectorString
			}
		}
		if maxScore > 0 {
			input.CVSSScore = &maxScore
			input.CVSSVector = maxVector
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

	// Exploitability: take the exploitability sub-score from the same NVD metric used for CVSS
	if detail.NVD != nil && len(detail.NVD.Metrics) > 0 {
		var bestExploitability *float64
		var bestBaseScore float64
		for _, m := range detail.NVD.Metrics {
			if m.ExploitabilityScore != nil && m.BaseScore >= bestBaseScore {
				bestBaseScore = m.BaseScore
				bestExploitability = m.ExploitabilityScore
			}
		}
		if bestExploitability != nil {
			input.ExploitabilityScore = bestExploitability
		}
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

	profile := s.resolveTriageProfileWithStore(r.Context(), req.Profile)
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
	profile := s.resolveTriageProfileWithStore(r.Context(), profileName)
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
	profile := s.resolveTriageProfileWithStore(r.Context(), profileName)
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

	// Get finding statuses to exclude suppressed/false_positive/resolved/risk_accepted findings
	excludedStatuses := map[string]bool{}
	statuses, _ := s.sbomStore.ListFindingStatuses(r.Context(), latestVersion.ID, nil)
	for _, fs := range statuses {
		if fs.Status == sbommon.FindingStatusFalsePositive ||
			fs.Status == sbommon.FindingStatusSuppressed ||
			fs.Status == sbommon.FindingStatusResolved ||
			fs.Status == sbommon.FindingStatusRiskAccepted {
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

// --- Environment Profile Binding API Handlers ---

// handleListEnvironmentBindings handles GET /api/v1/sbom/projects/{id}/environments
func (s *Server) handleListEnvironmentBindings(w http.ResponseWriter, r *http.Request) {
	projectID := chi.URLParam(r, "id")
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "project ID is required")
		return
	}

	pid, err := strconv.ParseInt(projectID, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid project ID")
		return
	}

	bindings, err := s.store.ListEnvironmentBindings(r.Context(), pid)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list environment bindings")
		return
	}

	if bindings == nil {
		bindings = []triage.EnvironmentProfileBinding{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"project_id": projectID,
		"bindings":   bindings,
	})
}

// handleGetEnvironmentBinding handles GET /api/v1/sbom/projects/{id}/environments/{environment}
func (s *Server) handleGetEnvironmentBinding(w http.ResponseWriter, r *http.Request) {
	projectID := chi.URLParam(r, "id")
	environment := chi.URLParam(r, "environment")

	if projectID == "" || environment == "" {
		writeError(w, http.StatusBadRequest, "project ID and environment are required")
		return
	}

	pid, err := strconv.ParseInt(projectID, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid project ID")
		return
	}

	binding, err := s.store.GetEnvironmentBinding(r.Context(), pid, environment)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get environment binding")
		return
	}
	if binding == nil {
		writeError(w, http.StatusNotFound, "environment binding not found")
		return
	}

	writeJSON(w, http.StatusOK, binding)
}

// handleSetEnvironmentBinding handles PUT /api/v1/sbom/projects/{id}/environments/{environment}
func (s *Server) handleSetEnvironmentBinding(w http.ResponseWriter, r *http.Request) {
	projectID := chi.URLParam(r, "id")
	environment := chi.URLParam(r, "environment")

	if projectID == "" || environment == "" {
		writeError(w, http.StatusBadRequest, "project ID and environment are required")
		return
	}

	pid, err := strconv.ParseInt(projectID, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid project ID")
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
	if p := s.resolveTriageProfileWithStore(r.Context(), req.ProfileName); p.Name == "default" && req.ProfileName != "default" {
		writeError(w, http.StatusBadRequest, "profile not found: "+req.ProfileName)
		return
	}

	if err := s.store.CreateOrUpdateEnvironmentBinding(r.Context(), pid, environment, req.ProfileName, req.Description); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create/update environment binding")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"project_id":   projectID,
		"environment":  environment,
		"profile_name": req.ProfileName,
		"message":      "environment binding created/updated",
	})
}

// handleDeleteEnvironmentBinding handles DELETE /api/v1/sbom/projects/{id}/environments/{environment}
func (s *Server) handleDeleteEnvironmentBinding(w http.ResponseWriter, r *http.Request) {
	projectID := chi.URLParam(r, "id")
	environment := chi.URLParam(r, "environment")

	if projectID == "" || environment == "" {
		writeError(w, http.StatusBadRequest, "project ID and environment are required")
		return
	}

	pid, err := strconv.ParseInt(projectID, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid project ID")
		return
	}

	if err := s.store.DeleteEnvironmentBinding(r.Context(), pid, environment); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "environment binding not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to delete environment binding")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "environment binding removed",
	})
}

// --- Project Default Profile API Handlers ---

// handleGetProjectDefaultProfile handles GET /api/v1/sbom/projects/{id}/default-profile
func (s *Server) handleGetProjectDefaultProfile(w http.ResponseWriter, r *http.Request) {
	projectID := chi.URLParam(r, "id")
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "project ID is required")
		return
	}

	pid, err := strconv.ParseInt(projectID, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid project ID")
		return
	}

	profileName, err := s.store.GetProjectDefaultProfile(r.Context(), pid)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get project default profile")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"project_id":   projectID,
		"profile_name": profileName,
	})
}

// handleSetProjectDefaultProfile handles PUT /api/v1/sbom/projects/{id}/default-profile
func (s *Server) handleSetProjectDefaultProfile(w http.ResponseWriter, r *http.Request) {
	projectID := chi.URLParam(r, "id")
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "project ID is required")
		return
	}

	pid, err := strconv.ParseInt(projectID, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid project ID")
		return
	}

	var req struct {
		ProfileName string `json:"profile_name"`
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
	if p := s.resolveTriageProfileWithStore(r.Context(), req.ProfileName); p.Name == "default" && req.ProfileName != "default" {
		writeError(w, http.StatusBadRequest, "profile not found: "+req.ProfileName)
		return
	}

	if err := s.store.SetProjectDefaultProfile(r.Context(), pid, req.ProfileName); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "project not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to set project default profile")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"project_id":   projectID,
		"profile_name": req.ProfileName,
		"message":      "default profile set",
	})
}

// handleDeleteProjectDefaultProfile handles DELETE /api/v1/sbom/projects/{id}/default-profile
func (s *Server) handleDeleteProjectDefaultProfile(w http.ResponseWriter, r *http.Request) {
	projectID := chi.URLParam(r, "id")
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "project ID is required")
		return
	}

	pid, err := strconv.ParseInt(projectID, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid project ID")
		return
	}

	if err := s.store.ClearProjectDefaultProfile(r.Context(), pid); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "project not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to clear project default profile")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "default profile cleared",
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

	_ = sortBy // sorting is already done by AggregateCrossProjectBatch (priority desc)

	summary, crossResults := s.computeCrossProjectOverview(r.Context())

	// Filter by priority if specified
	if priority != "" {
		var filtered []*triage.CrossProjectTriageResult
		for _, cr := range crossResults {
			if strings.EqualFold(string(cr.OrgPriorityLevel), priority) {
				filtered = append(filtered, cr)
			}
		}
		crossResults = filtered
	}

	// Apply limit
	if limit < len(crossResults) {
		crossResults = crossResults[:limit]
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"vulnerabilities": crossResults,
		"summary":         summary,
		"computed_at":     time.Now().UTC().Format(time.RFC3339),
	})
}

// handleTriageOverviewSummary handles GET /api/v1/triage/overview/summary
func (s *Server) handleTriageOverviewSummary(w http.ResponseWriter, r *http.Request) {
	summary, crossResults := s.computeCrossProjectOverview(r.Context())

	// Compute total unique servers across all vulnerabilities.
	// This is a cross-vulnerability union — a server affected by multiple
	// vulnerabilities is counted only once.
	type serverKey struct {
		projectID   int64
		serverLabel string
	}
	projectSet := make(map[int64]struct{})
	serverSet := make(map[serverKey]struct{})
	for _, cr := range crossResults {
		for _, srv := range cr.ServerBreakdown {
			projectSet[srv.ProjectID] = struct{}{}
			serverSet[serverKey{srv.ProjectID, srv.ServerLabel}] = struct{}{}
		}
	}

	// Return format expected by the UI: priority_counts with capitalized keys
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total_vulnerabilities": summary.Total,
		"priority_counts": map[string]int{
			"Critical": summary.Critical,
			"High":     summary.High,
			"Medium":   summary.Medium,
			"Low":      summary.Low,
		},
		"total_projects":      len(projectSet),
		"total_servers":       len(serverSet),
		"risk_accepted_count": summary.RiskAccepted,
	})
}

// resolveProfileForProjectEnvironment resolves the triage profile for a given
// project and environment using the priority: environment binding > project default > built-in default.
func (s *Server) resolveProfileForProjectEnvironment(ctx context.Context, projectID int64, environment string) *triage.Profile {
	// 1. Try environment binding
	if environment != "" {
		binding, err := s.store.GetEnvironmentBinding(ctx, projectID, environment)
		if err == nil && binding != nil {
			if p := s.resolveTriageProfileWithStore(ctx, binding.ProfileName); p.Name != "default" || binding.ProfileName == "default" {
				return p
			}
		}
	}

	// 2. Try project default
	defaultName, err := s.store.GetProjectDefaultProfile(ctx, projectID)
	if err == nil && defaultName != "" {
		if p := s.resolveTriageProfileWithStore(ctx, defaultName); p.Name != "default" || defaultName == "default" {
			return p
		}
	}

	// 3. Fall back to built-in default
	return triage.DefaultProfile()
}

// computeCrossProjectOverview aggregates triage results across all SBOM projects.
// It returns the summary counts and the full list of cross-project results.
func (s *Server) computeCrossProjectOverview(ctx context.Context) (*triage.OverviewSummary, []*triage.CrossProjectTriageResult) {
	if s.sbomStore == nil {
		return &triage.OverviewSummary{}, nil
	}

	user := auth.UserFromContext(ctx)
	if user == nil {
		return &triage.OverviewSummary{}, nil
	}

	projects, err := s.sbomStore.ListProjects(ctx, user.ID)
	if err != nil || len(projects) == 0 {
		return &triage.OverviewSummary{}, nil
	}

	// Collect triage entries grouped by vulnerability ID across all projects
	entriesByVuln := make(map[string][]triage.ServerTriageEntry)
	riskAcceptedVulnIDs := make(map[string]bool)

	for _, proj := range projects {
		latestVer, err := s.sbomStore.GetLatestVersion(ctx, proj.ID)
		if err != nil || latestVer == nil {
			continue
		}

		scanResult, err := s.sbomStore.GetLatestScanResult(ctx, latestVer.ID)
		if err != nil || scanResult == nil || len(scanResult.Findings) == 0 {
			continue
		}

		// Resolve profile for this project/environment
		profile := s.resolveProfileForProjectEnvironment(ctx, proj.ID, latestVer.Environment)
		engine := triage.NewEngine(profile)

		// Exclude suppressed/false_positive/resolved/risk_accepted findings
		excludedStatuses := make(map[string]bool)
		riskAcceptedKeys := make(map[string]bool)
		statuses, _ := s.sbomStore.ListFindingStatuses(ctx, latestVer.ID, nil)
		for _, fs := range statuses {
			if fs.Status == sbommon.FindingStatusFalsePositive ||
				fs.Status == sbommon.FindingStatusSuppressed ||
				fs.Status == sbommon.FindingStatusResolved ||
				fs.Status == sbommon.FindingStatusRiskAccepted {
				excludedStatuses[fs.VulnID+"|"+fs.Purl] = true
			}
			if fs.Status == sbommon.FindingStatusRiskAccepted {
				riskAcceptedKeys[fs.VulnID+"|"+fs.Purl] = true
			}
		}

		// Collect unique vulnerability IDs from active findings and risk_accepted findings
		vulnIDsSeen := make(map[string]bool)
		var vulnIDs []string
		for _, f := range scanResult.Findings {
			key := f.VulnID + "|" + f.Purl
			if excludedStatuses[key] {
				// Track risk_accepted vuln IDs separately
				if riskAcceptedKeys[key] {
					riskAcceptedVulnIDs[f.VulnID] = true
				}
				continue
			}
			if !vulnIDsSeen[f.VulnID] {
				vulnIDsSeen[f.VulnID] = true
				vulnIDs = append(vulnIDs, f.VulnID)
			}
		}

		if len(vulnIDs) == 0 {
			continue
		}

		// Build triage inputs and run triage
		var inputs []*triage.TriageInput
		for _, vulnID := range vulnIDs {
			inputs = append(inputs, s.buildTriageInputForVulnID(ctx, vulnID))
		}

		results, err := engine.TriageBatch(ctx, inputs)
		if err != nil {
			slog.Error("triage computation failed for project", "project", proj.Name, "error", err)
			continue
		}

		// Map results into ServerTriageEntry per vulnerability
		for _, result := range results {
			entry := triage.ServerTriageEntry{
				ProjectID:    proj.ID,
				ProjectName:  proj.Name,
				ServerLabel:  latestVer.Environment,
				Environment:  latestVer.Environment,
				ProfileUsed:  profile.Name,
				TriageResult: result,
			}
			if entry.ServerLabel == "" {
				entry.ServerLabel = "default"
			}
			entriesByVuln[result.VulnerabilityID] = append(entriesByVuln[result.VulnerabilityID], entry)
		}
	}

	if len(entriesByVuln) == 0 {
		// Still count risk_accepted even when no active vulns
		riskAcceptedCount := 0
		for vulnID := range riskAcceptedVulnIDs {
			if _, active := entriesByVuln[vulnID]; !active {
				riskAcceptedCount++
			}
		}
		s := &triage.OverviewSummary{RiskAccepted: riskAcceptedCount}
		return s, nil
	}

	// Aggregate cross-project results
	crossResults := triage.AggregateCrossProjectBatch(entriesByVuln)
	summary := triage.ComputeOverviewSummary(crossResults)

	// Count risk_accepted vuln IDs that are NOT in active results
	for vulnID := range riskAcceptedVulnIDs {
		if _, active := entriesByVuln[vulnID]; !active {
			summary.RiskAccepted++
		}
	}

	return summary, crossResults
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

	paths := s.computeTriagePaths(r.Context())

	// Filter by priority
	if priority != "" {
		var filtered []*triage.TriagePath
		for _, p := range paths {
			if strings.EqualFold(string(p.MaxPriorityLevel), priority) {
				filtered = append(filtered, p)
			}
		}
		paths = filtered
	}

	// Filter by ecosystem
	if ecosystem != "" {
		var filtered []*triage.TriagePath
		for _, p := range paths {
			if strings.EqualFold(p.Action.Ecosystem, ecosystem) {
				filtered = append(filtered, p)
			}
		}
		paths = filtered
	}

	// Filter by project name
	if project != "" {
		var filtered []*triage.TriagePath
		for _, p := range paths {
			for _, srv := range p.Servers {
				if strings.EqualFold(srv.ProjectName, project) {
					filtered = append(filtered, p)
					break
				}
			}
		}
		paths = filtered
	}

	// Apply limit
	if limit < len(paths) {
		paths = paths[:limit]
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"paths":       paths,
		"total":       len(paths),
		"computed_at": time.Now().UTC().Format(time.RFC3339),
	})
}

// computeTriagePaths computes remediation paths across all SBOM projects.
func (s *Server) computeTriagePaths(ctx context.Context) []*triage.TriagePath {
	if s.sbomStore == nil {
		return nil
	}

	user := auth.UserFromContext(ctx)
	if user == nil {
		return nil
	}

	projects, err := s.sbomStore.ListProjects(ctx, user.ID)
	if err != nil || len(projects) == 0 {
		return nil
	}

	var scanFindings []triage.ScanFinding

	for _, proj := range projects {
		latestVer, err := s.sbomStore.GetLatestVersion(ctx, proj.ID)
		if err != nil || latestVer == nil {
			continue
		}

		scanResult, err := s.sbomStore.GetLatestScanResult(ctx, latestVer.ID)
		if err != nil || scanResult == nil || len(scanResult.Findings) == 0 {
			continue
		}

		// Resolve profile for this project/environment
		profile := s.resolveProfileForProjectEnvironment(ctx, proj.ID, latestVer.Environment)
		engine := triage.NewEngine(profile)

		// Exclude suppressed/false_positive/resolved/risk_accepted findings
		excludedStatuses := make(map[string]bool)
		statuses, _ := s.sbomStore.ListFindingStatuses(ctx, latestVer.ID, nil)
		for _, fs := range statuses {
			if fs.Status == sbommon.FindingStatusFalsePositive ||
				fs.Status == sbommon.FindingStatusSuppressed ||
				fs.Status == sbommon.FindingStatusResolved ||
				fs.Status == sbommon.FindingStatusRiskAccepted {
				excludedStatuses[fs.VulnID+"|"+fs.Purl] = true
			}
		}

		// Build triage inputs for scoring
		vulnScores := make(map[string]*triage.TriageResult)
		var vulnIDs []string
		vulnIDsSeen := make(map[string]bool)
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

		if len(vulnIDs) == 0 {
			continue
		}

		var inputs []*triage.TriageInput
		for _, vulnID := range vulnIDs {
			inputs = append(inputs, s.buildTriageInputForVulnID(ctx, vulnID))
		}

		results, err := engine.TriageBatch(ctx, inputs)
		if err != nil {
			continue
		}
		for _, r := range results {
			vulnScores[r.VulnerabilityID] = r
		}

		// Build ScanFindings for path computation
		for _, f := range scanResult.Findings {
			key := f.VulnID + "|" + f.Purl
			if excludedStatuses[key] {
				continue
			}
			sf := triage.ScanFinding{
				VulnerabilityID: f.VulnID,
				PackagePurl:     f.Purl,
				CurrentVersion:  f.Version,
				FixedVersion:    f.FixedVersion,
				Ecosystem:       f.Ecosystem,
				ServerLabel:     latestVer.Environment,
				ProjectID:       proj.ID,
				ProjectName:     proj.Name,
				Environment:     latestVer.Environment,
			}
			if sf.ServerLabel == "" {
				sf.ServerLabel = "default"
			}
			if result, ok := vulnScores[f.VulnID]; ok {
				sf.CompositeScore = result.CompositeScore
				sf.PriorityLevel = result.PriorityLevel
			}
			scanFindings = append(scanFindings, sf)
		}
	}

	if len(scanFindings) == 0 {
		return nil
	}

	return triage.ComputeTriagePaths(scanFindings)
}

// handleGetTriagePath handles GET /api/v1/triage/paths/{id}
func (s *Server) handleGetTriagePath(w http.ResponseWriter, r *http.Request) {
	pathID := chi.URLParam(r, "id")
	if pathID == "" {
		writeError(w, http.StatusBadRequest, "path ID is required")
		return
	}

	paths := s.computeTriagePaths(r.Context())
	for _, p := range paths {
		if p.ID == pathID {
			writeJSON(w, http.StatusOK, p)
			return
		}
	}

	writeError(w, http.StatusNotFound, "triage path not found: "+pathID)
}

// handleGetProjectTriagePaths handles GET /api/v1/sbom/projects/{project}/triage/paths
func (s *Server) handleGetProjectTriagePaths(w http.ResponseWriter, r *http.Request) {
	projectID := chi.URLParam(r, "id")
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "project ID is required")
		return
	}

	pid, err := strconv.ParseInt(projectID, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid project ID")
		return
	}

	limitStr := r.URL.Query().Get("limit")
	priority := r.URL.Query().Get("priority")

	limit := 20
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	paths := s.computeTriagePathsForProject(r.Context(), pid)

	// Filter by priority
	if priority != "" {
		var filtered []*triage.TriagePath
		for _, p := range paths {
			if strings.EqualFold(string(p.MaxPriorityLevel), priority) {
				filtered = append(filtered, p)
			}
		}
		paths = filtered
	}

	// Apply limit
	if limit < len(paths) {
		paths = paths[:limit]
	}

	if paths == nil {
		paths = []*triage.TriagePath{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"project_id":  projectID,
		"paths":       paths,
		"total":       len(paths),
		"computed_at": time.Now().UTC().Format(time.RFC3339),
	})
}

// computeTriagePathsForProject computes remediation paths for a single SBOM project.
func (s *Server) computeTriagePathsForProject(ctx context.Context, projectID int64) []*triage.TriagePath {
	if s.sbomStore == nil {
		return nil
	}

	latestVer, err := s.sbomStore.GetLatestVersion(ctx, projectID)
	if err != nil || latestVer == nil {
		return nil
	}

	scanResult, err := s.sbomStore.GetLatestScanResult(ctx, latestVer.ID)
	if err != nil || scanResult == nil || len(scanResult.Findings) == 0 {
		return nil
	}

	// Resolve profile for this project/environment
	profile := s.resolveProfileForProjectEnvironment(ctx, projectID, latestVer.Environment)
	engine := triage.NewEngine(profile)

	// Exclude suppressed/false_positive/resolved/risk_accepted findings
	excludedStatuses := make(map[string]bool)
	statuses, _ := s.sbomStore.ListFindingStatuses(ctx, latestVer.ID, nil)
	for _, fs := range statuses {
		if fs.Status == sbommon.FindingStatusFalsePositive ||
			fs.Status == sbommon.FindingStatusSuppressed ||
			fs.Status == sbommon.FindingStatusResolved ||
			fs.Status == sbommon.FindingStatusRiskAccepted {
			excludedStatuses[fs.VulnID+"|"+fs.Purl] = true
		}
	}

	// Build triage inputs for scoring
	vulnScores := make(map[string]*triage.TriageResult)
	var vulnIDs []string
	vulnIDsSeen := make(map[string]bool)
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

	if len(vulnIDs) == 0 {
		return nil
	}

	var inputs []*triage.TriageInput
	for _, vulnID := range vulnIDs {
		inputs = append(inputs, s.buildTriageInputForVulnID(ctx, vulnID))
	}

	results, err := engine.TriageBatch(ctx, inputs)
	if err != nil {
		return nil
	}
	for _, r := range results {
		vulnScores[r.VulnerabilityID] = r
	}

	// Get project info for the ScanFinding (we need project name)
	var projectName string
	user := auth.UserFromContext(ctx)
	if user != nil {
		proj, err := s.sbomStore.GetProject(ctx, projectID, user.ID)
		if err == nil && proj != nil {
			projectName = proj.Name
		}
	}

	// Build ScanFindings for path computation
	var scanFindings []triage.ScanFinding
	for _, f := range scanResult.Findings {
		key := f.VulnID + "|" + f.Purl
		if excludedStatuses[key] {
			continue
		}
		sf := triage.ScanFinding{
			VulnerabilityID: f.VulnID,
			PackagePurl:     f.Purl,
			CurrentVersion:  f.Version,
			FixedVersion:    f.FixedVersion,
			Ecosystem:       f.Ecosystem,
			ServerLabel:     latestVer.Environment,
			ProjectID:       projectID,
			ProjectName:     projectName,
			Environment:     latestVer.Environment,
		}
		if sf.ServerLabel == "" {
			sf.ServerLabel = "default"
		}
		if result, ok := vulnScores[f.VulnID]; ok {
			sf.CompositeScore = result.CompositeScore
			sf.PriorityLevel = result.PriorityLevel
		}
		scanFindings = append(scanFindings, sf)
	}

	if len(scanFindings) == 0 {
		return nil
	}

	return triage.ComputeTriagePaths(scanFindings)
}

// handleDashboardTriage handles GET /api/v1/dashboard/triage
func (s *Server) handleDashboardTriage(w http.ResponseWriter, r *http.Request) {
	summary, _ := s.computeCrossProjectOverview(r.Context())
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"by_priority": map[string]int{
			"critical": summary.Critical,
			"high":     summary.High,
			"medium":   summary.Medium,
			"low":      summary.Low,
		},
		"total_triaged": summary.Total,
		"profile_used":  "default",
		"last_computed": time.Now().UTC().Format(time.RFC3339),
	})
}

// --- Helper functions ---

// resolveTriageProfileWithStore resolves a profile name by checking built-in templates
// first, then falling back to custom profiles stored in the database.
func (s *Server) resolveTriageProfileWithStore(ctx context.Context, name string) *triage.Profile {
	if name == "" {
		return triage.DefaultProfile()
	}
	name = strings.TrimSpace(name)

	// Check built-in templates first
	for _, t := range triage.BuiltinTemplates() {
		if t.Name == name {
			return &t
		}
	}

	// Check custom profiles in DB
	row, err := s.store.GetTriageProfile(ctx, name)
	if err == nil && row != nil {
		if p := rowToProfile(row); p != nil {
			return p
		}
	}

	return triage.DefaultProfile()
}

// rowToProfile converts a TriageProfileRow to a triage.Profile.
func rowToProfile(row *store.TriageProfileRow) *triage.Profile {
	var weights triage.ExtendedWeights
	if err := json.Unmarshal(row.Weights, &weights); err != nil {
		return nil
	}

	var thresholds triage.Thresholds
	if err := json.Unmarshal(row.Thresholds, &thresholds); err != nil {
		return nil
	}

	p := &triage.Profile{
		Name:        row.Name,
		Description: row.Description,
		Base:        row.Base,
		ScoreWeight: row.ScoreWeight,
		ActFloor:    triage.PriorityLevel(row.ActFloor),
		Weights:     &weights,
		Thresholds:  &thresholds,
	}

	if row.SSVCMapping != nil {
		var ssvc map[string]string
		if err := json.Unmarshal(*row.SSVCMapping, &ssvc); err == nil {
			p.SSVCMapping = ssvc
		}
	}

	return p
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
