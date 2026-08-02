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
	if p := s.resolveTriageProfileWithStore(r.Context(), req.ProfileName); p.Name == "default" && req.ProfileName != "default" {
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
		"total_projects": len(projectSet),
		"total_servers":  len(serverSet),
	})
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

	profile := triage.DefaultProfile()
	engine := triage.NewEngine(profile)

	// Collect triage entries grouped by vulnerability ID across all projects
	entriesByVuln := make(map[string][]triage.ServerTriageEntry)

	for _, proj := range projects {
		latestVer, err := s.sbomStore.GetLatestVersion(ctx, proj.ID)
		if err != nil || latestVer == nil {
			continue
		}

		scanResult, err := s.sbomStore.GetLatestScanResult(ctx, latestVer.ID)
		if err != nil || scanResult == nil || len(scanResult.Findings) == 0 {
			continue
		}

		// Exclude suppressed/false_positive/resolved findings
		excludedStatuses := make(map[string]bool)
		statuses, _ := s.sbomStore.ListFindingStatuses(ctx, latestVer.ID, nil)
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
		return &triage.OverviewSummary{}, nil
	}

	// Aggregate cross-project results
	crossResults := triage.AggregateCrossProjectBatch(entriesByVuln)
	summary := triage.ComputeOverviewSummary(crossResults)

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

	profile := triage.DefaultProfile()
	engine := triage.NewEngine(profile)

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

		// Exclude suppressed/false_positive/resolved findings
		excludedStatuses := make(map[string]bool)
		statuses, _ := s.sbomStore.ListFindingStatuses(ctx, latestVer.ID, nil)
		for _, fs := range statuses {
			if fs.Status == sbommon.FindingStatusFalsePositive ||
				fs.Status == sbommon.FindingStatusSuppressed ||
				fs.Status == sbommon.FindingStatusResolved {
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

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"project_id":  projectID,
		"paths":       []interface{}{},
		"total":       0,
		"computed_at": time.Now().UTC().Format(time.RFC3339),
	})
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
