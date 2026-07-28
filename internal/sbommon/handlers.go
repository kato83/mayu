package sbommon

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/kato83/mayu/internal/auth"
)

// --- Request/Response types ---

type createProjectRequest struct {
	Name string `json:"name"`
}

type projectResponse struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type versionResponse struct {
	ID             int64  `json:"id"`
	ProjectID      int64  `json:"project_id"`
	Version        string `json:"version"`
	Environment    string `json:"environment,omitempty"`
	SBOMFormat     string `json:"sbom_format"`
	ComponentCount int    `json:"component_count"`
	CreatedAt      string `json:"created_at"`
}

type scanResultResponse struct {
	ID                 int64         `json:"id"`
	VersionID          int64         `json:"version_id"`
	ScannedAt          string        `json:"scanned_at"`
	TotalPackages      int           `json:"total_packages"`
	VulnerablePackages int           `json:"vulnerable_packages"`
	TotalFindings      int           `json:"total_findings"`
	NewFindings        int           `json:"new_findings"`
	ResolvedFindings   int           `json:"resolved_findings"`
	Findings           []ScanFinding `json:"findings"`
	Status             string        `json:"status"`
	Trigger            string        `json:"trigger"`
}

type scanDiffResponse struct {
	NewFindings      []ScanFinding `json:"new_findings"`
	ResolvedFindings []ScanFinding `json:"resolved_findings"`
}

type uploadSBOMResponse struct {
	Version    versionResponse    `json:"version"`
	ScanResult scanResultResponse `json:"scan_result"`
}

// --- Handlers ---

// HandleCreateProject returns an http.HandlerFunc that creates an SBOM project.
func HandleCreateProject(store SBOMStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		if user == nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		var req createProjectRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		if req.Name == "" {
			writeError(w, http.StatusBadRequest, "name is required")
			return
		}

		p := &SBOMProject{
			UserID: user.ID,
			Name:   req.Name,
		}

		id, err := store.CreateProject(r.Context(), p)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to create project")
			return
		}

		created, err := store.GetProject(r.Context(), id, user.ID)
		if err != nil || created == nil {
			p.ID = id
			p.CreatedAt = time.Now()
			p.UpdatedAt = time.Now()
			writeJSON(w, http.StatusCreated, toProjectResponse(p))
			return
		}

		writeJSON(w, http.StatusCreated, toProjectResponse(created))
	}
}

// HandleListProjects returns an http.HandlerFunc that lists the user's SBOM projects.
func HandleListProjects(store SBOMStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		if user == nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		projects, err := store.ListProjects(r.Context(), user.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to list projects")
			return
		}

		resp := make([]projectResponse, 0, len(projects))
		for _, p := range projects {
			resp = append(resp, toProjectResponse(p))
		}

		writeJSON(w, http.StatusOK, resp)
	}
}

// HandleGetProject returns an http.HandlerFunc that gets a single SBOM project.
func HandleGetProject(store SBOMStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		if user == nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		id, err := parseID(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid project ID")
			return
		}

		p, err := store.GetProject(r.Context(), id, user.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to get project")
			return
		}
		if p == nil {
			writeError(w, http.StatusNotFound, "project not found")
			return
		}

		writeJSON(w, http.StatusOK, toProjectResponse(p))
	}
}

// HandleDeleteProject returns an http.HandlerFunc that deletes an SBOM project.
func HandleDeleteProject(store SBOMStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		if user == nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		id, err := parseID(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid project ID")
			return
		}

		existing, err := store.GetProject(r.Context(), id, user.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to get project")
			return
		}
		if existing == nil {
			writeError(w, http.StatusNotFound, "project not found")
			return
		}

		if err := store.DeleteProject(r.Context(), id, user.ID); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to delete project")
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// HandleUploadSBOM returns an http.HandlerFunc that creates a version and runs a scan.
func HandleUploadSBOM(sbomStore SBOMStore, scanner *Scanner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		if user == nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		id, err := parseID(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid project ID")
			return
		}

		project, err := sbomStore.GetProject(r.Context(), id, user.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to get project")
			return
		}
		if project == nil {
			writeError(w, http.StatusNotFound, "project not found")
			return
		}

		// Read multipart or JSON body
		var versionStr, environment string
		var sbomData []byte

		contentType := r.Header.Get("Content-Type")
		if contentType == "application/json" || contentType == "" {
			// Apply body size limit for JSON path (50MB)
			r.Body = http.MaxBytesReader(w, r.Body, 50*1024*1024)

			// JSON body with sbom inline
			var body struct {
				Version     string          `json:"version"`
				Environment string          `json:"environment,omitempty"`
				SBOM        json.RawMessage `json:"sbom"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeError(w, http.StatusBadRequest, "invalid request body")
				return
			}
			versionStr = body.Version
			environment = body.Environment
			sbomData = body.SBOM
		} else {
			// Read version and environment from query params, body is raw SBOM
			versionStr = r.URL.Query().Get("version")
			environment = r.URL.Query().Get("environment")
			sbomData, err = io.ReadAll(io.LimitReader(r.Body, 50*1024*1024)) // 50MB limit
			if err != nil {
				writeError(w, http.StatusBadRequest, "failed to read request body")
				return
			}
		}

		if versionStr == "" {
			writeError(w, http.StatusBadRequest, "version is required")
			return
		}
		if len(sbomData) == 0 {
			writeError(w, http.StatusBadRequest, "sbom data is required")
			return
		}

		// Run scan to validate SBOM and get results
		scanResult, err := scanner.Scan(r.Context(), sbomData)
		if err != nil {
			writeError(w, http.StatusBadRequest, "failed to scan SBOM: "+err.Error())
			return
		}

		// Detect format from scan
		parsed, parseErr := parseSBOMFormat(sbomData)
		sbomFormat := ""
		componentCount := 0
		if parseErr == nil {
			sbomFormat = parsed.Format
			componentCount = len(parsed.Components)
		}

		// Create version
		ver := &SBOMVersion{
			ProjectID:      project.ID,
			Version:        versionStr,
			Environment:    environment,
			SBOMFormat:     sbomFormat,
			RawSBOM:        sbomData,
			ComponentCount: componentCount,
		}

		versionID, err := sbomStore.CreateVersion(r.Context(), ver)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to create version")
			return
		}

		// Get previous scan for diff computation
		prevResult, _ := sbomStore.GetLatestScanResult(r.Context(), versionID)

		// Compute diff
		diff := ComputeDiff(scanResult, prevResult)
		scanResult.VersionID = versionID
		scanResult.Trigger = "api"
		scanResult.NewFindings = len(diff.NewFindings)
		scanResult.ResolvedFindings = len(diff.ResolvedFindings)

		// Store scan result
		scanID, err := sbomStore.CreateScanResult(r.Context(), scanResult)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to store scan result")
			return
		}
		scanResult.ID = scanID

		// Fetch back version for response
		createdVersion, _ := sbomStore.GetVersion(r.Context(), versionID)
		if createdVersion == nil {
			createdVersion = ver
			createdVersion.ID = versionID
			createdVersion.CreatedAt = time.Now()
		}

		writeJSON(w, http.StatusCreated, uploadSBOMResponse{
			Version:    toVersionResponse(createdVersion),
			ScanResult: toScanResultResponse(scanResult),
		})
	}
}

// HandleListVersions returns an http.HandlerFunc that lists versions for a project.
func HandleListVersions(sbomStore SBOMStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		if user == nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		id, err := parseID(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid project ID")
			return
		}

		project, err := sbomStore.GetProject(r.Context(), id, user.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to get project")
			return
		}
		if project == nil {
			writeError(w, http.StatusNotFound, "project not found")
			return
		}

		versions, err := sbomStore.ListVersions(r.Context(), id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to list versions")
			return
		}

		resp := make([]versionResponse, 0, len(versions))
		for _, v := range versions {
			resp = append(resp, toVersionResponse(v))
		}

		writeJSON(w, http.StatusOK, resp)
	}
}

// HandleListScanResults returns an http.HandlerFunc that lists scan results for a version.
func HandleListScanResults(sbomStore SBOMStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		if user == nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		versionIDStr := chi.URLParam(r, "versionID")
		versionID, err := strconv.ParseInt(versionIDStr, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid version ID")
			return
		}

		// Verify the version exists
		version, err := sbomStore.GetVersion(r.Context(), versionID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to get version")
			return
		}
		if version == nil {
			writeError(w, http.StatusNotFound, "version not found")
			return
		}

		// Verify the version's parent project belongs to the authenticated user
		project, err := sbomStore.GetProject(r.Context(), version.ProjectID, user.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to verify project ownership")
			return
		}
		if project == nil {
			writeError(w, http.StatusNotFound, "version not found")
			return
		}

		results, err := sbomStore.ListScanResults(r.Context(), versionID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to list scan results")
			return
		}

		resp := make([]scanResultResponse, 0, len(results))
		for _, sr := range results {
			resp = append(resp, toScanResultResponse(sr))
		}

		writeJSON(w, http.StatusOK, resp)
	}
}

// HandleGetScanResult returns an http.HandlerFunc that gets a single scan result.
func HandleGetScanResult(sbomStore SBOMStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		if user == nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		scanIDStr := chi.URLParam(r, "scanID")
		scanID, err := strconv.ParseInt(scanIDStr, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid scan result ID")
			return
		}

		sr, err := sbomStore.GetScanResult(r.Context(), scanID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to get scan result")
			return
		}
		if sr == nil {
			writeError(w, http.StatusNotFound, "scan result not found")
			return
		}

		// Verify ownership: scan -> version -> project -> user
		version, err := sbomStore.GetVersion(r.Context(), sr.VersionID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to verify ownership")
			return
		}
		if version == nil {
			writeError(w, http.StatusNotFound, "scan result not found")
			return
		}
		project, err := sbomStore.GetProject(r.Context(), version.ProjectID, user.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to verify ownership")
			return
		}
		if project == nil {
			writeError(w, http.StatusNotFound, "scan result not found")
			return
		}

		writeJSON(w, http.StatusOK, toScanResultResponse(sr))
	}
}

// HandleGetScanDiff returns an http.HandlerFunc that computes the diff between
// a scan result and its predecessor.
func HandleGetScanDiff(sbomStore SBOMStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		if user == nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		scanIDStr := chi.URLParam(r, "scanID")
		scanID, err := strconv.ParseInt(scanIDStr, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid scan result ID")
			return
		}

		current, err := sbomStore.GetScanResult(r.Context(), scanID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to get scan result")
			return
		}
		if current == nil {
			writeError(w, http.StatusNotFound, "scan result not found")
			return
		}

		// Verify ownership: scan -> version -> project -> user
		version, err := sbomStore.GetVersion(r.Context(), current.VersionID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to verify ownership")
			return
		}
		if version == nil {
			writeError(w, http.StatusNotFound, "scan result not found")
			return
		}
		project, err := sbomStore.GetProject(r.Context(), version.ProjectID, user.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to verify ownership")
			return
		}
		if project == nil {
			writeError(w, http.StatusNotFound, "scan result not found")
			return
		}

		previous, err := sbomStore.GetPreviousScanResult(r.Context(), current.VersionID, current.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to get previous scan result")
			return
		}

		diff := ComputeDiff(current, previous)

		writeJSON(w, http.StatusOK, scanDiffResponse{
			NewFindings:      orEmptyFindings(diff.NewFindings),
			ResolvedFindings: orEmptyFindings(diff.ResolvedFindings),
		})
	}
}

// --- Helpers ---

func parseID(r *http.Request) (int64, error) {
	idStr := chi.URLParam(r, "id")
	return strconv.ParseInt(idStr, 10, 64)
}

func toProjectResponse(p *SBOMProject) projectResponse {
	return projectResponse{
		ID:        p.ID,
		Name:      p.Name,
		CreatedAt: p.CreatedAt.Format(time.RFC3339),
		UpdatedAt: p.UpdatedAt.Format(time.RFC3339),
	}
}

func toVersionResponse(v *SBOMVersion) versionResponse {
	return versionResponse{
		ID:             v.ID,
		ProjectID:      v.ProjectID,
		Version:        v.Version,
		Environment:    v.Environment,
		SBOMFormat:     v.SBOMFormat,
		ComponentCount: v.ComponentCount,
		CreatedAt:      v.CreatedAt.Format(time.RFC3339),
	}
}

func toScanResultResponse(sr *SBOMScanResult) scanResultResponse {
	return scanResultResponse{
		ID:                 sr.ID,
		VersionID:          sr.VersionID,
		ScannedAt:          sr.ScannedAt.Format(time.RFC3339),
		TotalPackages:      sr.TotalPackages,
		VulnerablePackages: sr.VulnerablePackages,
		TotalFindings:      sr.TotalFindings,
		NewFindings:        sr.NewFindings,
		ResolvedFindings:   sr.ResolvedFindings,
		Findings:           orEmptyFindings(sr.Findings),
		Status:             sr.Status,
		Trigger:            sr.Trigger,
	}
}

func orEmptyFindings(findings []ScanFinding) []ScanFinding {
	if findings == nil {
		return []ScanFinding{}
	}
	return findings
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// parseSBOMFormat is a helper to parse just the SBOM format info.
func parseSBOMFormat(data []byte) (*struct {
	Format     string
	Components []struct{}
}, error) {
	var probe struct {
		BomFormat   string `json:"bomFormat"`
		SpdxVersion string `json:"spdxVersion"`
		Components  []struct {
			Purl string `json:"purl"`
		} `json:"components"`
		Packages []struct {
			ExternalRefs []struct {
				ReferenceType    string `json:"referenceType"`
				ReferenceLocator string `json:"referenceLocator"`
			} `json:"externalRefs"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, err
	}

	format := ""
	count := 0
	if probe.BomFormat == "CycloneDX" {
		format = "CycloneDX"
		count = len(probe.Components)
	} else if probe.SpdxVersion != "" {
		format = "SPDX"
		count = len(probe.Packages)
	}

	result := &struct {
		Format     string
		Components []struct{}
	}{
		Format:     format,
		Components: make([]struct{}, count),
	}
	return result, nil
}
