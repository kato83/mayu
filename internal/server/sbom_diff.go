package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/kato83/mayu/internal/auth"
	"github.com/kato83/mayu/internal/sbommon"
)

// SBOMDiffResponse is the response body for GET /api/v1/sbom/projects/{id}/versions/{vid}/diff.
type SBOMDiffResponse struct {
	AddedComponents         []SBOMDiffComponent     `json:"added_components"`
	RemovedComponents       []SBOMDiffComponent     `json:"removed_components"`
	UpdatedComponents       []SBOMDiffUpdated       `json:"updated_components"`
	NewVulnerabilities      []SBOMDiffVulnerability `json:"new_vulnerabilities"`
	ResolvedVulnerabilities []SBOMDiffVulnerability `json:"resolved_vulnerabilities"`
}

// SBOMDiffComponent represents an added or removed component.
type SBOMDiffComponent struct {
	Purl string `json:"purl"`
}

// SBOMDiffUpdated represents a component that was updated between versions.
type SBOMDiffUpdated struct {
	Purl            string `json:"purl"`
	PreviousVersion string `json:"previous_version"`
}

// SBOMDiffVulnerability represents a new or resolved vulnerability in the diff.
type SBOMDiffVulnerability struct {
	VulnID    string `json:"vuln_id"`
	Severity  string `json:"severity"`
	Component string `json:"component"`
}

// handleSBOMVersionDiff handles GET /api/v1/sbom/projects/{id}/versions/{vid}/diff.
// Compares two SBOM versions and returns the diff of components and vulnerabilities.
// Query parameter: compare_to (required) — the version ID to compare against.
func (s *Server) handleSBOMVersionDiff(w http.ResponseWriter, r *http.Request) {
	if s.sbomStore == nil {
		writeError(w, http.StatusServiceUnavailable, "SBOM store not configured")
		return
	}

	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Parse project ID
	projectIDStr := chi.URLParam(r, "id")
	projectID, err := strconv.ParseInt(projectIDStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid project ID")
		return
	}

	// Verify project access
	proj, err := s.sbomStore.GetProject(r.Context(), projectID, user.ID)
	if err != nil {
		slog.Error("failed to get project", "error", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if proj == nil {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}

	// Parse version ID
	versionIDStr := chi.URLParam(r, "vid")
	versionID, err := strconv.ParseInt(versionIDStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid version ID")
		return
	}

	// Parse compare_to parameter
	compareToStr := r.URL.Query().Get("compare_to")
	if compareToStr == "" {
		writeError(w, http.StatusBadRequest, "compare_to query parameter is required")
		return
	}
	compareToID, err := strconv.ParseInt(compareToStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid compare_to parameter")
		return
	}

	// Get both versions
	currentVer, err := s.sbomStore.GetVersion(r.Context(), versionID)
	if err != nil {
		slog.Error("failed to get current version", "error", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if currentVer == nil || currentVer.ProjectID != projectID {
		writeError(w, http.StatusNotFound, "version not found")
		return
	}

	compareVer, err := s.sbomStore.GetVersion(r.Context(), compareToID)
	if err != nil {
		slog.Error("failed to get compare version", "error", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if compareVer == nil || compareVer.ProjectID != projectID {
		writeError(w, http.StatusNotFound, "compare_to version not found")
		return
	}

	// Get latest scan results for both versions
	currentScan, err := s.sbomStore.GetLatestScanResult(r.Context(), versionID)
	if err != nil {
		slog.Error("failed to get current scan result", "error", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if currentScan == nil {
		writeError(w, http.StatusNotFound, "no scan results for current version")
		return
	}

	compareScan, err := s.sbomStore.GetLatestScanResult(r.Context(), compareToID)
	if err != nil {
		slog.Error("failed to get compare scan result", "error", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if compareScan == nil {
		writeError(w, http.StatusNotFound, "no scan results for compare_to version")
		return
	}

	// Compute component diff using raw SBOM data
	added, removed, updated := computeComponentDiff(currentVer, compareVer)

	// Compute vulnerability diff
	newVulns, resolvedVulns := computeVulnerabilityDiff(currentScan, compareScan)

	resp := SBOMDiffResponse{
		AddedComponents:         added,
		RemovedComponents:       removed,
		UpdatedComponents:       updated,
		NewVulnerabilities:      newVulns,
		ResolvedVulnerabilities: resolvedVulns,
	}

	writeJSON(w, http.StatusOK, resp)
}

// computeComponentDiff compares two SBOM versions' raw_sbom to find added, removed, and updated components.
func computeComponentDiff(current, compare *sbommon.SBOMVersion) (
	added []SBOMDiffComponent,
	removed []SBOMDiffComponent,
	updated []SBOMDiffUpdated,
) {
	added = []SBOMDiffComponent{}
	removed = []SBOMDiffComponent{}
	updated = []SBOMDiffUpdated{}

	// Extract purls from each version's raw SBOM
	currentPurls := extractPurlsFromSBOM(current.RawSBOM)
	comparePurls := extractPurlsFromSBOM(compare.RawSBOM)

	// Build lookup maps: base purl (without version) → full purl
	currentByBase := make(map[string]string) // base → full purl
	compareByBase := make(map[string]string)

	for purl, base := range currentPurls {
		currentByBase[base] = purl
	}
	for purl, base := range comparePurls {
		compareByBase[base] = purl
	}

	// Find added and updated
	for base, currentPurl := range currentByBase {
		if comparePurl, exists := compareByBase[base]; exists {
			// Exists in both — check if version changed
			if currentPurl != comparePurl {
				updated = append(updated, SBOMDiffUpdated{
					Purl:            currentPurl,
					PreviousVersion: extractVersionFromPurl(comparePurl),
				})
			}
		} else {
			// Only in current — added
			added = append(added, SBOMDiffComponent{Purl: currentPurl})
		}
	}

	// Find removed
	for base, comparePurl := range compareByBase {
		if _, exists := currentByBase[base]; !exists {
			removed = append(removed, SBOMDiffComponent{Purl: comparePurl})
		}
	}

	return added, removed, updated
}

// extractPurlsFromSBOM extracts package URLs from raw SBOM JSON.
// Returns map of full purl → base purl (without version).
func extractPurlsFromSBOM(rawSBOM []byte) map[string]string {
	result := make(map[string]string)
	if rawSBOM == nil {
		return result
	}

	// Try CycloneDX format first
	type cdxComponent struct {
		Purl string `json:"purl"`
	}
	type cdxSBOM struct {
		Components []cdxComponent `json:"components"`
	}

	var cdx cdxSBOM
	if err := json.Unmarshal(rawSBOM, &cdx); err == nil && len(cdx.Components) > 0 {
		for _, comp := range cdx.Components {
			if comp.Purl != "" {
				base := stripVersionFromPurl(comp.Purl)
				result[comp.Purl] = base
			}
		}
		return result
	}

	// Try SPDX format
	type spdxPackage struct {
		ExternalRefs []struct {
			ReferenceType string `json:"referenceType"`
			Locator       string `json:"referenceLocator"`
		} `json:"externalRefs"`
	}
	type spdxSBOM struct {
		Packages []spdxPackage `json:"packages"`
	}

	var spdx spdxSBOM
	if err := json.Unmarshal(rawSBOM, &spdx); err == nil {
		for _, pkg := range spdx.Packages {
			for _, ref := range pkg.ExternalRefs {
				if ref.ReferenceType == "purl" && ref.Locator != "" {
					base := stripVersionFromPurl(ref.Locator)
					result[ref.Locator] = base
				}
			}
		}
	}

	return result
}

// stripVersionFromPurl removes the version part from a purl string.
// e.g., "pkg:npm/foo@1.0.0" → "pkg:npm/foo"
func stripVersionFromPurl(purl string) string {
	// Strip qualifiers first (anything after ?)
	base := purl
	if qIdx := indexOf(base, '?'); qIdx >= 0 {
		base = base[:qIdx]
	}

	// Find the last @ that separates name from version
	for i := len(base) - 1; i >= 0; i-- {
		if base[i] == '@' {
			// Make sure this isn't a scoped package name (e.g., @angular/core)
			// by checking if there's a / after the @
			isScope := false
			for j := i + 1; j < len(base); j++ {
				if base[j] == '/' {
					isScope = true
					break
				}
			}
			if !isScope {
				return base[:i]
			}
		}
	}
	return base
}

// extractVersionFromPurl extracts the version part from a purl string.
// e.g., "pkg:npm/foo@1.0.0" → "1.0.0"
func extractVersionFromPurl(purl string) string {
	for i := len(purl) - 1; i >= 0; i-- {
		if purl[i] == '@' {
			isScope := false
			for j := i + 1; j < len(purl); j++ {
				if purl[j] == '/' {
					isScope = true
					break
				}
			}
			if !isScope {
				// Strip qualifiers (anything after ?)
				ver := purl[i+1:]
				if qIdx := indexOf(ver, '?'); qIdx >= 0 {
					ver = ver[:qIdx]
				}
				return ver
			}
		}
	}
	return ""
}

// indexOf returns the index of the first occurrence of c in s, or -1 if not found.
func indexOf(s string, c byte) int {
	for i := range s {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// computeVulnerabilityDiff compares scan findings between two versions.
func computeVulnerabilityDiff(current, compare *sbommon.SBOMScanResult) (
	newVulns []SBOMDiffVulnerability,
	resolvedVulns []SBOMDiffVulnerability,
) {
	newVulns = []SBOMDiffVulnerability{}
	resolvedVulns = []SBOMDiffVulnerability{}

	// Build sets of "vulnID|purl" keys
	currentSet := make(map[string]sbommon.ScanFinding)
	compareSet := make(map[string]sbommon.ScanFinding)

	for _, f := range current.Findings {
		key := f.VulnID + "|" + f.Purl
		currentSet[key] = f
	}
	for _, f := range compare.Findings {
		key := f.VulnID + "|" + f.Purl
		compareSet[key] = f
	}

	// New: in current but not in compare
	for key, f := range currentSet {
		if _, exists := compareSet[key]; !exists {
			newVulns = append(newVulns, SBOMDiffVulnerability{
				VulnID:    f.VulnID,
				Severity:  f.Severity,
				Component: f.Purl,
			})
		}
	}

	// Resolved: in compare but not in current
	for key, f := range compareSet {
		if _, exists := currentSet[key]; !exists {
			resolvedVulns = append(resolvedVulns, SBOMDiffVulnerability{
				VulnID:    f.VulnID,
				Severity:  f.Severity,
				Component: f.Purl,
			})
		}
	}

	return newVulns, resolvedVulns
}
