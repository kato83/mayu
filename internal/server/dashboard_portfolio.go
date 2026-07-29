package server

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/kato83/mayu/internal/auth"
)

// PortfolioResponse is the response body for GET /api/v1/dashboard/portfolio.
type PortfolioResponse struct {
	TotalProjects      int                  `json:"total_projects"`
	TotalComponents    int                  `json:"total_components"`
	TotalFindings      int                  `json:"total_findings"`
	FindingsBySeverity map[string]int       `json:"findings_by_severity"`
	FindingsByStatus   map[string]int       `json:"findings_by_status"`
	Projects           []PortfolioProject   `json:"projects"`
	EOLExposure        PortfolioEOLExposure `json:"eol_exposure"`
}

// PortfolioProject summarizes a single project within the portfolio.
type PortfolioProject struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	LatestVersion string `json:"latest_version"`
	TotalFindings int    `json:"total_findings"`
	Critical      int    `json:"critical"`
	High          int    `json:"high"`
	LastScanned   string `json:"last_scanned,omitempty"`
}

// PortfolioEOLExposure summarizes EOL exposure across the portfolio.
type PortfolioEOLExposure struct {
	Total    int                   `json:"total"`
	Products []PortfolioEOLProduct `json:"products"`
}

// PortfolioEOLProduct is an EOL product found in the portfolio.
type PortfolioEOLProduct struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	EOLDate string `json:"eol_date"`
}

// EOLReportResponse is the response body for GET /api/v1/dashboard/eol-report.
type EOLReportResponse struct {
	EOLProducts []EOLReportEntry   `json:"eol_products"`
	UpcomingEOL []EOLUpcomingEntry `json:"upcoming_eol"`
}

// EOLReportEntry represents a product that has reached EOL.
type EOLReportEntry struct {
	Name             string   `json:"name"`
	Label            string   `json:"label"`
	Release          string   `json:"release"`
	EOLDate          string   `json:"eol_date"`
	IsEOL            bool     `json:"is_eol"`
	AffectedProjects []string `json:"affected_projects"`
}

// EOLUpcomingEntry represents a product approaching EOL.
type EOLUpcomingEntry struct {
	Name         string `json:"name"`
	Label        string `json:"label"`
	Release      string `json:"release"`
	EOLDate      string `json:"eol_date"`
	DaysUntilEOL int    `json:"days_until_eol"`
}

// handleDashboardPortfolio handles GET /api/v1/dashboard/portfolio.
// Returns a cross-project SBOM portfolio summary.
func (s *Server) handleDashboardPortfolio(w http.ResponseWriter, r *http.Request) {
	if s.sbomStore == nil {
		writeError(w, http.StatusServiceUnavailable, "SBOM store not configured")
		return
	}

	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	projects, err := s.sbomStore.ListProjects(r.Context(), user.ID)
	if err != nil {
		slog.Error("failed to list projects for portfolio", "error", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	resp := PortfolioResponse{
		TotalProjects:      len(projects),
		FindingsBySeverity: map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0},
		FindingsByStatus:   map[string]int{"open": 0, "in_triage": 0, "suppressed": 0, "resolved": 0},
		Projects:           []PortfolioProject{},
		EOLExposure:        PortfolioEOLExposure{Products: []PortfolioEOLProduct{}},
	}

	for _, proj := range projects {
		latestVer, err := s.sbomStore.GetLatestVersion(r.Context(), proj.ID)
		if err != nil || latestVer == nil {
			continue
		}

		resp.TotalComponents += latestVer.ComponentCount

		latestScan, err := s.sbomStore.GetLatestScanResult(r.Context(), latestVer.ID)
		if err != nil || latestScan == nil {
			resp.Projects = append(resp.Projects, PortfolioProject{
				ID:            proj.ID,
				Name:          proj.Name,
				LatestVersion: latestVer.Version,
			})
			continue
		}

		projEntry := PortfolioProject{
			ID:            proj.ID,
			Name:          proj.Name,
			LatestVersion: latestVer.Version,
			TotalFindings: latestScan.TotalFindings,
			LastScanned:   latestScan.ScannedAt.Format(time.RFC3339),
		}

		for _, f := range latestScan.Findings {
			resp.TotalFindings++
			switch f.Severity {
			case "CRITICAL":
				resp.FindingsBySeverity["critical"]++
				projEntry.Critical++
			case "HIGH":
				resp.FindingsBySeverity["high"]++
				projEntry.High++
			case "MEDIUM":
				resp.FindingsBySeverity["medium"]++
			case "LOW":
				resp.FindingsBySeverity["low"]++
			}
		}

		// Get finding statuses for this version
		statuses, err := s.sbomStore.ListFindingStatuses(r.Context(), latestVer.ID, nil)
		if err == nil {
			for _, fs := range statuses {
				switch fs.Status {
				case "open":
					resp.FindingsByStatus["open"]++
				case "in_triage":
					resp.FindingsByStatus["in_triage"]++
				case "suppressed", "false_positive", "risk_accepted":
					resp.FindingsByStatus["suppressed"]++
				case "resolved":
					resp.FindingsByStatus["resolved"]++
				}
			}
		}
		// Count findings without explicit status as "open"
		statusCount := 0
		if statuses != nil {
			statusCount = len(statuses)
		}
		if latestScan.TotalFindings > statusCount {
			resp.FindingsByStatus["open"] += latestScan.TotalFindings - statusCount
		}

		resp.Projects = append(resp.Projects, projEntry)
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleDashboardEOLReport handles GET /api/v1/dashboard/eol-report.
// Returns products that are EOL or approaching EOL.
// Query parameter: days (default 180) — how far ahead to look for upcoming EOL.
func (s *Server) handleDashboardEOLReport(w http.ResponseWriter, r *http.Request) {
	days := 180
	if d := r.URL.Query().Get("days"); d != "" {
		parsed, err := strconv.Atoi(d)
		if err != nil || parsed < 1 {
			writeError(w, http.StatusBadRequest, "invalid days parameter: must be a positive integer")
			return
		}
		if parsed > 730 {
			parsed = 730
		}
		days = parsed
	}

	eolProducts, upcomingEOL, err := s.store.GetEOLReport(r.Context(), days)
	if err != nil {
		slog.Error("failed to get EOL report", "error", err, "days", days)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Build affected projects mapping if sbomStore is available
	var affectedMap map[string][]string
	if s.sbomStore != nil {
		user := auth.UserFromContext(r.Context())
		if user != nil {
			affectedMap = s.buildAffectedProjectsMap(r, user.ID)
		}
	}

	resp := EOLReportResponse{
		EOLProducts: make([]EOLReportEntry, 0, len(eolProducts)),
		UpcomingEOL: make([]EOLUpcomingEntry, 0, len(upcomingEOL)),
	}

	for _, p := range eolProducts {
		entry := EOLReportEntry{
			Name:             p.Name,
			Label:            p.Label,
			Release:          p.Release,
			EOLDate:          p.EOLDate,
			IsEOL:            true,
			AffectedProjects: []string{},
		}
		if affectedMap != nil {
			if projects, ok := affectedMap[p.Name+"/"+p.Release]; ok {
				entry.AffectedProjects = projects
			}
		}
		resp.EOLProducts = append(resp.EOLProducts, entry)
	}

	for _, p := range upcomingEOL {
		resp.UpcomingEOL = append(resp.UpcomingEOL, EOLUpcomingEntry{
			Name:         p.Name,
			Label:        p.Label,
			Release:      p.Release,
			EOLDate:      p.EOLDate,
			DaysUntilEOL: p.DaysUntilEOL,
		})
	}

	writeJSON(w, http.StatusOK, resp)
}

// buildAffectedProjectsMap scans SBOM projects to find which ones use EOL products.
// Returns a map of "product/release" → list of project names.
func (s *Server) buildAffectedProjectsMap(r *http.Request, userID int64) map[string][]string {
	// This is a best-effort lookup; we don't fail if it errors
	projects, err := s.sbomStore.ListProjects(r.Context(), userID)
	if err != nil {
		return nil
	}

	// For now, return empty map — full implementation would require
	// matching SBOM component purls against eol_identifiers.
	// This will be enhanced when purl↔EOL matching is implemented.
	_ = projects
	return nil
}
