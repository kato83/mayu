package server

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/kato83/mayu/internal/auth"
)

// handleDashboardSummary handles GET /api/v1/dashboard/summary.
// Returns overview counts (total, recent, severity, KEV).
func (s *Server) handleDashboardSummary(w http.ResponseWriter, r *http.Request) {
	summary, err := s.store.GetDashboardSummary(r.Context())
	if err != nil {
		slog.Error("failed to get dashboard summary", "error", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

// handleDashboardTrends handles GET /api/v1/dashboard/trends.
// Query parameter: days (default 30, max 365).
// Returns daily new vulnerability counts for the requested period.
func (s *Server) handleDashboardTrends(w http.ResponseWriter, r *http.Request) {
	days := 30
	if d := r.URL.Query().Get("days"); d != "" {
		parsed, err := strconv.Atoi(d)
		if err != nil || parsed < 1 {
			writeError(w, http.StatusBadRequest, "invalid days parameter: must be a positive integer")
			return
		}
		if parsed > 365 {
			parsed = 365
		}
		days = parsed
	}

	trends, err := s.store.GetDashboardTrends(r.Context(), days)
	if err != nil {
		slog.Error("failed to get dashboard trends", "error", err, "days", days)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, trends)
}

// handleDashboardDistributions handles GET /api/v1/dashboard/distributions.
// Returns severity, ecosystem, EPSS, and LEV distribution data.
func (s *Server) handleDashboardDistributions(w http.ResponseWriter, r *http.Request) {
	dist, err := s.store.GetDashboardDistributions(r.Context())
	if err != nil {
		slog.Error("failed to get dashboard distributions", "error", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, dist)
}

// handleDashboardTopRisks handles GET /api/v1/dashboard/top-risks.
// Query parameter: limit (default 10, max 50).
// Returns top vulnerabilities by EPSS and LEV scores.
func (s *Server) handleDashboardTopRisks(w http.ResponseWriter, r *http.Request) {
	limit := 10
	if l := r.URL.Query().Get("limit"); l != "" {
		parsed, err := strconv.Atoi(l)
		if err != nil || parsed < 1 {
			writeError(w, http.StatusBadRequest, "invalid limit parameter: must be a positive integer")
			return
		}
		if parsed > 50 {
			parsed = 50
		}
		limit = parsed
	}

	risks, err := s.store.GetDashboardTopRisks(r.Context(), limit)
	if err != nil {
		slog.Error("failed to get dashboard top risks", "error", err, "limit", limit)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, risks)
}

// TeamDashboardSummary holds team-scoped vulnerability dashboard data.
type TeamDashboardSummary struct {
	TeamID        int64                `json:"team_id"`
	TeamName      string               `json:"team_name"`
	TotalProjects int                  `json:"total_projects"`
	TotalFindings int                  `json:"total_findings"`
	BySeverity    map[string]int       `json:"by_severity"`
	TopProjects   []ProjectRiskSummary `json:"top_projects"`
	RecentScans   []RecentScanSummary  `json:"recent_scans"`
	KEVExposure   int                  `json:"kev_exposure"`
}

// ProjectRiskSummary summarizes risk for a single project.
type ProjectRiskSummary struct {
	ProjectID   int64  `json:"project_id"`
	ProjectName string `json:"project_name"`
	Critical    int    `json:"critical"`
	High        int    `json:"high"`
	Medium      int    `json:"medium"`
	Low         int    `json:"low"`
	Total       int    `json:"total"`
}

// RecentScanSummary summarizes a recent scan.
type RecentScanSummary struct {
	ProjectName   string `json:"project_name"`
	Version       string `json:"version"`
	ScannedAt     string `json:"scanned_at"`
	TotalFindings int    `json:"total_findings"`
	NewFindings   int    `json:"new_findings"`
}

// handleDashboardTeamSummary handles GET /api/v1/dashboard/team-summary.
// Query parameter: team_id (required).
// Returns SBOM project-level finding summary scoped by team.
func (s *Server) handleDashboardTeamSummary(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	teamIDStr := r.URL.Query().Get("team_id")
	if teamIDStr == "" {
		writeError(w, http.StatusBadRequest, "team_id is required")
		return
	}
	teamID, err := strconv.ParseInt(teamIDStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid team_id")
		return
	}

	// Check access: admin sees all, otherwise must be team member
	if s.teamStore != nil && user.Role != "admin" {
		isMember, err := s.teamStore.IsTeamMember(r.Context(), teamID, user.ID)
		if err != nil {
			slog.Error("failed to check team membership", "error", err)
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}
		if !isMember {
			writeError(w, http.StatusForbidden, "not a team member")
			return
		}
	}

	// Get team info
	var teamName string
	if s.teamStore != nil {
		t, err := s.teamStore.GetTeam(r.Context(), teamID)
		if err != nil {
			slog.Error("failed to get team", "error", err)
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}
		if t == nil {
			writeError(w, http.StatusNotFound, "team not found")
			return
		}
		teamName = t.Name
	}

	// Get team's projects
	if s.sbomStore == nil {
		writeError(w, http.StatusServiceUnavailable, "SBOM store not configured")
		return
	}

	projects, err := s.sbomStore.ListProjectsByTeam(r.Context(), teamID)
	if err != nil {
		slog.Error("failed to list team projects", "error", err, "team_id", teamID)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	summary := TeamDashboardSummary{
		TeamID:        teamID,
		TeamName:      teamName,
		TotalProjects: len(projects),
		BySeverity:    map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0},
		TopProjects:   []ProjectRiskSummary{},
		RecentScans:   []RecentScanSummary{},
	}

	// Aggregate findings across all team projects
	for _, proj := range projects {
		// Get latest version
		latestVer, err := s.sbomStore.GetLatestVersion(r.Context(), proj.ID)
		if err != nil || latestVer == nil {
			continue
		}

		// Get latest scan result
		latestScan, err := s.sbomStore.GetLatestScanResult(r.Context(), latestVer.ID)
		if err != nil || latestScan == nil {
			continue
		}

		projSummary := ProjectRiskSummary{
			ProjectID:   proj.ID,
			ProjectName: proj.Name,
		}

		for _, f := range latestScan.Findings {
			summary.TotalFindings++
			switch f.Severity {
			case "CRITICAL":
				summary.BySeverity["critical"]++
				projSummary.Critical++
			case "HIGH":
				summary.BySeverity["high"]++
				projSummary.High++
			case "MEDIUM":
				summary.BySeverity["medium"]++
				projSummary.Medium++
			case "LOW":
				summary.BySeverity["low"]++
				projSummary.Low++
			}
			projSummary.Total++
		}

		summary.TopProjects = append(summary.TopProjects, projSummary)

		// Add to recent scans (limit to 10 most recent)
		if len(summary.RecentScans) < 10 {
			summary.RecentScans = append(summary.RecentScans, RecentScanSummary{
				ProjectName:   proj.Name,
				Version:       latestVer.Version,
				ScannedAt:     latestScan.ScannedAt.Format("2006-01-02T15:04:05Z07:00"),
				TotalFindings: latestScan.TotalFindings,
				NewFindings:   latestScan.NewFindings,
			})
		}
	}

	writeJSON(w, http.StatusOK, summary)
}
