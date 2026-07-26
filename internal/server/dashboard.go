package server

import (
	"log/slog"
	"net/http"
	"strconv"
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
