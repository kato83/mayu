package server

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/kato83/mayu/internal/store"
)

// validRanges defines allowed values for the range query parameter.
var validRanges = map[string]bool{
	"30d":  true,
	"90d":  true,
	"180d": true,
	"365d": true,
	"all":  true,
}

// validGroupBy defines allowed values for the group_by query parameter.
var validGroupBy = map[string]bool{
	"day":   true,
	"week":  true,
	"month": true,
}

// validMetrics defines allowed values for the metric query parameter.
var validMetrics = map[string]bool{
	"findings": true,
	"severity": true,
	"new":      true,
	"resolved": true,
}

// handleStatsTrend handles GET /api/v1/stats/trend.
// Query parameters:
//   - range: time range (30d, 90d, 180d, 365d, all) - default "30d"
//   - project_id: optional project ID for project-level trends
//   - group_by: aggregation period (day, week, month) - default "day"
//   - metric: optional metric filter (findings, severity, new, resolved)
func (s *Server) handleStatsTrend(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	// Parse and validate range
	rangeParam := q.Get("range")
	if rangeParam == "" {
		rangeParam = "30d"
	}
	if !validRanges[rangeParam] {
		writeError(w, http.StatusBadRequest, "invalid range parameter: must be one of 30d, 90d, 180d, 365d, all")
		return
	}

	// Parse and validate group_by
	groupBy := q.Get("group_by")
	if groupBy == "" {
		groupBy = "day"
	}
	if !validGroupBy[groupBy] {
		writeError(w, http.StatusBadRequest, "invalid group_by parameter: must be one of day, week, month")
		return
	}

	// Parse and validate metric (optional)
	metric := q.Get("metric")
	if metric != "" && !validMetrics[metric] {
		writeError(w, http.StatusBadRequest, "invalid metric parameter: must be one of findings, severity, new, resolved")
		return
	}

	// Parse project_id (optional)
	var projectID int64
	if pidStr := q.Get("project_id"); pidStr != "" {
		pid, err := strconv.ParseInt(pidStr, 10, 64)
		if err != nil || pid < 1 {
			writeError(w, http.StatusBadRequest, "invalid project_id parameter: must be a positive integer")
			return
		}
		projectID = pid
	}

	query := store.StatsTrendQuery{
		Range:     rangeParam,
		ProjectID: projectID,
		GroupBy:   groupBy,
		Metric:    metric,
	}

	result, err := s.store.GetStatsTrend(r.Context(), query)
	if err != nil {
		slog.Error("failed to get stats trend", "error", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, result)
}
