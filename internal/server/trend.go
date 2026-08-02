package server

import (
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/kato83/mayu/internal/store"
)

// staleDaysThreshold is the number of days after which EPSS data is considered stale.
const staleDaysThreshold = 2

// validPeriods defines allowed values for the period query parameter.
var validPeriods = map[string]bool{
	"30d":  true,
	"90d":  true,
	"365d": true,
	"all":  true,
}

// periodToDuration converts a period string to a duration for date filtering.
// Returns nil for "all" (no filtering).
func periodToSince(period string) *time.Time {
	now := time.Now().UTC()
	var since time.Time
	switch period {
	case "30d":
		since = now.AddDate(0, 0, -30)
	case "90d":
		since = now.AddDate(0, 0, -90)
	case "365d":
		since = now.AddDate(0, 0, -365)
	default:
		return nil
	}
	return &since
}

// handleGetLEVHistory handles GET /api/v1/vulnerabilities/{id}/lev-history
func (s *Server) handleGetLEVHistory(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "vulnerability ID is required")
		return
	}

	// Decode percent-encoded path parameter
	if decoded, err := url.PathUnescape(id); err == nil {
		id = decoded
	}

	// Parse period parameter
	period := r.URL.Query().Get("period")
	if period == "" {
		period = "all"
	}
	if !validPeriods[period] {
		writeError(w, http.StatusBadRequest, "invalid period parameter: must be one of 30d, 90d, 365d, all")
		return
	}

	since := periodToSince(period)

	history, err := s.store.GetLEVHistory(r.Context(), id, since)
	if err != nil {
		slog.Error("failed to get LEV history", "id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	if history == nil {
		history = []store.LEVHistoryEntry{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"vulnerability_id": id,
		"period":           period,
		"history":          history,
	})
}

// handleGetEPSSTrending handles GET /api/v1/epss/trending
func (s *Server) handleGetEPSSTrending(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	// Parse days parameter (default 7)
	days := 7
	if d := q.Get("days"); d != "" {
		parsed, err := strconv.Atoi(d)
		if err != nil || parsed < 1 || parsed > 365 {
			writeError(w, http.StatusBadRequest, "invalid days parameter: must be an integer between 1 and 365")
			return
		}
		days = parsed
	}

	// Parse threshold parameter (default 0.1)
	threshold := 0.1
	if t := q.Get("threshold"); t != "" {
		parsed, err := strconv.ParseFloat(t, 64)
		if err != nil || parsed < 0 || parsed > 1 {
			writeError(w, http.StatusBadRequest, "invalid threshold parameter: must be a number between 0 and 1")
			return
		}
		threshold = parsed
	}

	// Parse limit parameter (default 20)
	limit := 20
	if l := q.Get("limit"); l != "" {
		parsed, err := strconv.Atoi(l)
		if err != nil || parsed < 1 || parsed > 100 {
			writeError(w, http.StatusBadRequest, "invalid limit parameter: must be an integer between 1 and 100")
			return
		}
		limit = parsed
	}

	params := store.EPSSTrendingQuery{
		Days:      days,
		Threshold: threshold,
		Limit:     limit,
	}

	result, err := s.store.GetEPSSTrending(r.Context(), params)
	if err != nil {
		slog.Error("failed to get EPSS trending", "error", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	entries := result.Entries
	if entries == nil {
		entries = []store.EPSSTrendingEntry{}
	}

	// Determine staleness: latest_date is staleDaysThreshold+ days before current UTC date
	stale := false
	if result.LatestDate != "" {
		if latestTime, err := time.Parse("2006-01-02", result.LatestDate); err == nil {
			stale = time.Now().UTC().Truncate(24*time.Hour).Sub(latestTime) >= time.Duration(staleDaysThreshold)*24*time.Hour
		}
	}

	// Determine if previous_date data is missing
	previousDateMissing := result.PreviousDate == ""

	// Determine if previous_date differs from expected (data gap)
	previousDateApprox := result.PreviousDate != "" && result.ExpectedPreviousDate != "" && result.PreviousDate != result.ExpectedPreviousDate

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"entries": entries,
		"query": map[string]interface{}{
			"days":      days,
			"threshold": threshold,
			"limit":     limit,
		},
		"latest_date":               result.LatestDate,
		"previous_date":             result.PreviousDate,
		"expected_previous_date":    result.ExpectedPreviousDate,
		"stale":                     stale,
		"previous_date_missing":     previousDateMissing,
		"previous_date_approximate": previousDateApprox,
	})
}
