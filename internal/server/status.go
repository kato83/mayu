package server

import (
	"log/slog"
	"net/http"
)

// statusResponse is the JSON response for GET /api/v1/status.
type statusResponse struct {
	SyncStates   []syncStateResponse   `json:"sync_states"`
	EPSSCoverage *epssCoverageResponse `json:"epss_coverage"`
}

type syncStateResponse struct {
	Source         string `json:"source"`
	SourceType     string `json:"source_type"`
	LastModifiedAt string `json:"last_modified_at"`
	LastSyncedAt   string `json:"last_synced_at"`
	RecordCount    int64  `json:"record_count"`
}

type epssCoverageResponse struct {
	TotalDays    int      `json:"total_days"`
	FirstDate    string   `json:"first_date"`
	LastDate     string   `json:"last_date"`
	TotalScores  int64    `json:"total_scores"`
	MissingDates []string `json:"missing_dates"`
}

// handleStatus handles GET /api/v1/status — returns data source sync states
// and EPSS coverage information.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	states, err := s.store.ListSyncStates(ctx)
	if err != nil {
		slog.Error("failed to list sync states", "error", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	coverage, err := s.store.GetEPSSCoverage(ctx)
	if err != nil {
		slog.Error("failed to get EPSS coverage", "error", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	resp := statusResponse{
		SyncStates: make([]syncStateResponse, 0, len(states)),
	}

	for _, st := range states {
		resp.SyncStates = append(resp.SyncStates, syncStateResponse{
			Source:         st.Source,
			SourceType:     st.SourceType,
			LastModifiedAt: st.LastModifiedAt,
			LastSyncedAt:   st.LastSyncedAt,
			RecordCount:    st.RecordCount,
		})
	}

	if coverage != nil {
		missingDates := coverage.MissingDates
		if missingDates == nil {
			missingDates = []string{}
		}
		resp.EPSSCoverage = &epssCoverageResponse{
			TotalDays:    coverage.TotalDays,
			FirstDate:    coverage.FirstDate,
			LastDate:     coverage.LastDate,
			TotalScores:  coverage.TotalScores,
			MissingDates: missingDates,
		}
	}

	writeJSON(w, http.StatusOK, resp)
}
