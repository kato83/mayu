package watchlist

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/kato83/mayu/internal/auth"
)

// --- Request/Response types ---

type createWatchlistRequest struct {
	Name          string   `json:"name"`
	MatchType     string   `json:"match_type"`
	Ecosystem     *string  `json:"ecosystem,omitempty"`
	PackageName   *string  `json:"package_name,omitempty"`
	PurlPattern   *string  `json:"purl_pattern,omitempty"`
	CpePattern    *string  `json:"cpe_pattern,omitempty"`
	SeverityMin   *int16   `json:"severity_min,omitempty"`
	EpssThreshold *float64 `json:"epss_threshold,omitempty"`
	Enabled       *bool    `json:"enabled,omitempty"`
}

type updateWatchlistRequest struct {
	Name          *string  `json:"name,omitempty"`
	MatchType     *string  `json:"match_type,omitempty"`
	Ecosystem     *string  `json:"ecosystem,omitempty"`
	PackageName   *string  `json:"package_name,omitempty"`
	PurlPattern   *string  `json:"purl_pattern,omitempty"`
	CpePattern    *string  `json:"cpe_pattern,omitempty"`
	SeverityMin   *int16   `json:"severity_min,omitempty"`
	EpssThreshold *float64 `json:"epss_threshold,omitempty"`
	Enabled       *bool    `json:"enabled,omitempty"`
}

type watchlistResponse struct {
	ID            int64    `json:"id"`
	Name          string   `json:"name"`
	MatchType     string   `json:"match_type"`
	Ecosystem     *string  `json:"ecosystem,omitempty"`
	PackageName   *string  `json:"package_name,omitempty"`
	PurlPattern   *string  `json:"purl_pattern,omitempty"`
	CpePattern    *string  `json:"cpe_pattern,omitempty"`
	SeverityMin   *int16   `json:"severity_min,omitempty"`
	EpssThreshold *float64 `json:"epss_threshold,omitempty"`
	Enabled       bool     `json:"enabled"`
	CreatedAt     string   `json:"created_at"`
	UpdatedAt     string   `json:"updated_at"`
}

type matchResponse struct {
	ID              int64   `json:"id"`
	WatchlistID     int64   `json:"watchlist_id"`
	VulnerabilityID string  `json:"vulnerability_id"`
	MatchedAt       string  `json:"matched_at"`
	Notified        bool    `json:"notified"`
	NotifiedAt      *string `json:"notified_at,omitempty"`
}

// matchesListResponse wraps match results with a total count.
type matchesListResponse struct {
	Matches []matchResponse `json:"matches"`
	Total   int64           `json:"total"`
}

// --- Handlers ---

// HandleListWatchlists returns an http.HandlerFunc that lists the current user's watchlists.
func HandleListWatchlists(store WatchlistStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		if user == nil {
			writeWatchlistError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		watchlists, err := store.ListWatchlists(r.Context(), user.ID)
		if err != nil {
			writeWatchlistError(w, http.StatusInternalServerError, "failed to list watchlists")
			return
		}

		resp := make([]watchlistResponse, 0, len(watchlists))
		for _, wl := range watchlists {
			resp = append(resp, toWatchlistResponse(wl))
		}

		writeWatchlistJSON(w, http.StatusOK, resp)
	}
}

// HandleCreateWatchlist returns an http.HandlerFunc that creates a watchlist for the current user.
func HandleCreateWatchlist(store WatchlistStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		if user == nil {
			writeWatchlistError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		var req createWatchlistRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeWatchlistError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		if err := validateCreateRequest(&req); err != nil {
			writeWatchlistError(w, http.StatusBadRequest, err.Error())
			return
		}

		enabled := true
		if req.Enabled != nil {
			enabled = *req.Enabled
		}

		wl := &Watchlist{
			UserID:        user.ID,
			Name:          req.Name,
			MatchType:     req.MatchType,
			Ecosystem:     req.Ecosystem,
			PackageName:   req.PackageName,
			PurlPattern:   req.PurlPattern,
			CpePattern:    req.CpePattern,
			SeverityMin:   req.SeverityMin,
			EpssThreshold: req.EpssThreshold,
			Enabled:       enabled,
		}

		id, err := store.CreateWatchlist(r.Context(), wl)
		if err != nil {
			writeWatchlistError(w, http.StatusInternalServerError, "failed to create watchlist")
			return
		}

		// Fetch back the created watchlist for full response
		created, err := store.GetWatchlist(r.Context(), id, user.ID)
		if err != nil || created == nil {
			// Fallback: return minimal response
			wl.ID = id
			wl.CreatedAt = time.Now()
			wl.UpdatedAt = time.Now()
			writeWatchlistJSON(w, http.StatusCreated, toWatchlistResponse(wl))
			return
		}

		writeWatchlistJSON(w, http.StatusCreated, toWatchlistResponse(created))
	}
}

// HandleGetWatchlist returns an http.HandlerFunc that gets a single watchlist by ID.
func HandleGetWatchlist(store WatchlistStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		if user == nil {
			writeWatchlistError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		id, err := parseIDParam(r)
		if err != nil {
			writeWatchlistError(w, http.StatusBadRequest, "invalid watchlist ID")
			return
		}

		wl, err := store.GetWatchlist(r.Context(), id, user.ID)
		if err != nil {
			writeWatchlistError(w, http.StatusInternalServerError, "failed to get watchlist")
			return
		}
		if wl == nil {
			writeWatchlistError(w, http.StatusNotFound, "watchlist not found")
			return
		}

		writeWatchlistJSON(w, http.StatusOK, toWatchlistResponse(wl))
	}
}

// HandleUpdateWatchlist returns an http.HandlerFunc that updates a watchlist by ID.
func HandleUpdateWatchlist(store WatchlistStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		if user == nil {
			writeWatchlistError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		id, err := parseIDParam(r)
		if err != nil {
			writeWatchlistError(w, http.StatusBadRequest, "invalid watchlist ID")
			return
		}

		// First check the watchlist exists and belongs to the user
		existing, err := store.GetWatchlist(r.Context(), id, user.ID)
		if err != nil {
			writeWatchlistError(w, http.StatusInternalServerError, "failed to get watchlist")
			return
		}
		if existing == nil {
			writeWatchlistError(w, http.StatusNotFound, "watchlist not found")
			return
		}

		var req updateWatchlistRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeWatchlistError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		if err := validateUpdateRequest(&req); err != nil {
			writeWatchlistError(w, http.StatusBadRequest, err.Error())
			return
		}

		// Apply updates to existing watchlist
		if req.Name != nil {
			existing.Name = *req.Name
		}
		if req.MatchType != nil {
			existing.MatchType = *req.MatchType
		}
		if req.Ecosystem != nil {
			existing.Ecosystem = req.Ecosystem
		}
		if req.PackageName != nil {
			existing.PackageName = req.PackageName
		}
		if req.PurlPattern != nil {
			existing.PurlPattern = req.PurlPattern
		}
		if req.CpePattern != nil {
			existing.CpePattern = req.CpePattern
		}
		if req.SeverityMin != nil {
			existing.SeverityMin = req.SeverityMin
		}
		if req.EpssThreshold != nil {
			existing.EpssThreshold = req.EpssThreshold
		}
		if req.Enabled != nil {
			existing.Enabled = *req.Enabled
		}

		// Validate the final state to ensure match_type/field consistency
		if err := validateWatchlistState(existing); err != nil {
			writeWatchlistError(w, http.StatusBadRequest, err.Error())
			return
		}

		if err := store.UpdateWatchlist(r.Context(), existing); err != nil {
			writeWatchlistError(w, http.StatusInternalServerError, "failed to update watchlist")
			return
		}

		// Fetch updated version
		updated, err := store.GetWatchlist(r.Context(), id, user.ID)
		if err != nil || updated == nil {
			writeWatchlistJSON(w, http.StatusOK, toWatchlistResponse(existing))
			return
		}

		writeWatchlistJSON(w, http.StatusOK, toWatchlistResponse(updated))
	}
}

// HandleDeleteWatchlist returns an http.HandlerFunc that deletes a watchlist by ID.
func HandleDeleteWatchlist(store WatchlistStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		if user == nil {
			writeWatchlistError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		id, err := parseIDParam(r)
		if err != nil {
			writeWatchlistError(w, http.StatusBadRequest, "invalid watchlist ID")
			return
		}

		// Check it exists first
		existing, err := store.GetWatchlist(r.Context(), id, user.ID)
		if err != nil {
			writeWatchlistError(w, http.StatusInternalServerError, "failed to get watchlist")
			return
		}
		if existing == nil {
			writeWatchlistError(w, http.StatusNotFound, "watchlist not found")
			return
		}

		if err := store.DeleteWatchlist(r.Context(), id, user.ID); err != nil {
			writeWatchlistError(w, http.StatusInternalServerError, "failed to delete watchlist")
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// HandleListWatchlistMatches returns an http.HandlerFunc that lists matches for a watchlist.
func HandleListWatchlistMatches(store WatchlistStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		if user == nil {
			writeWatchlistError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		id, err := parseIDParam(r)
		if err != nil {
			writeWatchlistError(w, http.StatusBadRequest, "invalid watchlist ID")
			return
		}

		// Verify the watchlist belongs to the user
		wl, err := store.GetWatchlist(r.Context(), id, user.ID)
		if err != nil {
			writeWatchlistError(w, http.StatusInternalServerError, "failed to get watchlist")
			return
		}
		if wl == nil {
			writeWatchlistError(w, http.StatusNotFound, "watchlist not found")
			return
		}

		limit, offset := parsePagination(r)

		matches, err := store.ListMatchesByWatchlist(r.Context(), id, limit, offset)
		if err != nil {
			writeWatchlistError(w, http.StatusInternalServerError, "failed to list matches")
			return
		}

		total, err := store.CountMatchesByWatchlist(r.Context(), id)
		if err != nil {
			writeWatchlistError(w, http.StatusInternalServerError, "failed to count matches")
			return
		}

		resp := make([]matchResponse, 0, len(matches))
		for _, m := range matches {
			resp = append(resp, toMatchResponse(m))
		}

		writeWatchlistJSON(w, http.StatusOK, matchesListResponse{
			Matches: resp,
			Total:   total,
		})
	}
}

// HandleListUserMatches returns an http.HandlerFunc that lists all matches for the current user.
func HandleListUserMatches(store WatchlistStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		if user == nil {
			writeWatchlistError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		limit, offset := parsePagination(r)

		matches, err := store.ListMatchesByUser(r.Context(), user.ID, limit, offset)
		if err != nil {
			writeWatchlistError(w, http.StatusInternalServerError, "failed to list matches")
			return
		}

		total, err := store.CountMatchesByUser(r.Context(), user.ID)
		if err != nil {
			writeWatchlistError(w, http.StatusInternalServerError, "failed to count matches")
			return
		}

		resp := make([]matchResponse, 0, len(matches))
		for _, m := range matches {
			resp = append(resp, toMatchResponse(m))
		}

		writeWatchlistJSON(w, http.StatusOK, matchesListResponse{
			Matches: resp,
			Total:   total,
		})
	}
}

// --- Helpers ---

func parseIDParam(r *http.Request) (int64, error) {
	idStr := chi.URLParam(r, "id")
	return strconv.ParseInt(idStr, 10, 64)
}

func parsePagination(r *http.Request) (limit int, offset int) {
	limit = 20
	offset = 0

	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
			if limit > 1000 {
				limit = 1000
			}
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}
	return
}

func toWatchlistResponse(wl *Watchlist) watchlistResponse {
	return watchlistResponse{
		ID:            wl.ID,
		Name:          wl.Name,
		MatchType:     wl.MatchType,
		Ecosystem:     wl.Ecosystem,
		PackageName:   wl.PackageName,
		PurlPattern:   wl.PurlPattern,
		CpePattern:    wl.CpePattern,
		SeverityMin:   wl.SeverityMin,
		EpssThreshold: wl.EpssThreshold,
		Enabled:       wl.Enabled,
		CreatedAt:     wl.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     wl.UpdatedAt.Format(time.RFC3339),
	}
}

func toMatchResponse(m *WatchlistMatch) matchResponse {
	resp := matchResponse{
		ID:              m.ID,
		WatchlistID:     m.WatchlistID,
		VulnerabilityID: m.VulnerabilityID,
		MatchedAt:       m.MatchedAt.Format(time.RFC3339),
		Notified:        m.Notified,
	}
	if m.NotifiedAt != nil {
		s := m.NotifiedAt.Format(time.RFC3339)
		resp.NotifiedAt = &s
	}
	return resp
}

func writeWatchlistJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeWatchlistError(w http.ResponseWriter, status int, message string) {
	writeWatchlistJSON(w, status, map[string]string{"error": message})
}
