package watchlist

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/kato83/mayu/internal/auth"
)

// --- Handler test helpers ---

// testWatchlistStore is an in-memory implementation for handler tests.
type testWatchlistStore struct {
	watchlists []*Watchlist
	matches    []*WatchlistMatch
	nextID     int64
}

func newTestStore() *testWatchlistStore {
	return &testWatchlistStore{nextID: 1}
}

func (s *testWatchlistStore) CreateWatchlist(_ context.Context, w *Watchlist) (int64, error) {
	id := s.nextID
	s.nextID++
	w.ID = id
	w.CreatedAt = time.Now()
	w.UpdatedAt = time.Now()
	s.watchlists = append(s.watchlists, w)
	return id, nil
}

func (s *testWatchlistStore) GetWatchlist(_ context.Context, id int64, userID int64) (*Watchlist, error) {
	for _, wl := range s.watchlists {
		if wl.ID == id && wl.UserID == userID {
			return wl, nil
		}
	}
	return nil, nil
}

func (s *testWatchlistStore) ListWatchlists(_ context.Context, userID int64) ([]*Watchlist, error) {
	var result []*Watchlist
	for _, wl := range s.watchlists {
		if wl.UserID == userID {
			result = append(result, wl)
		}
	}
	return result, nil
}

func (s *testWatchlistStore) UpdateWatchlist(_ context.Context, w *Watchlist) error {
	for i, wl := range s.watchlists {
		if wl.ID == w.ID {
			w.UpdatedAt = time.Now()
			s.watchlists[i] = w
			return nil
		}
	}
	return nil
}

func (s *testWatchlistStore) DeleteWatchlist(_ context.Context, id int64, userID int64) error {
	for i, wl := range s.watchlists {
		if wl.ID == id && wl.UserID == userID {
			s.watchlists = append(s.watchlists[:i], s.watchlists[i+1:]...)
			return nil
		}
	}
	return nil
}

func (s *testWatchlistStore) ListMatchesByWatchlist(_ context.Context, watchlistID int64, limit int, offset int) ([]*WatchlistMatch, error) {
	var result []*WatchlistMatch
	for _, m := range s.matches {
		if m.WatchlistID == watchlistID {
			result = append(result, m)
		}
	}
	if offset >= len(result) {
		return nil, nil
	}
	end := offset + limit
	if end > len(result) {
		end = len(result)
	}
	return result[offset:end], nil
}

func (s *testWatchlistStore) ListMatchesByUser(_ context.Context, userID int64, limit int, offset int) ([]*WatchlistMatch, error) {
	var result []*WatchlistMatch
	for _, m := range s.matches {
		for _, wl := range s.watchlists {
			if wl.ID == m.WatchlistID && wl.UserID == userID {
				result = append(result, m)
				break
			}
		}
	}
	if offset >= len(result) {
		return nil, nil
	}
	end := offset + limit
	if end > len(result) {
		end = len(result)
	}
	return result[offset:end], nil
}

func (s *testWatchlistStore) CountMatchesByUser(_ context.Context, userID int64) (int64, error) {
	var count int64
	for _, m := range s.matches {
		for _, wl := range s.watchlists {
			if wl.ID == m.WatchlistID && wl.UserID == userID {
				count++
				break
			}
		}
	}
	return count, nil
}

func (s *testWatchlistStore) RecordMatches(_ context.Context, matches []WatchlistMatch) error {
	for i := range matches {
		s.matches = append(s.matches, &matches[i])
	}
	return nil
}

func (s *testWatchlistStore) GetActiveWatchlists(_ context.Context) ([]*Watchlist, error) {
	var result []*Watchlist
	for _, wl := range s.watchlists {
		if wl.Enabled {
			result = append(result, wl)
		}
	}
	return result, nil
}

// requestWithUser creates a request with an authenticated user in context.
func requestWithUser(method, path string, body []byte, user *auth.User) *http.Request {
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, path, bytes.NewReader(body))
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	req.Header.Set("Content-Type", "application/json")
	ctx := auth.ContextWithUser(req.Context(), user)
	return req.WithContext(ctx)
}

// --- Tests ---

func TestHandleCreateWatchlist_Success(t *testing.T) {
	store := newTestStore()
	handler := HandleCreateWatchlist(store)

	body := `{"name":"Test Watch","match_type":"package","ecosystem":"Go","package_name":"golang.org/x/crypto"}`
	req := requestWithUser("POST", "/api/v1/watchlists", []byte(body), &auth.User{ID: 1, Email: "test@example.com"})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp watchlistResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.ID != 1 {
		t.Errorf("expected ID 1, got %d", resp.ID)
	}
	if resp.Name != "Test Watch" {
		t.Errorf("expected name 'Test Watch', got %q", resp.Name)
	}
	if resp.MatchType != "package" {
		t.Errorf("expected match_type 'package', got %q", resp.MatchType)
	}
}

func TestHandleCreateWatchlist_InvalidMatchType(t *testing.T) {
	store := newTestStore()
	handler := HandleCreateWatchlist(store)

	body := `{"name":"Test","match_type":"invalid"}`
	req := requestWithUser("POST", "/api/v1/watchlists", []byte(body), &auth.User{ID: 1})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rr.Code)
	}
}

func TestHandleCreateWatchlist_MissingName(t *testing.T) {
	store := newTestStore()
	handler := HandleCreateWatchlist(store)

	body := `{"match_type":"package","ecosystem":"Go","package_name":"foo"}`
	req := requestWithUser("POST", "/api/v1/watchlists", []byte(body), &auth.User{ID: 1})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rr.Code)
	}
}

func TestHandleCreateWatchlist_MissingRequiredFields(t *testing.T) {
	store := newTestStore()
	handler := HandleCreateWatchlist(store)

	tests := []struct {
		name string
		body string
	}{
		{"package missing ecosystem", `{"name":"T","match_type":"package","package_name":"foo"}`},
		{"package missing package_name", `{"name":"T","match_type":"package","ecosystem":"Go"}`},
		{"purl missing purl_pattern", `{"name":"T","match_type":"purl"}`},
		{"cpe missing cpe_pattern", `{"name":"T","match_type":"cpe"}`},
		{"ecosystem missing ecosystem", `{"name":"T","match_type":"ecosystem"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := requestWithUser("POST", "/api/v1/watchlists", []byte(tt.body), &auth.User{ID: 1})
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("expected status 400, got %d: %s", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestHandleCreateWatchlist_InvalidSeverity(t *testing.T) {
	store := newTestStore()
	handler := HandleCreateWatchlist(store)

	body := `{"name":"T","match_type":"ecosystem","ecosystem":"Go","severity_min":6}`
	req := requestWithUser("POST", "/api/v1/watchlists", []byte(body), &auth.User{ID: 1})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleCreateWatchlist_InvalidEPSS(t *testing.T) {
	store := newTestStore()
	handler := HandleCreateWatchlist(store)

	body := `{"name":"T","match_type":"ecosystem","ecosystem":"Go","epss_threshold":1.5}`
	req := requestWithUser("POST", "/api/v1/watchlists", []byte(body), &auth.User{ID: 1})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleCreateWatchlist_Unauthorized(t *testing.T) {
	store := newTestStore()
	handler := HandleCreateWatchlist(store)

	body := `{"name":"T","match_type":"ecosystem","ecosystem":"Go"}`
	// No user in context
	req := httptest.NewRequest("POST", "/api/v1/watchlists", bytes.NewReader([]byte(body)))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rr.Code)
	}
}

func TestHandleListWatchlists(t *testing.T) {
	store := newTestStore()
	user := &auth.User{ID: 1, Email: "test@example.com"}

	// Seed data
	eco := "Go"
	pkg := "golang.org/x/crypto"
	store.watchlists = []*Watchlist{
		{ID: 1, UserID: 1, Name: "Watch1", MatchType: MatchTypePackage, Ecosystem: &eco, PackageName: &pkg, Enabled: true, CreatedAt: time.Now(), UpdatedAt: time.Now()},
		{ID: 2, UserID: 2, Name: "Other", MatchType: MatchTypeEcosystem, Ecosystem: &eco, Enabled: true, CreatedAt: time.Now(), UpdatedAt: time.Now()},
	}

	handler := HandleListWatchlists(store)
	req := requestWithUser("GET", "/api/v1/watchlists", nil, user)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var resp []watchlistResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp) != 1 {
		t.Fatalf("expected 1 watchlist for user 1, got %d", len(resp))
	}
	if resp[0].Name != "Watch1" {
		t.Errorf("expected name 'Watch1', got %q", resp[0].Name)
	}
}

func TestHandleGetWatchlist(t *testing.T) {
	store := newTestStore()
	user := &auth.User{ID: 1, Email: "test@example.com"}

	eco := "Go"
	store.watchlists = []*Watchlist{
		{ID: 1, UserID: 1, Name: "Watch1", MatchType: MatchTypeEcosystem, Ecosystem: &eco, Enabled: true, CreatedAt: time.Now(), UpdatedAt: time.Now()},
	}

	handler := HandleGetWatchlist(store)

	// Use chi router context to set URL param
	r := chi.NewRouter()
	r.Get("/{id}", handler)

	req := requestWithUser("GET", "/1", nil, user)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleGetWatchlist_NotFound(t *testing.T) {
	store := newTestStore()
	user := &auth.User{ID: 1, Email: "test@example.com"}

	handler := HandleGetWatchlist(store)

	r := chi.NewRouter()
	r.Get("/{id}", handler)

	req := requestWithUser("GET", "/999", nil, user)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", rr.Code)
	}
}

func TestHandleDeleteWatchlist(t *testing.T) {
	store := newTestStore()
	user := &auth.User{ID: 1, Email: "test@example.com"}

	eco := "Go"
	store.watchlists = []*Watchlist{
		{ID: 1, UserID: 1, Name: "Watch1", MatchType: MatchTypeEcosystem, Ecosystem: &eco, Enabled: true, CreatedAt: time.Now(), UpdatedAt: time.Now()},
	}

	handler := HandleDeleteWatchlist(store)

	r := chi.NewRouter()
	r.Delete("/{id}", handler)

	req := requestWithUser("DELETE", "/1", nil, user)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d: %s", rr.Code, rr.Body.String())
	}

	if len(store.watchlists) != 0 {
		t.Error("watchlist was not deleted from store")
	}
}

func TestHandleDeleteWatchlist_NotFound(t *testing.T) {
	store := newTestStore()
	user := &auth.User{ID: 1, Email: "test@example.com"}

	handler := HandleDeleteWatchlist(store)

	r := chi.NewRouter()
	r.Delete("/{id}", handler)

	req := requestWithUser("DELETE", "/999", nil, user)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", rr.Code)
	}
}

func TestHandleUpdateWatchlist(t *testing.T) {
	store := newTestStore()
	user := &auth.User{ID: 1, Email: "test@example.com"}

	eco := "Go"
	store.watchlists = []*Watchlist{
		{ID: 1, UserID: 1, Name: "Watch1", MatchType: MatchTypeEcosystem, Ecosystem: &eco, Enabled: true, CreatedAt: time.Now(), UpdatedAt: time.Now()},
	}

	handler := HandleUpdateWatchlist(store)

	r := chi.NewRouter()
	r.Put("/{id}", handler)

	body := `{"name":"Updated Watch"}`
	req := requestWithUser("PUT", "/1", []byte(body), user)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp watchlistResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Name != "Updated Watch" {
		t.Errorf("expected name 'Updated Watch', got %q", resp.Name)
	}
}

func TestHandleListUserMatches(t *testing.T) {
	store := newTestStore()
	user := &auth.User{ID: 1, Email: "test@example.com"}

	eco := "Go"
	store.watchlists = []*Watchlist{
		{ID: 1, UserID: 1, Name: "Watch1", MatchType: MatchTypeEcosystem, Ecosystem: &eco, Enabled: true, CreatedAt: time.Now(), UpdatedAt: time.Now()},
	}
	store.matches = []*WatchlistMatch{
		{ID: 1, WatchlistID: 1, VulnerabilityID: "CVE-2024-0001", MatchedAt: time.Now()},
		{ID: 2, WatchlistID: 1, VulnerabilityID: "CVE-2024-0002", MatchedAt: time.Now()},
	}

	handler := HandleListUserMatches(store)
	req := requestWithUser("GET", "/api/v1/watchlists/matches", nil, user)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp []matchResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(resp))
	}

	// Check X-Total-Count header
	totalCount := rr.Header().Get("X-Total-Count")
	if totalCount != "2" {
		t.Errorf("expected X-Total-Count 2, got %q", totalCount)
	}
}

func TestHandleListWatchlistMatches(t *testing.T) {
	store := newTestStore()
	user := &auth.User{ID: 1, Email: "test@example.com"}

	eco := "Go"
	store.watchlists = []*Watchlist{
		{ID: 1, UserID: 1, Name: "Watch1", MatchType: MatchTypeEcosystem, Ecosystem: &eco, Enabled: true, CreatedAt: time.Now(), UpdatedAt: time.Now()},
	}
	store.matches = []*WatchlistMatch{
		{ID: 1, WatchlistID: 1, VulnerabilityID: "CVE-2024-0001", MatchedAt: time.Now()},
	}

	handler := HandleListWatchlistMatches(store)

	r := chi.NewRouter()
	r.Get("/{id}/matches", handler)

	req := requestWithUser("GET", "/1/matches", nil, user)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp []matchResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp) != 1 {
		t.Fatalf("expected 1 match, got %d", len(resp))
	}
}
