package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kato83/mayu/internal/store"
)

func TestHandleStatsTrend_Success(t *testing.T) {
	ms := &mockStore{
		getStatsTrendFunc: func(ctx context.Context, query store.StatsTrendQuery) (*store.StatsTrendResponse, error) {
			if query.Range != "30d" {
				t.Errorf("expected range 30d, got %q", query.Range)
			}
			if query.GroupBy != "day" {
				t.Errorf("expected group_by day, got %q", query.GroupBy)
			}
			if query.ProjectID != 0 {
				t.Errorf("expected project_id 0, got %d", query.ProjectID)
			}
			return &store.StatsTrendResponse{
				Range:   "30d",
				GroupBy: "day",
				DataPoints: []store.StatsTrendDataPoint{
					{Date: "2024-01-01", Total: 10, Critical: 2, High: 3, Medium: 4, Low: 1},
					{Date: "2024-01-02", Total: 5, Critical: 1, High: 2, Medium: 1, Low: 1},
				},
			}, nil
		},
	}
	srv := newTestServer(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats/trend", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp store.StatsTrendResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Range != "30d" {
		t.Errorf("expected range 30d, got %q", resp.Range)
	}
	if resp.GroupBy != "day" {
		t.Errorf("expected group_by day, got %q", resp.GroupBy)
	}
	if len(resp.DataPoints) != 2 {
		t.Fatalf("expected 2 data points, got %d", len(resp.DataPoints))
	}
	if resp.DataPoints[0].Date != "2024-01-01" {
		t.Errorf("expected first date 2024-01-01, got %q", resp.DataPoints[0].Date)
	}
	if resp.DataPoints[0].Total != 10 {
		t.Errorf("expected first total 10, got %d", resp.DataPoints[0].Total)
	}
	if resp.DataPoints[0].Critical != 2 {
		t.Errorf("expected first critical 2, got %d", resp.DataPoints[0].Critical)
	}
}

func TestHandleStatsTrend_InvalidRange(t *testing.T) {
	srv := newTestServer(&mockStore{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats/trend?range=invalid", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["error"] == "" {
		t.Error("expected error message in response")
	}
}

func TestHandleStatsTrend_InvalidGroupBy(t *testing.T) {
	srv := newTestServer(&mockStore{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats/trend?group_by=year", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["error"] == "" {
		t.Error("expected error message in response")
	}
}

func TestHandleStatsTrend_WithProjectID(t *testing.T) {
	ms := &mockStore{
		getStatsTrendFunc: func(ctx context.Context, query store.StatsTrendQuery) (*store.StatsTrendResponse, error) {
			if query.ProjectID != 5 {
				t.Errorf("expected project_id 5, got %d", query.ProjectID)
			}
			if query.Range != "90d" {
				t.Errorf("expected range 90d, got %q", query.Range)
			}
			if query.GroupBy != "week" {
				t.Errorf("expected group_by week, got %q", query.GroupBy)
			}
			return &store.StatsTrendResponse{
				Range:   "90d",
				GroupBy: "week",
				DataPoints: []store.StatsTrendDataPoint{
					{Date: "2024-01-01", Total: 20, New: 5, Resolved: 3},
				},
			}, nil
		},
	}
	srv := newTestServer(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats/trend?project_id=5&range=90d&group_by=week", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp store.StatsTrendResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(resp.DataPoints) != 1 {
		t.Fatalf("expected 1 data point, got %d", len(resp.DataPoints))
	}
	if resp.DataPoints[0].New != 5 {
		t.Errorf("expected new 5, got %d", resp.DataPoints[0].New)
	}
	if resp.DataPoints[0].Resolved != 3 {
		t.Errorf("expected resolved 3, got %d", resp.DataPoints[0].Resolved)
	}
}

func TestHandleStatsTrend_InvalidProjectID(t *testing.T) {
	srv := newTestServer(&mockStore{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats/trend?project_id=abc", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleStatsTrend_DefaultParams(t *testing.T) {
	ms := &mockStore{
		getStatsTrendFunc: func(ctx context.Context, query store.StatsTrendQuery) (*store.StatsTrendResponse, error) {
			if query.Range != "30d" {
				t.Errorf("expected default range 30d, got %q", query.Range)
			}
			if query.GroupBy != "day" {
				t.Errorf("expected default group_by day, got %q", query.GroupBy)
			}
			if query.ProjectID != 0 {
				t.Errorf("expected project_id 0, got %d", query.ProjectID)
			}
			return &store.StatsTrendResponse{
				Range:      "30d",
				GroupBy:    "day",
				DataPoints: []store.StatsTrendDataPoint{},
			}, nil
		},
	}
	srv := newTestServer(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats/trend", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}
}
