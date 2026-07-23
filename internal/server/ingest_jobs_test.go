package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kato83/mayu/internal/store"
)

func TestListIngestJobs_Success(t *testing.T) {
	now := time.Now().Truncate(time.Second).UTC()
	finished := now.Add(1 * time.Minute)
	total := 1000
	success := 999
	failure := 1

	ms := &mockStore{
		listIngestJobsFunc: func(ctx context.Context, limit int) ([]store.IngestJob, error) {
			if limit != 20 {
				t.Errorf("expected default limit 20, got %d", limit)
			}
			return []store.IngestJob{
				{
					ID:           1,
					Source:       "osv",
					CommandArgs:  map[string]interface{}{"ecosystem": "Go"},
					StartedAt:    now,
					FinishedAt:   &finished,
					Status:       "success",
					TotalCount:   &total,
					SuccessCount: &success,
					FailureCount: &failure,
				},
			}, nil
		},
	}

	srv := newTestServer(ms)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ingest/jobs", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp ingestJobsListResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(resp.Jobs) != 1 {
		t.Fatalf("expected 1 job, got %d", len(resp.Jobs))
	}

	job := resp.Jobs[0]
	if job.ID != 1 {
		t.Errorf("expected ID 1, got %d", job.ID)
	}
	if job.Source != "osv" {
		t.Errorf("expected source osv, got %q", job.Source)
	}
	if job.Status != "success" {
		t.Errorf("expected status success, got %q", job.Status)
	}
	if *job.TotalCount != 1000 {
		t.Errorf("expected total_count 1000, got %d", *job.TotalCount)
	}
}

func TestListIngestJobs_CustomLimit(t *testing.T) {
	ms := &mockStore{
		listIngestJobsFunc: func(ctx context.Context, limit int) ([]store.IngestJob, error) {
			if limit != 5 {
				t.Errorf("expected limit 5, got %d", limit)
			}
			return []store.IngestJob{}, nil
		},
	}

	srv := newTestServer(ms)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ingest/jobs?limit=5", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestListIngestJobs_LimitCappedAt100(t *testing.T) {
	ms := &mockStore{
		listIngestJobsFunc: func(ctx context.Context, limit int) ([]store.IngestJob, error) {
			if limit != 100 {
				t.Errorf("expected limit capped at 100, got %d", limit)
			}
			return []store.IngestJob{}, nil
		},
	}

	srv := newTestServer(ms)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ingest/jobs?limit=500", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestListIngestJobs_InvalidLimit(t *testing.T) {
	srv := newTestServer(&mockStore{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ingest/jobs?limit=abc", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestListIngestJobs_NegativeLimit(t *testing.T) {
	srv := newTestServer(&mockStore{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ingest/jobs?limit=-1", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestListIngestJobs_StoreError(t *testing.T) {
	ms := &mockStore{
		listIngestJobsFunc: func(ctx context.Context, limit int) ([]store.IngestJob, error) {
			return nil, errors.New("db timeout")
		},
	}

	srv := newTestServer(ms)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ingest/jobs", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestListIngestJobs_EmptyList(t *testing.T) {
	ms := &mockStore{
		listIngestJobsFunc: func(ctx context.Context, limit int) ([]store.IngestJob, error) {
			return []store.IngestJob{}, nil
		},
	}

	srv := newTestServer(ms)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ingest/jobs", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var resp ingestJobsListResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(resp.Jobs) != 0 {
		t.Errorf("expected empty jobs list, got %d", len(resp.Jobs))
	}
}

func TestGetIngestJob_Success(t *testing.T) {
	now := time.Now().Truncate(time.Second).UTC()
	finished := now.Add(1 * time.Minute)
	total := 1000
	success := 999
	failure := 1
	errMsg := "invalid JSON"

	ms := &mockStore{
		getIngestJobFunc: func(ctx context.Context, id int64) (*store.IngestJob, error) {
			if id != 42 {
				t.Errorf("expected id 42, got %d", id)
			}
			return &store.IngestJob{
				ID:           42,
				Source:       "osv",
				CommandArgs:  map[string]interface{}{"ecosystem": "Go"},
				StartedAt:    now,
				FinishedAt:   &finished,
				Status:       "partial",
				TotalCount:   &total,
				SuccessCount: &success,
				FailureCount: &failure,
				Failures: []store.IngestFailure{
					{
						ID:           1,
						JobID:        42,
						VulnID:       "CVE-2024-1234",
						ErrorType:    "parse_error",
						ErrorMessage: &errMsg,
						FailedAt:     now.Add(30 * time.Second),
					},
				},
			}, nil
		},
	}

	srv := newTestServer(ms)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ingest/jobs/42", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp ingestJobDetailResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.ID != 42 {
		t.Errorf("expected ID 42, got %d", resp.ID)
	}
	if resp.Status != "partial" {
		t.Errorf("expected status partial, got %q", resp.Status)
	}
	if len(resp.Failures) != 1 {
		t.Fatalf("expected 1 failure, got %d", len(resp.Failures))
	}
	if resp.Failures[0].VulnID != "CVE-2024-1234" {
		t.Errorf("expected vuln_id CVE-2024-1234, got %q", resp.Failures[0].VulnID)
	}
	if resp.Failures[0].ErrorType != "parse_error" {
		t.Errorf("expected error_type parse_error, got %q", resp.Failures[0].ErrorType)
	}
	if *resp.Failures[0].ErrorMessage != "invalid JSON" {
		t.Errorf("expected error_message 'invalid JSON', got %q", *resp.Failures[0].ErrorMessage)
	}
}

func TestGetIngestJob_NotFound(t *testing.T) {
	ms := &mockStore{
		getIngestJobFunc: func(ctx context.Context, id int64) (*store.IngestJob, error) {
			return nil, nil
		},
	}

	srv := newTestServer(ms)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ingest/jobs/999", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["error"] != "ingest job not found" {
		t.Errorf("expected error 'ingest job not found', got %q", resp["error"])
	}
}

func TestGetIngestJob_InvalidID(t *testing.T) {
	srv := newTestServer(&mockStore{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ingest/jobs/abc", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetIngestJob_StoreError(t *testing.T) {
	ms := &mockStore{
		getIngestJobFunc: func(ctx context.Context, id int64) (*store.IngestJob, error) {
			return nil, errors.New("db connection lost")
		},
	}

	srv := newTestServer(ms)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ingest/jobs/1", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestGetIngestJob_EmptyFailures(t *testing.T) {
	now := time.Now().Truncate(time.Second).UTC()
	total := 100
	success := 100
	failure := 0

	ms := &mockStore{
		getIngestJobFunc: func(ctx context.Context, id int64) (*store.IngestJob, error) {
			return &store.IngestJob{
				ID:           1,
				Source:       "epss",
				CommandArgs:  map[string]interface{}{},
				StartedAt:    now,
				Status:       "success",
				TotalCount:   &total,
				SuccessCount: &success,
				FailureCount: &failure,
				Failures:     []store.IngestFailure{},
			}, nil
		},
	}

	srv := newTestServer(ms)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ingest/jobs/1", nil)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp ingestJobDetailResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(resp.Failures) != 0 {
		t.Errorf("expected empty failures, got %d", len(resp.Failures))
	}
}
