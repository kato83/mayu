//go:build integration

package store

import (
	"context"
	"testing"
	"time"
)

func TestCreateAndGetIngestJob(t *testing.T) {
	s := setupTestStore(t)
	ctx := context.Background()

	job := &IngestJob{
		CommandArgs: map[string]interface{}{"ecosystem": "Go", "update": true},
		Source:      "osv",
		StartedAt:   time.Now().UTC().Truncate(time.Microsecond),
		Status:      "running",
	}

	id, err := s.CreateIngestJob(ctx, job)
	if err != nil {
		t.Fatalf("CreateIngestJob failed: %v", err)
	}
	if id == 0 {
		t.Fatal("expected non-zero ID")
	}

	got, err := s.GetIngestJob(ctx, id)
	if err != nil {
		t.Fatalf("GetIngestJob failed: %v", err)
	}
	if got == nil {
		t.Fatal("GetIngestJob returned nil")
	}

	if got.ID != id {
		t.Errorf("expected ID %d, got %d", id, got.ID)
	}
	if got.Source != "osv" {
		t.Errorf("expected source osv, got %q", got.Source)
	}
	if got.Status != "running" {
		t.Errorf("expected status running, got %q", got.Status)
	}
	if got.CommandArgs["ecosystem"] != "Go" {
		t.Errorf("expected ecosystem Go, got %v", got.CommandArgs["ecosystem"])
	}
	if got.CommandArgs["update"] != true {
		t.Errorf("expected update true, got %v", got.CommandArgs["update"])
	}
	if got.FinishedAt != nil {
		t.Error("expected finished_at to be nil")
	}
}

func TestUpdateIngestJob(t *testing.T) {
	s := setupTestStore(t)
	ctx := context.Background()

	job := &IngestJob{
		CommandArgs: map[string]interface{}{"ecosystem": "Go"},
		Source:      "osv",
		StartedAt:   time.Now().UTC().Truncate(time.Microsecond),
		Status:      "running",
	}

	id, err := s.CreateIngestJob(ctx, job)
	if err != nil {
		t.Fatalf("CreateIngestJob failed: %v", err)
	}

	// Update to success
	now := time.Now().UTC().Truncate(time.Microsecond)
	total := 100
	success := 98
	failures := 2
	updateJob := &IngestJob{
		ID:           id,
		FinishedAt:   &now,
		Status:       "partial",
		TotalCount:   &total,
		SuccessCount: &success,
		FailureCount: &failures,
	}

	if err := s.UpdateIngestJob(ctx, updateJob); err != nil {
		t.Fatalf("UpdateIngestJob failed: %v", err)
	}

	got, err := s.GetIngestJob(ctx, id)
	if err != nil {
		t.Fatalf("GetIngestJob failed: %v", err)
	}

	if got.Status != "partial" {
		t.Errorf("expected status partial, got %q", got.Status)
	}
	if got.FinishedAt == nil {
		t.Fatal("expected finished_at to be set")
	}
	if *got.TotalCount != 100 {
		t.Errorf("expected total_count 100, got %d", *got.TotalCount)
	}
	if *got.SuccessCount != 98 {
		t.Errorf("expected success_count 98, got %d", *got.SuccessCount)
	}
	if *got.FailureCount != 2 {
		t.Errorf("expected failure_count 2, got %d", *got.FailureCount)
	}
}

func TestUpdateIngestJob_WithError(t *testing.T) {
	s := setupTestStore(t)
	ctx := context.Background()

	job := &IngestJob{
		CommandArgs: map[string]interface{}{},
		Source:      "nvd",
		StartedAt:   time.Now().UTC().Truncate(time.Microsecond),
		Status:      "running",
	}

	id, err := s.CreateIngestJob(ctx, job)
	if err != nil {
		t.Fatalf("CreateIngestJob failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	total := 0
	success := 0
	failures := 0
	errMsg := "connection refused"
	errStack := "main.go:42\n\tingest.go:100"
	updateJob := &IngestJob{
		ID:           id,
		FinishedAt:   &now,
		Status:       "failed",
		TotalCount:   &total,
		SuccessCount: &success,
		FailureCount: &failures,
		ErrorMessage: &errMsg,
		ErrorStack:   &errStack,
	}

	if err := s.UpdateIngestJob(ctx, updateJob); err != nil {
		t.Fatalf("UpdateIngestJob failed: %v", err)
	}

	got, err := s.GetIngestJob(ctx, id)
	if err != nil {
		t.Fatalf("GetIngestJob failed: %v", err)
	}

	if got.Status != "failed" {
		t.Errorf("expected status failed, got %q", got.Status)
	}
	if got.ErrorMessage == nil || *got.ErrorMessage != "connection refused" {
		t.Errorf("expected error_message 'connection refused', got %v", got.ErrorMessage)
	}
	if got.ErrorStack == nil || *got.ErrorStack != errStack {
		t.Errorf("expected error_stack set, got %v", got.ErrorStack)
	}
}

func TestRecordIngestFailure(t *testing.T) {
	s := setupTestStore(t)
	ctx := context.Background()

	job := &IngestJob{
		CommandArgs: map[string]interface{}{"ecosystem": "Go"},
		Source:      "osv",
		StartedAt:   time.Now().UTC().Truncate(time.Microsecond),
		Status:      "running",
	}

	id, err := s.CreateIngestJob(ctx, job)
	if err != nil {
		t.Fatalf("CreateIngestJob failed: %v", err)
	}

	errMsg := "unexpected EOF"
	errStack := "parser.go:55"
	failure := &IngestFailure{
		JobID:        id,
		VulnID:       "CVE-2024-1234",
		ErrorType:    "parse_error",
		ErrorMessage: &errMsg,
		ErrorStack:   &errStack,
		FailedAt:     time.Now().UTC().Truncate(time.Microsecond),
	}

	if err := s.RecordIngestFailure(ctx, failure); err != nil {
		t.Fatalf("RecordIngestFailure failed: %v", err)
	}

	got, err := s.GetIngestJob(ctx, id)
	if err != nil {
		t.Fatalf("GetIngestJob failed: %v", err)
	}

	if len(got.Failures) != 1 {
		t.Fatalf("expected 1 failure, got %d", len(got.Failures))
	}

	f := got.Failures[0]
	if f.VulnID != "CVE-2024-1234" {
		t.Errorf("expected vuln_id CVE-2024-1234, got %q", f.VulnID)
	}
	if f.ErrorType != "parse_error" {
		t.Errorf("expected error_type parse_error, got %q", f.ErrorType)
	}
	if f.ErrorMessage == nil || *f.ErrorMessage != "unexpected EOF" {
		t.Errorf("expected error_message 'unexpected EOF', got %v", f.ErrorMessage)
	}
	if f.ErrorStack == nil || *f.ErrorStack != "parser.go:55" {
		t.Errorf("expected error_stack, got %v", f.ErrorStack)
	}
}

func TestRecordIngestFailures_Batch(t *testing.T) {
	s := setupTestStore(t)
	ctx := context.Background()

	job := &IngestJob{
		CommandArgs: map[string]interface{}{},
		Source:      "osv",
		StartedAt:   time.Now().UTC().Truncate(time.Microsecond),
		Status:      "running",
	}

	id, err := s.CreateIngestJob(ctx, job)
	if err != nil {
		t.Fatalf("CreateIngestJob failed: %v", err)
	}

	msg1 := "invalid JSON"
	msg2 := "db timeout"
	failures := []IngestFailure{
		{
			JobID:        id,
			VulnID:       "CVE-2024-0001",
			ErrorType:    "parse_error",
			ErrorMessage: &msg1,
			FailedAt:     time.Now().UTC().Truncate(time.Microsecond),
		},
		{
			JobID:        id,
			VulnID:       "CVE-2024-0002",
			ErrorType:    "store_error",
			ErrorMessage: &msg2,
			FailedAt:     time.Now().UTC().Truncate(time.Microsecond),
		},
	}

	if err := s.RecordIngestFailures(ctx, failures); err != nil {
		t.Fatalf("RecordIngestFailures failed: %v", err)
	}

	got, err := s.GetIngestJob(ctx, id)
	if err != nil {
		t.Fatalf("GetIngestJob failed: %v", err)
	}

	if len(got.Failures) != 2 {
		t.Fatalf("expected 2 failures, got %d", len(got.Failures))
	}
}

func TestRecordIngestFailures_Empty(t *testing.T) {
	s := setupTestStore(t)
	ctx := context.Background()

	// Should be no-op
	if err := s.RecordIngestFailures(ctx, nil); err != nil {
		t.Fatalf("RecordIngestFailures with nil failed: %v", err)
	}
	if err := s.RecordIngestFailures(ctx, []IngestFailure{}); err != nil {
		t.Fatalf("RecordIngestFailures with empty slice failed: %v", err)
	}
}

func TestListIngestJobs(t *testing.T) {
	s := setupTestStore(t)
	ctx := context.Background()

	// Create 5 jobs with different start times
	for i := 0; i < 5; i++ {
		job := &IngestJob{
			CommandArgs: map[string]interface{}{"i": i},
			Source:      "osv",
			StartedAt:   time.Now().UTC().Add(time.Duration(i) * time.Second).Truncate(time.Microsecond),
			Status:      "success",
		}
		if _, err := s.CreateIngestJob(ctx, job); err != nil {
			t.Fatalf("CreateIngestJob #%d failed: %v", i, err)
		}
	}

	// List all
	jobs, err := s.ListIngestJobs(ctx, 10)
	if err != nil {
		t.Fatalf("ListIngestJobs failed: %v", err)
	}
	if len(jobs) != 5 {
		t.Fatalf("expected 5 jobs, got %d", len(jobs))
	}

	// Should be ordered by started_at DESC (newest first)
	for i := 1; i < len(jobs); i++ {
		if jobs[i].StartedAt.After(jobs[i-1].StartedAt) {
			t.Errorf("jobs not ordered by started_at DESC: job[%d]=%v > job[%d]=%v",
				i, jobs[i].StartedAt, i-1, jobs[i-1].StartedAt)
		}
	}

	// List with limit
	jobs, err = s.ListIngestJobs(ctx, 2)
	if err != nil {
		t.Fatalf("ListIngestJobs with limit failed: %v", err)
	}
	if len(jobs) != 2 {
		t.Fatalf("expected 2 jobs with limit=2, got %d", len(jobs))
	}
}

func TestListIngestJobs_DefaultLimit(t *testing.T) {
	s := setupTestStore(t)
	ctx := context.Background()

	// limit <= 0 should default to 20
	jobs, err := s.ListIngestJobs(ctx, 0)
	if err != nil {
		t.Fatalf("ListIngestJobs failed: %v", err)
	}
	// Should return empty since we haven't created any jobs
	if len(jobs) != 0 {
		t.Errorf("expected 0 jobs, got %d", len(jobs))
	}
}

func TestGetIngestJob_NotFound(t *testing.T) {
	s := setupTestStore(t)
	ctx := context.Background()

	got, err := s.GetIngestJob(ctx, 99999)
	if err != nil {
		t.Fatalf("GetIngestJob failed: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for non-existent job, got %+v", got)
	}
}

func TestPruneIngestJobs(t *testing.T) {
	s := setupTestStore(t)
	ctx := context.Background()

	// Create 105 jobs
	for i := 0; i < 105; i++ {
		job := &IngestJob{
			CommandArgs: map[string]interface{}{"i": i},
			Source:      "osv",
			StartedAt:   time.Now().UTC().Add(time.Duration(i) * time.Millisecond).Truncate(time.Microsecond),
			Status:      "success",
		}
		if _, err := s.CreateIngestJob(ctx, job); err != nil {
			t.Fatalf("CreateIngestJob #%d failed: %v", i, err)
		}
	}

	// After creating 105, pruning should have been triggered during creation.
	// Verify only 100 remain.
	jobs, err := s.ListIngestJobs(ctx, 200)
	if err != nil {
		t.Fatalf("ListIngestJobs failed: %v", err)
	}
	if len(jobs) != 100 {
		t.Errorf("expected 100 jobs after pruning, got %d", len(jobs))
	}
}

func TestGetIngestJob_FailuresCascadeOnDelete(t *testing.T) {
	s := setupTestStore(t)
	ctx := context.Background()

	// Create a job with failures
	job := &IngestJob{
		CommandArgs: map[string]interface{}{},
		Source:      "osv",
		StartedAt:   time.Now().UTC().Truncate(time.Microsecond),
		Status:      "running",
	}
	id, err := s.CreateIngestJob(ctx, job)
	if err != nil {
		t.Fatalf("CreateIngestJob failed: %v", err)
	}

	msg := "test error"
	failure := &IngestFailure{
		JobID:        id,
		VulnID:       "CVE-2024-9999",
		ErrorType:    "fetch_error",
		ErrorMessage: &msg,
		FailedAt:     time.Now().UTC().Truncate(time.Microsecond),
	}
	if err := s.RecordIngestFailure(ctx, failure); err != nil {
		t.Fatalf("RecordIngestFailure failed: %v", err)
	}

	// Manually delete the job
	_, err = s.db.ExecContext(ctx, "DELETE FROM ingest_jobs WHERE id = $1", id)
	if err != nil {
		t.Fatalf("DELETE job failed: %v", err)
	}

	// Failures should be cascade-deleted
	var count int
	err = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM ingest_failures WHERE job_id = $1", id).Scan(&count)
	if err != nil {
		t.Fatalf("count failures failed: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 failures after cascade delete, got %d", count)
	}
}
