package ingest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/kato83/mayu/internal/store"
)

// mockJobStore implements the subset of store.Store used by JobRecorder.
type mockJobStore struct {
	store.Store // embed interface for unimplemented methods

	mu             sync.Mutex
	createdJobs    []*store.IngestJob
	updatedJobs    []*store.IngestJob
	recordedSingle []*store.IngestFailure
	recordedBatch  []store.IngestFailure
	createJobErr   error
	updateJobErr   error
	recordFailErr  error
	recordBatchErr error
	nextJobID      int64
}

func (m *mockJobStore) CreateIngestJob(_ context.Context, job *store.IngestJob) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.createJobErr != nil {
		return 0, m.createJobErr
	}
	m.createdJobs = append(m.createdJobs, job)
	m.nextJobID++
	return m.nextJobID, nil
}

func (m *mockJobStore) UpdateIngestJob(_ context.Context, job *store.IngestJob) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.updateJobErr != nil {
		return m.updateJobErr
	}
	m.updatedJobs = append(m.updatedJobs, job)
	return nil
}

func (m *mockJobStore) RecordIngestFailure(_ context.Context, failure *store.IngestFailure) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.recordFailErr != nil {
		return m.recordFailErr
	}
	m.recordedSingle = append(m.recordedSingle, failure)
	return nil
}

func (m *mockJobStore) RecordIngestFailures(_ context.Context, failures []store.IngestFailure) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.recordBatchErr != nil {
		return m.recordBatchErr
	}
	m.recordedBatch = append(m.recordedBatch, failures...)
	return nil
}

func TestNewJobRecorder(t *testing.T) {
	ms := &mockJobStore{}
	ctx := context.Background()

	jr, err := NewJobRecorder(ctx, ms, "osv", map[string]interface{}{"ecosystem": "Go"})
	if err != nil {
		t.Fatalf("NewJobRecorder failed: %v", err)
	}
	if jr == nil {
		t.Fatal("expected non-nil recorder")
	}
	if jr.JobID() != 1 {
		t.Errorf("expected JobID 1, got %d", jr.JobID())
	}

	ms.mu.Lock()
	defer ms.mu.Unlock()
	if len(ms.createdJobs) != 1 {
		t.Fatalf("expected 1 created job, got %d", len(ms.createdJobs))
	}
	job := ms.createdJobs[0]
	if job.Source != "osv" {
		t.Errorf("expected source osv, got %q", job.Source)
	}
	if job.Status != "running" {
		t.Errorf("expected status running, got %q", job.Status)
	}
	if job.CommandArgs["ecosystem"] != "Go" {
		t.Errorf("expected ecosystem Go in args, got %v", job.CommandArgs)
	}
}

func TestNewJobRecorder_CreateFails(t *testing.T) {
	ms := &mockJobStore{createJobErr: errors.New("db error")}
	ctx := context.Background()

	jr, err := NewJobRecorder(ctx, ms, "osv", nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if jr != nil {
		t.Error("expected nil recorder on error")
	}
}

func TestJobRecorder_RecordFailure(t *testing.T) {
	ms := &mockJobStore{}
	ctx := context.Background()

	jr, _ := NewJobRecorder(ctx, ms, "osv", nil)

	jr.RecordFailure("CVE-2024-1234", "parse_error", errors.New("invalid JSON"))
	jr.RecordFailure("CVE-2024-5678", "fetch_error", errors.New("timeout"))

	jr.mu.Lock()
	if len(jr.failures) != 2 {
		t.Fatalf("expected 2 buffered failures, got %d", len(jr.failures))
	}
	f1 := jr.failures[0]
	f2 := jr.failures[1]
	jr.mu.Unlock()

	if f1.VulnID != "CVE-2024-1234" {
		t.Errorf("expected vuln_id CVE-2024-1234, got %q", f1.VulnID)
	}
	if f1.ErrorType != "parse_error" {
		t.Errorf("expected error_type parse_error, got %q", f1.ErrorType)
	}
	if *f1.ErrorMessage != "invalid JSON" {
		t.Errorf("expected error_message 'invalid JSON', got %q", *f1.ErrorMessage)
	}
	if f1.ErrorStack == nil || *f1.ErrorStack == "" {
		t.Error("expected non-empty error_stack")
	}

	if f2.VulnID != "CVE-2024-5678" {
		t.Errorf("expected vuln_id CVE-2024-5678, got %q", f2.VulnID)
	}
	if f2.ErrorType != "fetch_error" {
		t.Errorf("expected error_type fetch_error, got %q", f2.ErrorType)
	}
}

func TestJobRecorder_RecordFailure_NilError(t *testing.T) {
	ms := &mockJobStore{}
	ctx := context.Background()

	jr, _ := NewJobRecorder(ctx, ms, "osv", nil)
	jr.RecordFailure("CVE-2024-0001", "store_error", nil)

	jr.mu.Lock()
	if len(jr.failures) != 1 {
		t.Fatalf("expected 1 failure, got %d", len(jr.failures))
	}
	if *jr.failures[0].ErrorMessage != "" {
		t.Errorf("expected empty error message for nil error, got %q", *jr.failures[0].ErrorMessage)
	}
	jr.mu.Unlock()
}

func TestJobRecorder_Finish_Success(t *testing.T) {
	ms := &mockJobStore{}
	ctx := context.Background()

	jr, _ := NewJobRecorder(ctx, ms, "osv", map[string]interface{}{"ecosystem": "Go"})

	jr.Finish(ctx, "success", 100, 100, 0, nil)

	ms.mu.Lock()
	defer ms.mu.Unlock()

	if len(ms.updatedJobs) != 1 {
		t.Fatalf("expected 1 updated job, got %d", len(ms.updatedJobs))
	}
	updated := ms.updatedJobs[0]
	if updated.Status != "success" {
		t.Errorf("expected status success, got %q", updated.Status)
	}
	if *updated.TotalCount != 100 {
		t.Errorf("expected total_count 100, got %d", *updated.TotalCount)
	}
	if *updated.SuccessCount != 100 {
		t.Errorf("expected success_count 100, got %d", *updated.SuccessCount)
	}
	if *updated.FailureCount != 0 {
		t.Errorf("expected failure_count 0, got %d", *updated.FailureCount)
	}
	if updated.ErrorMessage != nil {
		t.Errorf("expected nil error_message, got %v", updated.ErrorMessage)
	}
	if updated.FinishedAt == nil {
		t.Error("expected finished_at to be set")
	}
}

func TestJobRecorder_Finish_WithError(t *testing.T) {
	ms := &mockJobStore{}
	ctx := context.Background()

	jr, _ := NewJobRecorder(ctx, ms, "nvd", nil)

	jr.Finish(ctx, "failed", 0, 0, 0, errors.New("connection refused"))

	ms.mu.Lock()
	defer ms.mu.Unlock()

	if len(ms.updatedJobs) != 1 {
		t.Fatalf("expected 1 updated job, got %d", len(ms.updatedJobs))
	}
	updated := ms.updatedJobs[0]
	if updated.Status != "failed" {
		t.Errorf("expected status failed, got %q", updated.Status)
	}
	if updated.ErrorMessage == nil || *updated.ErrorMessage != "connection refused" {
		t.Errorf("expected error_message 'connection refused', got %v", updated.ErrorMessage)
	}
	if updated.ErrorStack == nil || *updated.ErrorStack == "" {
		t.Error("expected non-empty error_stack")
	}
}

func TestJobRecorder_Finish_FlushesFailures(t *testing.T) {
	ms := &mockJobStore{}
	ctx := context.Background()

	jr, _ := NewJobRecorder(ctx, ms, "osv", nil)

	// Record failures before Finish
	jr.RecordFailure("CVE-2024-0001", "parse_error", errors.New("err1"))
	jr.RecordFailure("CVE-2024-0002", "fetch_error", errors.New("err2"))

	jr.Finish(ctx, "partial", 10, 8, 2, nil)

	ms.mu.Lock()
	defer ms.mu.Unlock()

	// Failures should be flushed via RecordIngestFailures
	if len(ms.recordedBatch) != 2 {
		t.Fatalf("expected 2 batch-recorded failures, got %d", len(ms.recordedBatch))
	}
	if ms.recordedBatch[0].VulnID != "CVE-2024-0001" {
		t.Errorf("expected first failure CVE-2024-0001, got %q", ms.recordedBatch[0].VulnID)
	}
	if ms.recordedBatch[1].VulnID != "CVE-2024-0002" {
		t.Errorf("expected second failure CVE-2024-0002, got %q", ms.recordedBatch[1].VulnID)
	}

	// Internal buffer should be cleared
	jr.mu.Lock()
	if len(jr.failures) != 0 {
		t.Errorf("expected failures buffer to be cleared, got %d", len(jr.failures))
	}
	jr.mu.Unlock()
}

func TestJobRecorder_Finish_NoFailures(t *testing.T) {
	ms := &mockJobStore{}
	ctx := context.Background()

	jr, _ := NewJobRecorder(ctx, ms, "epss", nil)
	jr.Finish(ctx, "success", 200000, 200000, 0, nil)

	ms.mu.Lock()
	defer ms.mu.Unlock()

	// Should not call RecordIngestFailures when there are no failures
	if len(ms.recordedBatch) != 0 {
		t.Errorf("expected 0 batch-recorded failures, got %d", len(ms.recordedBatch))
	}
}

func TestJobRecorder_ConcurrentRecordFailure(t *testing.T) {
	ms := &mockJobStore{}
	ctx := context.Background()

	jr, _ := NewJobRecorder(ctx, ms, "osv", nil)

	// Record failures concurrently
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			jr.RecordFailure(
				"CVE-2024-"+time.Now().Format("0000"),
				"parse_error",
				errors.New("err"),
			)
		}(i)
	}
	wg.Wait()

	jr.mu.Lock()
	count := len(jr.failures)
	jr.mu.Unlock()

	if count != 50 {
		t.Errorf("expected 50 failures from concurrent access, got %d", count)
	}
}

func TestCaptureStack(t *testing.T) {
	stack := captureStack(1) // skip captureStack itself

	if stack == "" {
		t.Fatal("expected non-empty stack trace")
	}
	// Should contain this test function
	if !containsString(stack, "TestCaptureStack") {
		t.Errorf("expected stack to contain TestCaptureStack, got:\n%s", stack)
	}
}

func TestIngester_StartJob_NilStore(t *testing.T) {
	ing := &Ingester{} // no jobStore set

	jr := ing.startJob(context.Background(), "osv", nil)
	if jr != nil {
		t.Error("expected nil recorder when jobStore is nil")
	}
}

func TestIngester_StartJob_WithStore(t *testing.T) {
	ms := &mockJobStore{}
	ing := &Ingester{jobStore: ms}

	jr := ing.startJob(context.Background(), "osv", map[string]interface{}{"eco": "Go"})
	if jr == nil {
		t.Fatal("expected non-nil recorder")
	}
	if jr.JobID() != 1 {
		t.Errorf("expected job ID 1, got %d", jr.JobID())
	}
}

func containsString(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && contains(s, substr)
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
