package ingest

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/kato83/mayu/internal/store"
)

// JobRecorder manages the lifecycle of an ingest job record.
type JobRecorder struct {
	store     store.Store
	jobID     int64
	startedAt time.Time
	mu        sync.Mutex
	failures  []store.IngestFailure
}

// NewJobRecorder creates a new job record in the database and returns a recorder.
func NewJobRecorder(ctx context.Context, s store.Store, source string, args map[string]interface{}) (*JobRecorder, error) {
	now := time.Now().UTC()
	job := &store.IngestJob{
		CommandArgs: args,
		Source:      source,
		StartedAt:   now,
		Status:      "running",
	}
	id, err := s.CreateIngestJob(ctx, job)
	if err != nil {
		return nil, fmt.Errorf("create ingest job: %w", err)
	}
	return &JobRecorder{
		store:     s,
		jobID:     id,
		startedAt: now,
	}, nil
}

// RecordFailure records a single failure with stack trace.
func (jr *JobRecorder) RecordFailure(vulnID, errorType string, err error) {
	stack := captureStack(3) // skip captureStack, RecordFailure, caller
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}
	failure := store.IngestFailure{
		JobID:        jr.jobID,
		VulnID:       vulnID,
		ErrorType:    errorType,
		ErrorMessage: &errMsg,
		ErrorStack:   &stack,
		FailedAt:     time.Now().UTC(),
	}
	jr.mu.Lock()
	jr.failures = append(jr.failures, failure)
	jr.mu.Unlock()
}

// Finish completes the job record with final status and counts.
func (jr *JobRecorder) Finish(ctx context.Context, status string, total, success, failures int, jobErr error) {
	now := time.Now().UTC()
	job := &store.IngestJob{
		ID:           jr.jobID,
		FinishedAt:   &now,
		Status:       status,
		TotalCount:   &total,
		SuccessCount: &success,
		FailureCount: &failures,
	}
	if jobErr != nil {
		msg := jobErr.Error()
		stack := captureStack(2)
		job.ErrorMessage = &msg
		job.ErrorStack = &stack
	}
	// Best-effort update — don't fail the import if logging fails
	_ = jr.store.UpdateIngestJob(ctx, job)

	// Flush accumulated failures
	jr.mu.Lock()
	toFlush := jr.failures
	jr.failures = nil
	jr.mu.Unlock()

	if len(toFlush) > 0 {
		_ = jr.store.RecordIngestFailures(ctx, toFlush)
	}
}

// JobID returns the ID of the recorded job.
func (jr *JobRecorder) JobID() int64 {
	return jr.jobID
}

// captureStack captures a stack trace, skipping the specified number of frames.
func captureStack(skip int) string {
	const maxFrames = 20
	pcs := make([]uintptr, maxFrames)
	n := runtime.Callers(skip, pcs)
	if n == 0 {
		return ""
	}
	frames := runtime.CallersFrames(pcs[:n])
	var sb strings.Builder
	for {
		frame, more := frames.Next()
		fmt.Fprintf(&sb, "%s\n\t%s:%d\n", frame.Function, frame.File, frame.Line)
		if !more {
			break
		}
	}
	return sb.String()
}
