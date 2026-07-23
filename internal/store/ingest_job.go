package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// IngestJob represents a recorded ingest job execution.
type IngestJob struct {
	ID           int64
	CommandArgs  map[string]interface{}
	Source       string
	StartedAt    time.Time
	FinishedAt   *time.Time
	Status       string // running, success, failed, partial
	TotalCount   *int
	SuccessCount *int
	FailureCount *int
	ErrorMessage *string
	ErrorStack   *string
	Failures     []IngestFailure // populated on GetIngestJob
}

// IngestFailure represents a single failed item during an ingest job.
type IngestFailure struct {
	ID           int64
	JobID        int64
	VulnID       string
	ErrorType    string // parse_error, store_error, fetch_error
	ErrorMessage *string
	ErrorStack   *string
	FailedAt     time.Time
}

// CreateIngestJob records a new ingest job and returns the auto-generated ID.
// After insertion, it prunes old jobs to keep only the 100 most recent.
func (s *PostgresStore) CreateIngestJob(ctx context.Context, job *IngestJob) (int64, error) {
	argsJSON, err := json.Marshal(job.CommandArgs)
	if err != nil {
		return 0, fmt.Errorf("marshal command_args: %w", err)
	}

	var id int64
	err = s.db.QueryRowContext(ctx, `
		INSERT INTO ingest_jobs (command_args, source, started_at, status)
		VALUES ($1, $2, $3, $4)
		RETURNING id`,
		argsJSON,
		job.Source,
		job.StartedAt,
		job.Status,
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("insert ingest_job: %w", err)
	}

	// Prune old jobs asynchronously (best-effort)
	if err := s.pruneIngestJobs(ctx); err != nil {
		// Log but don't fail the creation
		_ = err
	}

	return id, nil
}

// UpdateIngestJob updates an existing ingest job (status, counts, finish time).
func (s *PostgresStore) UpdateIngestJob(ctx context.Context, job *IngestJob) error {
	var finishedAt sql.NullTime
	if job.FinishedAt != nil {
		finishedAt = sql.NullTime{Time: *job.FinishedAt, Valid: true}
	}

	var totalCount sql.NullInt32
	if job.TotalCount != nil {
		totalCount = sql.NullInt32{Int32: int32(*job.TotalCount), Valid: true}
	}

	var successCount sql.NullInt32
	if job.SuccessCount != nil {
		successCount = sql.NullInt32{Int32: int32(*job.SuccessCount), Valid: true}
	}

	var failureCount sql.NullInt32
	if job.FailureCount != nil {
		failureCount = sql.NullInt32{Int32: int32(*job.FailureCount), Valid: true}
	}

	var errorMessage sql.NullString
	if job.ErrorMessage != nil {
		errorMessage = sql.NullString{String: *job.ErrorMessage, Valid: true}
	}

	var errorStack sql.NullString
	if job.ErrorStack != nil {
		errorStack = sql.NullString{String: *job.ErrorStack, Valid: true}
	}

	_, err := s.db.ExecContext(ctx, `
		UPDATE ingest_jobs
		SET finished_at = $2,
		    status = $3,
		    total_count = $4,
		    success_count = $5,
		    failure_count = $6,
		    error_message = $7,
		    error_stack = $8
		WHERE id = $1`,
		job.ID,
		finishedAt,
		job.Status,
		totalCount,
		successCount,
		failureCount,
		errorMessage,
		errorStack,
	)
	if err != nil {
		return fmt.Errorf("update ingest_job %d: %w", job.ID, err)
	}
	return nil
}

// RecordIngestFailure records a single failure for an ingest job.
func (s *PostgresStore) RecordIngestFailure(ctx context.Context, failure *IngestFailure) error {
	var errorMessage sql.NullString
	if failure.ErrorMessage != nil {
		errorMessage = sql.NullString{String: *failure.ErrorMessage, Valid: true}
	}

	var errorStack sql.NullString
	if failure.ErrorStack != nil {
		errorStack = sql.NullString{String: *failure.ErrorStack, Valid: true}
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO ingest_failures (job_id, vuln_id, error_type, error_message, error_stack, failed_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		failure.JobID,
		failure.VulnID,
		failure.ErrorType,
		errorMessage,
		errorStack,
		failure.FailedAt,
	)
	if err != nil {
		return fmt.Errorf("insert ingest_failure: %w", err)
	}
	return nil
}

// RecordIngestFailures records multiple failures for an ingest job in a batch.
func (s *PostgresStore) RecordIngestFailures(ctx context.Context, failures []IngestFailure) error {
	if len(failures) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO ingest_failures (job_id, vuln_id, error_type, error_message, error_stack, failed_at)
		VALUES ($1, $2, $3, $4, $5, $6)`)
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	for _, f := range failures {
		var errorMessage sql.NullString
		if f.ErrorMessage != nil {
			errorMessage = sql.NullString{String: *f.ErrorMessage, Valid: true}
		}

		var errorStack sql.NullString
		if f.ErrorStack != nil {
			errorStack = sql.NullString{String: *f.ErrorStack, Valid: true}
		}

		_, err := stmt.ExecContext(ctx, f.JobID, f.VulnID, f.ErrorType, errorMessage, errorStack, f.FailedAt)
		if err != nil {
			return fmt.Errorf("insert ingest_failure for %s: %w", f.VulnID, err)
		}
	}

	return tx.Commit()
}

// ListIngestJobs returns recent ingest jobs ordered by start time (newest first).
// If limit <= 0, defaults to 20.
func (s *PostgresStore) ListIngestJobs(ctx context.Context, limit int) ([]IngestJob, error) {
	if limit <= 0 {
		limit = 20
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, command_args, source, started_at, finished_at,
		       status, total_count, success_count, failure_count,
		       error_message, error_stack
		FROM ingest_jobs
		ORDER BY started_at DESC
		LIMIT $1`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query ingest_jobs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var jobs []IngestJob
	for rows.Next() {
		var job IngestJob
		var argsJSON []byte
		var finishedAt sql.NullTime
		var totalCount sql.NullInt32
		var successCount sql.NullInt32
		var failureCount sql.NullInt32
		var errorMessage sql.NullString
		var errorStack sql.NullString

		if err := rows.Scan(
			&job.ID,
			&argsJSON,
			&job.Source,
			&job.StartedAt,
			&finishedAt,
			&job.Status,
			&totalCount,
			&successCount,
			&failureCount,
			&errorMessage,
			&errorStack,
		); err != nil {
			return nil, fmt.Errorf("scan ingest_job: %w", err)
		}

		if argsJSON != nil {
			if err := json.Unmarshal(argsJSON, &job.CommandArgs); err != nil {
				return nil, fmt.Errorf("unmarshal command_args for job %d: %w", job.ID, err)
			}
		}
		if finishedAt.Valid {
			job.FinishedAt = &finishedAt.Time
		}
		if totalCount.Valid {
			v := int(totalCount.Int32)
			job.TotalCount = &v
		}
		if successCount.Valid {
			v := int(successCount.Int32)
			job.SuccessCount = &v
		}
		if failureCount.Valid {
			v := int(failureCount.Int32)
			job.FailureCount = &v
		}
		if errorMessage.Valid {
			job.ErrorMessage = &errorMessage.String
		}
		if errorStack.Valid {
			job.ErrorStack = &errorStack.String
		}

		jobs = append(jobs, job)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate ingest_jobs: %w", err)
	}

	return jobs, nil
}

// GetIngestJob retrieves an ingest job by ID, including its failures.
// Returns nil, nil if not found.
func (s *PostgresStore) GetIngestJob(ctx context.Context, id int64) (*IngestJob, error) {
	var job IngestJob
	var argsJSON []byte
	var finishedAt sql.NullTime
	var totalCount sql.NullInt32
	var successCount sql.NullInt32
	var failureCount sql.NullInt32
	var errorMessage sql.NullString
	var errorStack sql.NullString

	err := s.db.QueryRowContext(ctx, `
		SELECT id, command_args, source, started_at, finished_at,
		       status, total_count, success_count, failure_count,
		       error_message, error_stack
		FROM ingest_jobs
		WHERE id = $1`,
		id,
	).Scan(
		&job.ID,
		&argsJSON,
		&job.Source,
		&job.StartedAt,
		&finishedAt,
		&job.Status,
		&totalCount,
		&successCount,
		&failureCount,
		&errorMessage,
		&errorStack,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("query ingest_job %d: %w", id, err)
	}

	if argsJSON != nil {
		if err := json.Unmarshal(argsJSON, &job.CommandArgs); err != nil {
			return nil, fmt.Errorf("unmarshal command_args for job %d: %w", id, err)
		}
	}
	if finishedAt.Valid {
		job.FinishedAt = &finishedAt.Time
	}
	if totalCount.Valid {
		v := int(totalCount.Int32)
		job.TotalCount = &v
	}
	if successCount.Valid {
		v := int(successCount.Int32)
		job.SuccessCount = &v
	}
	if failureCount.Valid {
		v := int(failureCount.Int32)
		job.FailureCount = &v
	}
	if errorMessage.Valid {
		job.ErrorMessage = &errorMessage.String
	}
	if errorStack.Valid {
		job.ErrorStack = &errorStack.String
	}

	// Fetch associated failures
	failures, err := s.getIngestFailures(ctx, id)
	if err != nil {
		return nil, err
	}
	job.Failures = failures

	return &job, nil
}

// getIngestFailures retrieves all failures for a given job ID.
func (s *PostgresStore) getIngestFailures(ctx context.Context, jobID int64) ([]IngestFailure, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, job_id, vuln_id, error_type, error_message, error_stack, failed_at
		FROM ingest_failures
		WHERE job_id = $1
		ORDER BY failed_at ASC`,
		jobID,
	)
	if err != nil {
		return nil, fmt.Errorf("query ingest_failures for job %d: %w", jobID, err)
	}
	defer func() { _ = rows.Close() }()

	var failures []IngestFailure
	for rows.Next() {
		var f IngestFailure
		var errorMessage sql.NullString
		var errorStack sql.NullString

		if err := rows.Scan(
			&f.ID,
			&f.JobID,
			&f.VulnID,
			&f.ErrorType,
			&errorMessage,
			&errorStack,
			&f.FailedAt,
		); err != nil {
			return nil, fmt.Errorf("scan ingest_failure: %w", err)
		}

		if errorMessage.Valid {
			f.ErrorMessage = &errorMessage.String
		}
		if errorStack.Valid {
			f.ErrorStack = &errorStack.String
		}

		failures = append(failures, f)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate ingest_failures: %w", err)
	}

	return failures, nil
}

// pruneIngestJobs removes old ingest jobs, keeping only the 100 most recent.
// Associated failures are removed via CASCADE.
func (s *PostgresStore) pruneIngestJobs(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM ingest_jobs
		WHERE id NOT IN (
			SELECT id FROM ingest_jobs
			ORDER BY started_at DESC
			LIMIT 100
		)`)
	if err != nil {
		return fmt.Errorf("prune ingest_jobs: %w", err)
	}
	return nil
}
