package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// TranslationJob represents a background translation job execution.
type TranslationJob struct {
	ID               int64
	VulnerabilityID  string
	Locale           string
	StartedAt        time.Time
	FinishedAt       *time.Time
	Status           string // running, success, failed
	FieldsTranslated *int
	ErrorMessage     *string
}

// CreateTranslationJob records a new translation job and returns the auto-generated ID.
func (s *PostgresStore) CreateTranslationJob(ctx context.Context, job *TranslationJob) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO translation_jobs (vulnerability_id, locale, started_at, status)
		VALUES ($1, $2, $3, $4)
		RETURNING id`,
		job.VulnerabilityID,
		job.Locale,
		job.StartedAt,
		job.Status,
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("insert translation_job: %w", err)
	}
	return id, nil
}

// UpdateTranslationJob updates an existing translation job (status, fields_translated, finish time).
func (s *PostgresStore) UpdateTranslationJob(ctx context.Context, job *TranslationJob) error {
	var finishedAt sql.NullTime
	if job.FinishedAt != nil {
		finishedAt = sql.NullTime{Time: *job.FinishedAt, Valid: true}
	}

	var fieldsTranslated sql.NullInt32
	if job.FieldsTranslated != nil {
		fieldsTranslated = sql.NullInt32{Int32: int32(*job.FieldsTranslated), Valid: true}
	}

	var errorMessage sql.NullString
	if job.ErrorMessage != nil {
		errorMessage = sql.NullString{String: *job.ErrorMessage, Valid: true}
	}

	_, err := s.db.ExecContext(ctx, `
		UPDATE translation_jobs
		SET finished_at = $2,
		    status = $3,
		    fields_translated = $4,
		    error_message = $5
		WHERE id = $1`,
		job.ID,
		finishedAt,
		job.Status,
		fieldsTranslated,
		errorMessage,
	)
	if err != nil {
		return fmt.Errorf("update translation_job %d: %w", job.ID, err)
	}
	return nil
}

// GetTranslationJob retrieves a translation job by ID.
// Returns nil, nil if not found.
func (s *PostgresStore) GetTranslationJob(ctx context.Context, id int64) (*TranslationJob, error) {
	var job TranslationJob
	var finishedAt sql.NullTime
	var fieldsTranslated sql.NullInt32
	var errorMessage sql.NullString

	err := s.db.QueryRowContext(ctx, `
		SELECT id, vulnerability_id, locale, started_at, finished_at,
		       status, fields_translated, error_message
		FROM translation_jobs
		WHERE id = $1`,
		id,
	).Scan(
		&job.ID,
		&job.VulnerabilityID,
		&job.Locale,
		&job.StartedAt,
		&finishedAt,
		&job.Status,
		&fieldsTranslated,
		&errorMessage,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("query translation_job %d: %w", id, err)
	}

	if finishedAt.Valid {
		job.FinishedAt = &finishedAt.Time
	}
	if fieldsTranslated.Valid {
		v := int(fieldsTranslated.Int32)
		job.FieldsTranslated = &v
	}
	if errorMessage.Valid {
		job.ErrorMessage = &errorMessage.String
	}

	return &job, nil
}

// ListTranslationJobs returns recent translation jobs ordered by start time (newest first).
// If limit <= 0, defaults to 20.
func (s *PostgresStore) ListTranslationJobs(ctx context.Context, limit int) ([]TranslationJob, error) {
	if limit <= 0 {
		limit = 20
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, vulnerability_id, locale, started_at, finished_at,
		       status, fields_translated, error_message
		FROM translation_jobs
		ORDER BY started_at DESC
		LIMIT $1`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query translation_jobs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var jobs []TranslationJob
	for rows.Next() {
		var job TranslationJob
		var finishedAt sql.NullTime
		var fieldsTranslated sql.NullInt32
		var errorMessage sql.NullString

		if err := rows.Scan(
			&job.ID,
			&job.VulnerabilityID,
			&job.Locale,
			&job.StartedAt,
			&finishedAt,
			&job.Status,
			&fieldsTranslated,
			&errorMessage,
		); err != nil {
			return nil, fmt.Errorf("scan translation_job: %w", err)
		}

		if finishedAt.Valid {
			job.FinishedAt = &finishedAt.Time
		}
		if fieldsTranslated.Valid {
			v := int(fieldsTranslated.Int32)
			job.FieldsTranslated = &v
		}
		if errorMessage.Valid {
			job.ErrorMessage = &errorMessage.String
		}

		jobs = append(jobs, job)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate translation_jobs: %w", err)
	}

	return jobs, nil
}
