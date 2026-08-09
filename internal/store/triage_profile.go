package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// TriageProfileRow represents a custom triage profile stored in the database.
type TriageProfileRow struct {
	ID          int64            `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Base        string           `json:"base,omitempty"`
	ScoreWeight float64          `json:"score_weight"`
	ActFloor    string           `json:"act_floor"`
	Weights     json.RawMessage  `json:"weights"`
	Thresholds  json.RawMessage  `json:"thresholds"`
	SSVCMapping *json.RawMessage `json:"ssvc_mapping,omitempty"`
	CreatedBy   *int64           `json:"created_by,omitempty"`
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`
}

// CreateTriageProfile inserts a new custom triage profile into the database.
func (s *PostgresStore) CreateTriageProfile(ctx context.Context, row *TriageProfileRow) (*TriageProfileRow, error) {
	query := `
		INSERT INTO triage_profiles (name, description, base, score_weight, act_floor, weights, thresholds, ssvc_mapping, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, name, description, base, score_weight, act_floor, weights, thresholds, ssvc_mapping, created_by, created_at, updated_at`

	var result TriageProfileRow
	var base sql.NullString
	var ssvcMapping *json.RawMessage
	var createdBy sql.NullInt64

	err := s.db.QueryRowContext(ctx, query,
		row.Name, row.Description, nullString(row.Base),
		row.ScoreWeight, row.ActFloor,
		row.Weights, row.Thresholds, row.SSVCMapping,
		nullInt64(row.CreatedBy),
	).Scan(
		&result.ID, &result.Name, &result.Description,
		&base, &result.ScoreWeight, &result.ActFloor,
		&result.Weights, &result.Thresholds,
		&ssvcMapping, &createdBy,
		&result.CreatedAt, &result.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create triage profile: %w", err)
	}

	if base.Valid {
		result.Base = base.String
	}
	result.SSVCMapping = ssvcMapping
	if createdBy.Valid {
		result.CreatedBy = &createdBy.Int64
	}
	return &result, nil
}

// GetTriageProfile retrieves a custom triage profile by name.
func (s *PostgresStore) GetTriageProfile(ctx context.Context, name string) (*TriageProfileRow, error) {
	query := `
		SELECT id, name, description, base, score_weight, act_floor, weights, thresholds, ssvc_mapping, created_by, created_at, updated_at
		FROM triage_profiles WHERE name = $1`

	var row TriageProfileRow
	var base sql.NullString
	var ssvcMapping *json.RawMessage
	var createdBy sql.NullInt64

	err := s.db.QueryRowContext(ctx, query, name).Scan(
		&row.ID, &row.Name, &row.Description,
		&base, &row.ScoreWeight, &row.ActFloor,
		&row.Weights, &row.Thresholds,
		&ssvcMapping, &createdBy,
		&row.CreatedAt, &row.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get triage profile: %w", err)
	}

	if base.Valid {
		row.Base = base.String
	}
	row.SSVCMapping = ssvcMapping
	if createdBy.Valid {
		row.CreatedBy = &createdBy.Int64
	}
	return &row, nil
}

// ListTriageProfiles returns all custom triage profiles.
func (s *PostgresStore) ListTriageProfiles(ctx context.Context) ([]*TriageProfileRow, error) {
	query := `
		SELECT id, name, description, base, score_weight, act_floor, weights, thresholds, ssvc_mapping, created_by, created_at, updated_at
		FROM triage_profiles ORDER BY name`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list triage profiles: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var profiles []*TriageProfileRow
	for rows.Next() {
		var row TriageProfileRow
		var base sql.NullString
		var ssvcMapping *json.RawMessage
		var createdBy sql.NullInt64

		if err := rows.Scan(
			&row.ID, &row.Name, &row.Description,
			&base, &row.ScoreWeight, &row.ActFloor,
			&row.Weights, &row.Thresholds,
			&ssvcMapping, &createdBy,
			&row.CreatedAt, &row.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan triage profile: %w", err)
		}

		if base.Valid {
			row.Base = base.String
		}
		row.SSVCMapping = ssvcMapping
		if createdBy.Valid {
			row.CreatedBy = &createdBy.Int64
		}
		profiles = append(profiles, &row)
	}
	return profiles, rows.Err()
}

// UpdateTriageProfile updates a custom triage profile by name.
func (s *PostgresStore) UpdateTriageProfile(ctx context.Context, name string, row *TriageProfileRow) (*TriageProfileRow, error) {
	query := `
		UPDATE triage_profiles
		SET description = $2, base = $3, score_weight = $4, act_floor = $5, weights = $6, thresholds = $7, ssvc_mapping = $8, updated_at = NOW()
		WHERE name = $1
		RETURNING id, name, description, base, score_weight, act_floor, weights, thresholds, ssvc_mapping, created_by, created_at, updated_at`

	var result TriageProfileRow
	var base sql.NullString
	var ssvcMapping *json.RawMessage
	var createdBy sql.NullInt64

	err := s.db.QueryRowContext(ctx, query,
		name, row.Description, nullString(row.Base),
		row.ScoreWeight, row.ActFloor,
		row.Weights, row.Thresholds, row.SSVCMapping,
	).Scan(
		&result.ID, &result.Name, &result.Description,
		&base, &result.ScoreWeight, &result.ActFloor,
		&result.Weights, &result.Thresholds,
		&ssvcMapping, &createdBy,
		&result.CreatedAt, &result.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("update triage profile: %w", err)
	}

	if base.Valid {
		result.Base = base.String
	}
	result.SSVCMapping = ssvcMapping
	if createdBy.Valid {
		result.CreatedBy = &createdBy.Int64
	}
	return &result, nil
}

// DeleteTriageProfile deletes a custom triage profile by name.
func (s *PostgresStore) DeleteTriageProfile(ctx context.Context, name string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM triage_profiles WHERE name = $1`, name)
	if err != nil {
		return fmt.Errorf("delete triage profile: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("triage profile %q not found", name)
	}
	return nil
}

// nullString converts an empty string to sql.NullString.
func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

// nullInt64 converts a *int64 to sql.NullInt64.
func nullInt64(p *int64) sql.NullInt64 {
	if p == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: *p, Valid: true}
}
