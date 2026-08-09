package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/kato83/mayu/internal/triage"
)

// CreateOrUpdateEnvironmentBinding creates or updates an environment profile binding.
func (s *PostgresStore) CreateOrUpdateEnvironmentBinding(ctx context.Context, projectID int64, environment, profileName, description string) error {
	query := `
		INSERT INTO project_environment_profiles (project_id, environment, profile_name, description, created_at, updated_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW())
		ON CONFLICT (project_id, environment)
		DO UPDATE SET profile_name = EXCLUDED.profile_name, description = EXCLUDED.description, updated_at = NOW()`

	_, err := s.db.ExecContext(ctx, query, projectID, environment, profileName, description)
	if err != nil {
		return fmt.Errorf("create or update environment binding: %w", err)
	}
	return nil
}

// GetEnvironmentBinding retrieves an environment profile binding for a project+environment.
func (s *PostgresStore) GetEnvironmentBinding(ctx context.Context, projectID int64, environment string) (*triage.EnvironmentProfileBinding, error) {
	query := `
		SELECT id, project_id, environment, profile_name, description, created_at, updated_at
		FROM project_environment_profiles
		WHERE project_id = $1 AND environment = $2`

	var binding triage.EnvironmentProfileBinding
	var desc sql.NullString

	err := s.db.QueryRowContext(ctx, query, projectID, environment).Scan(
		&binding.ID, &binding.ProjectID, &binding.Environment,
		&binding.ProfileName, &desc,
		&binding.CreatedAt, &binding.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get environment binding: %w", err)
	}

	if desc.Valid {
		binding.Description = desc.String
	}
	return &binding, nil
}

// ListEnvironmentBindings returns all environment profile bindings for a project.
func (s *PostgresStore) ListEnvironmentBindings(ctx context.Context, projectID int64) ([]triage.EnvironmentProfileBinding, error) {
	query := `
		SELECT id, project_id, environment, profile_name, description, created_at, updated_at
		FROM project_environment_profiles
		WHERE project_id = $1
		ORDER BY environment`

	rows, err := s.db.QueryContext(ctx, query, projectID)
	if err != nil {
		return nil, fmt.Errorf("list environment bindings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var bindings []triage.EnvironmentProfileBinding
	for rows.Next() {
		var binding triage.EnvironmentProfileBinding
		var desc sql.NullString

		if err := rows.Scan(
			&binding.ID, &binding.ProjectID, &binding.Environment,
			&binding.ProfileName, &desc,
			&binding.CreatedAt, &binding.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan environment binding: %w", err)
		}

		if desc.Valid {
			binding.Description = desc.String
		}
		bindings = append(bindings, binding)
	}
	return bindings, rows.Err()
}

// DeleteEnvironmentBinding removes an environment profile binding.
func (s *PostgresStore) DeleteEnvironmentBinding(ctx context.Context, projectID int64, environment string) error {
	result, err := s.db.ExecContext(ctx,
		`DELETE FROM project_environment_profiles WHERE project_id = $1 AND environment = $2`,
		projectID, environment,
	)
	if err != nil {
		return fmt.Errorf("delete environment binding: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("environment binding not found for project %d, environment %q", projectID, environment)
	}
	return nil
}

// GetProjectDefaultProfile returns the default triage profile name for an SBOM project.
// Returns empty string if no default is set.
func (s *PostgresStore) GetProjectDefaultProfile(ctx context.Context, projectID int64) (string, error) {
	var profile sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT default_profile FROM sbom_projects WHERE id = $1`,
		projectID,
	).Scan(&profile)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("get project default profile: %w", err)
	}
	if profile.Valid {
		return profile.String, nil
	}
	return "", nil
}

// SetProjectDefaultProfile sets the default triage profile for an SBOM project.
func (s *PostgresStore) SetProjectDefaultProfile(ctx context.Context, projectID int64, profileName string) error {
	result, err := s.db.ExecContext(ctx,
		`UPDATE sbom_projects SET default_profile = $2, updated_at = $3 WHERE id = $1`,
		projectID, profileName, time.Now(),
	)
	if err != nil {
		return fmt.Errorf("set project default profile: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("project %d not found", projectID)
	}
	return nil
}

// ClearProjectDefaultProfile removes the default triage profile from an SBOM project.
func (s *PostgresStore) ClearProjectDefaultProfile(ctx context.Context, projectID int64) error {
	result, err := s.db.ExecContext(ctx,
		`UPDATE sbom_projects SET default_profile = NULL, updated_at = $2 WHERE id = $1`,
		projectID, time.Now(),
	)
	if err != nil {
		return fmt.Errorf("clear project default profile: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("project %d not found", projectID)
	}
	return nil
}
