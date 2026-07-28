package sbommon

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
)

// Compile-time interface compliance check.
var _ SBOMStore = (*PostgresSBOMStore)(nil)

// PostgresSBOMStore implements SBOMStore using database/sql with the pgx stdlib driver.
type PostgresSBOMStore struct {
	db *sql.DB
}

// NewPostgresSBOMStore creates a new PostgresSBOMStore with the given database connection.
func NewPostgresSBOMStore(db *sql.DB) *PostgresSBOMStore {
	return &PostgresSBOMStore{db: db}
}

// CreateProject creates a new SBOM project and returns the generated ID.
func (s *PostgresSBOMStore) CreateProject(ctx context.Context, p *SBOMProject) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO sbom_projects (user_id, name)
		VALUES ($1, $2)
		RETURNING id`,
		p.UserID, p.Name,
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("insert sbom project: %w", err)
	}
	return id, nil
}

// GetProject retrieves a project by ID, scoped to a user.
func (s *PostgresSBOMStore) GetProject(ctx context.Context, id int64, userID int64) (*SBOMProject, error) {
	var p SBOMProject
	err := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, name, created_at, updated_at
		FROM sbom_projects
		WHERE id = $1 AND user_id = $2`,
		id, userID,
	).Scan(&p.ID, &p.UserID, &p.Name, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get sbom project %d: %w", id, err)
	}
	return &p, nil
}

// GetProjectByName retrieves a project by name, scoped to a user.
func (s *PostgresSBOMStore) GetProjectByName(ctx context.Context, name string, userID int64) (*SBOMProject, error) {
	var p SBOMProject
	err := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, name, created_at, updated_at
		FROM sbom_projects
		WHERE name = $1 AND user_id = $2`,
		name, userID,
	).Scan(&p.ID, &p.UserID, &p.Name, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get sbom project by name %q: %w", name, err)
	}
	return &p, nil
}

// ListProjects returns all projects for a user, ordered by creation time.
func (s *PostgresSBOMStore) ListProjects(ctx context.Context, userID int64) ([]*SBOMProject, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_id, name, created_at, updated_at
		FROM sbom_projects
		WHERE user_id = $1
		ORDER BY created_at`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("list sbom projects for user %d: %w", userID, err)
	}
	defer func() { _ = rows.Close() }()

	var projects []*SBOMProject
	for rows.Next() {
		var p SBOMProject
		if err := rows.Scan(&p.ID, &p.UserID, &p.Name, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan sbom project: %w", err)
		}
		projects = append(projects, &p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sbom projects: %w", err)
	}
	return projects, nil
}

// UpdateProject updates an existing project.
func (s *PostgresSBOMStore) UpdateProject(ctx context.Context, p *SBOMProject) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE sbom_projects
		SET name = $2, updated_at = NOW()
		WHERE id = $1 AND user_id = $3`,
		p.ID, p.Name, p.UserID,
	)
	if err != nil {
		return fmt.Errorf("update sbom project %d: %w", p.ID, err)
	}
	return nil
}

// DeleteProject removes a project by ID, scoped to a user.
func (s *PostgresSBOMStore) DeleteProject(ctx context.Context, id int64, userID int64) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM sbom_projects
		WHERE id = $1 AND user_id = $2`,
		id, userID,
	)
	if err != nil {
		return fmt.Errorf("delete sbom project %d: %w", id, err)
	}
	return nil
}

// CreateVersion creates a new SBOM version and returns the generated ID.
func (s *PostgresSBOMStore) CreateVersion(ctx context.Context, v *SBOMVersion) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO sbom_versions (project_id, version, environment, sbom_format, raw_sbom, component_count)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id`,
		v.ProjectID, v.Version, v.Environment, v.SBOMFormat, v.RawSBOM, v.ComponentCount,
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("insert sbom version: %w", err)
	}
	return id, nil
}

// GetVersion retrieves a version by ID.
func (s *PostgresSBOMStore) GetVersion(ctx context.Context, id int64) (*SBOMVersion, error) {
	var v SBOMVersion
	var rawSBOM []byte
	err := s.db.QueryRowContext(ctx, `
		SELECT id, project_id, version, environment, sbom_format, raw_sbom, component_count, created_at
		FROM sbom_versions
		WHERE id = $1`,
		id,
	).Scan(&v.ID, &v.ProjectID, &v.Version, &v.Environment, &v.SBOMFormat, &rawSBOM, &v.ComponentCount, &v.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get sbom version %d: %w", id, err)
	}
	v.RawSBOM = rawSBOM
	return &v, nil
}

// ListVersions returns all versions for a project, ordered by creation time desc.
func (s *PostgresSBOMStore) ListVersions(ctx context.Context, projectID int64) ([]*SBOMVersion, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, project_id, version, environment, sbom_format, component_count, created_at
		FROM sbom_versions
		WHERE project_id = $1
		ORDER BY created_at DESC`,
		projectID,
	)
	if err != nil {
		return nil, fmt.Errorf("list sbom versions for project %d: %w", projectID, err)
	}
	defer func() { _ = rows.Close() }()

	var versions []*SBOMVersion
	for rows.Next() {
		var v SBOMVersion
		if err := rows.Scan(&v.ID, &v.ProjectID, &v.Version, &v.Environment, &v.SBOMFormat, &v.ComponentCount, &v.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan sbom version: %w", err)
		}
		versions = append(versions, &v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sbom versions: %w", err)
	}
	return versions, nil
}

// GetLatestVersion returns the most recent version for a project.
func (s *PostgresSBOMStore) GetLatestVersion(ctx context.Context, projectID int64) (*SBOMVersion, error) {
	var v SBOMVersion
	var rawSBOM []byte
	err := s.db.QueryRowContext(ctx, `
		SELECT id, project_id, version, environment, sbom_format, raw_sbom, component_count, created_at
		FROM sbom_versions
		WHERE project_id = $1
		ORDER BY created_at DESC
		LIMIT 1`,
		projectID,
	).Scan(&v.ID, &v.ProjectID, &v.Version, &v.Environment, &v.SBOMFormat, &rawSBOM, &v.ComponentCount, &v.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get latest sbom version for project %d: %w", projectID, err)
	}
	v.RawSBOM = rawSBOM
	return &v, nil
}

// CreateScanResult creates a new scan result and returns the generated ID.
func (s *PostgresSBOMStore) CreateScanResult(ctx context.Context, sr *SBOMScanResult) (int64, error) {
	findingsJSON, err := json.Marshal(sr.Findings)
	if err != nil {
		return 0, fmt.Errorf("marshal findings: %w", err)
	}

	var id int64
	err = s.db.QueryRowContext(ctx, `
		INSERT INTO sbom_scan_results (version_id, scanned_at, total_packages, vulnerable_packages,
			total_findings, new_findings, resolved_findings, findings, status, trigger)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id`,
		sr.VersionID, sr.ScannedAt, sr.TotalPackages, sr.VulnerablePackages,
		sr.TotalFindings, sr.NewFindings, sr.ResolvedFindings, findingsJSON, sr.Status, sr.Trigger,
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("insert sbom scan result: %w", err)
	}
	return id, nil
}

// GetScanResult retrieves a scan result by ID.
func (s *PostgresSBOMStore) GetScanResult(ctx context.Context, id int64) (*SBOMScanResult, error) {
	var sr SBOMScanResult
	var findingsJSON []byte
	err := s.db.QueryRowContext(ctx, `
		SELECT id, version_id, scanned_at, total_packages, vulnerable_packages,
			total_findings, new_findings, resolved_findings, findings, status, trigger
		FROM sbom_scan_results
		WHERE id = $1`,
		id,
	).Scan(&sr.ID, &sr.VersionID, &sr.ScannedAt, &sr.TotalPackages, &sr.VulnerablePackages,
		&sr.TotalFindings, &sr.NewFindings, &sr.ResolvedFindings, &findingsJSON, &sr.Status, &sr.Trigger)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get sbom scan result %d: %w", id, err)
	}
	if err := json.Unmarshal(findingsJSON, &sr.Findings); err != nil {
		return nil, fmt.Errorf("unmarshal findings for scan %d: %w", id, err)
	}
	return &sr, nil
}

// ListScanResults returns scan results for a version, ordered by scanned_at desc.
func (s *PostgresSBOMStore) ListScanResults(ctx context.Context, versionID int64) ([]*SBOMScanResult, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, version_id, scanned_at, total_packages, vulnerable_packages,
			total_findings, new_findings, resolved_findings, findings, status, trigger
		FROM sbom_scan_results
		WHERE version_id = $1
		ORDER BY scanned_at DESC`,
		versionID,
	)
	if err != nil {
		return nil, fmt.Errorf("list sbom scan results for version %d: %w", versionID, err)
	}
	defer func() { _ = rows.Close() }()

	var results []*SBOMScanResult
	for rows.Next() {
		var sr SBOMScanResult
		var findingsJSON []byte
		if err := rows.Scan(&sr.ID, &sr.VersionID, &sr.ScannedAt, &sr.TotalPackages, &sr.VulnerablePackages,
			&sr.TotalFindings, &sr.NewFindings, &sr.ResolvedFindings, &findingsJSON, &sr.Status, &sr.Trigger); err != nil {
			return nil, fmt.Errorf("scan sbom scan result: %w", err)
		}
		if err := json.Unmarshal(findingsJSON, &sr.Findings); err != nil {
			return nil, fmt.Errorf("unmarshal findings: %w", err)
		}
		results = append(results, &sr)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sbom scan results: %w", err)
	}
	return results, nil
}

// GetLatestScanResult returns the most recent scan result for a version.
func (s *PostgresSBOMStore) GetLatestScanResult(ctx context.Context, versionID int64) (*SBOMScanResult, error) {
	var sr SBOMScanResult
	var findingsJSON []byte
	err := s.db.QueryRowContext(ctx, `
		SELECT id, version_id, scanned_at, total_packages, vulnerable_packages,
			total_findings, new_findings, resolved_findings, findings, status, trigger
		FROM sbom_scan_results
		WHERE version_id = $1
		ORDER BY scanned_at DESC
		LIMIT 1`,
		versionID,
	).Scan(&sr.ID, &sr.VersionID, &sr.ScannedAt, &sr.TotalPackages, &sr.VulnerablePackages,
		&sr.TotalFindings, &sr.NewFindings, &sr.ResolvedFindings, &findingsJSON, &sr.Status, &sr.Trigger)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get latest sbom scan result for version %d: %w", versionID, err)
	}
	if err := json.Unmarshal(findingsJSON, &sr.Findings); err != nil {
		return nil, fmt.Errorf("unmarshal findings: %w", err)
	}
	return &sr, nil
}

// GetPreviousScanResult returns the scan result immediately before the given scan ID.
func (s *PostgresSBOMStore) GetPreviousScanResult(ctx context.Context, versionID int64, beforeScanID int64) (*SBOMScanResult, error) {
	var sr SBOMScanResult
	var findingsJSON []byte
	err := s.db.QueryRowContext(ctx, `
		SELECT id, version_id, scanned_at, total_packages, vulnerable_packages,
			total_findings, new_findings, resolved_findings, findings, status, trigger
		FROM sbom_scan_results
		WHERE version_id = $1 AND id < $2
		ORDER BY scanned_at DESC
		LIMIT 1`,
		versionID, beforeScanID,
	).Scan(&sr.ID, &sr.VersionID, &sr.ScannedAt, &sr.TotalPackages, &sr.VulnerablePackages,
		&sr.TotalFindings, &sr.NewFindings, &sr.ResolvedFindings, &findingsJSON, &sr.Status, &sr.Trigger)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get previous sbom scan result for version %d: %w", versionID, err)
	}
	if err := json.Unmarshal(findingsJSON, &sr.Findings); err != nil {
		return nil, fmt.Errorf("unmarshal findings: %w", err)
	}
	return &sr, nil
}

// GetPreviousVersionScanResult returns the latest scan result from the previous
// version in the same project (ordered by version creation time).
func (s *PostgresSBOMStore) GetPreviousVersionScanResult(ctx context.Context, projectID int64, currentVersionID int64) (*SBOMScanResult, error) {
	var sr SBOMScanResult
	var findingsJSON []byte
	err := s.db.QueryRowContext(ctx, `
		SELECT r.id, r.version_id, r.scanned_at, r.total_packages, r.vulnerable_packages,
			r.total_findings, r.new_findings, r.resolved_findings, r.findings, r.status, r.trigger
		FROM sbom_scan_results r
		JOIN sbom_versions v ON v.id = r.version_id
		WHERE v.project_id = $1
		  AND v.id < $2
		ORDER BY v.id DESC, r.scanned_at DESC
		LIMIT 1`,
		projectID, currentVersionID,
	).Scan(&sr.ID, &sr.VersionID, &sr.ScannedAt, &sr.TotalPackages, &sr.VulnerablePackages,
		&sr.TotalFindings, &sr.NewFindings, &sr.ResolvedFindings, &findingsJSON, &sr.Status, &sr.Trigger)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get previous version scan result for project %d: %w", projectID, err)
	}
	if err := json.Unmarshal(findingsJSON, &sr.Findings); err != nil {
		return nil, fmt.Errorf("unmarshal findings: %w", err)
	}
	return &sr, nil
}

// ListAllVersions returns all SBOM versions across all projects.
func (s *PostgresSBOMStore) ListAllVersions(ctx context.Context) ([]*SBOMVersion, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, project_id, version, environment, sbom_format, component_count, created_at
		FROM sbom_versions
		ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list all sbom versions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var versions []*SBOMVersion
	for rows.Next() {
		var v SBOMVersion
		if err := rows.Scan(&v.ID, &v.ProjectID, &v.Version, &v.Environment, &v.SBOMFormat, &v.ComponentCount, &v.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan sbom version: %w", err)
		}
		versions = append(versions, &v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate all sbom versions: %w", err)
	}
	return versions, nil
}

// ListAllVersionIDs returns the IDs of all SBOM versions across all projects.
// This is a lightweight query that avoids loading raw_sbom data into memory.
func (s *PostgresSBOMStore) ListAllVersionIDs(ctx context.Context) ([]int64, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id FROM sbom_versions ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list all sbom version IDs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan sbom version id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sbom version IDs: %w", err)
	}
	return ids, nil
}
