package sbommon

import "context"

// SBOMStore defines the interface for SBOM monitoring data persistence.
type SBOMStore interface {
	// CreateProject creates a new SBOM project and returns the generated ID.
	CreateProject(ctx context.Context, p *SBOMProject) (int64, error)

	// GetProject retrieves a project by ID, scoped to a user.
	// Returns nil, nil if not found.
	GetProject(ctx context.Context, id int64, userID int64) (*SBOMProject, error)

	// GetProjectByName retrieves a project by name, scoped to a user.
	// Returns nil, nil if not found.
	GetProjectByName(ctx context.Context, name string, userID int64) (*SBOMProject, error)

	// ListProjects returns all projects for a user, ordered by creation time.
	ListProjects(ctx context.Context, userID int64) ([]*SBOMProject, error)

	// ListProjectsByTeam returns all projects for a team, ordered by creation time.
	ListProjectsByTeam(ctx context.Context, teamID int64) ([]*SBOMProject, error)

	// UpdateProject updates an existing project.
	UpdateProject(ctx context.Context, p *SBOMProject) error

	// DeleteProject removes a project by ID, scoped to a user.
	DeleteProject(ctx context.Context, id int64, userID int64) error

	// CreateVersion creates a new SBOM version and returns the generated ID.
	CreateVersion(ctx context.Context, v *SBOMVersion) (int64, error)

	// GetVersion retrieves a version by ID.
	// Returns nil, nil if not found.
	GetVersion(ctx context.Context, id int64) (*SBOMVersion, error)

	// ListVersions returns all versions for a project, ordered by creation time desc.
	ListVersions(ctx context.Context, projectID int64) ([]*SBOMVersion, error)

	// GetLatestVersion returns the most recent version for a project.
	// Returns nil, nil if no versions exist.
	GetLatestVersion(ctx context.Context, projectID int64) (*SBOMVersion, error)

	// CreateScanResult creates a new scan result and returns the generated ID.
	CreateScanResult(ctx context.Context, sr *SBOMScanResult) (int64, error)

	// GetScanResult retrieves a scan result by ID.
	// Returns nil, nil if not found.
	GetScanResult(ctx context.Context, id int64) (*SBOMScanResult, error)

	// ListScanResults returns scan results for a version, ordered by scanned_at desc.
	ListScanResults(ctx context.Context, versionID int64) ([]*SBOMScanResult, error)

	// GetLatestScanResult returns the most recent scan result for a version.
	// Returns nil, nil if no scan results exist.
	GetLatestScanResult(ctx context.Context, versionID int64) (*SBOMScanResult, error)

	// GetPreviousVersionScanResult returns the latest scan result from the
	// previous version in the same project (ordered by creation time).
	// This is used for cross-version diff computation on new version uploads.
	// Returns nil, nil if no previous version or scan result exists.
	GetPreviousVersionScanResult(ctx context.Context, projectID int64, currentVersionID int64) (*SBOMScanResult, error)

	// GetPreviousScanResult returns the scan result immediately before the given scan ID
	// for the same version. Returns nil, nil if no previous result exists.
	GetPreviousScanResult(ctx context.Context, versionID int64, beforeScanID int64) (*SBOMScanResult, error)

	// ListAllVersions returns all SBOM versions across all projects.
	// Used by the ingest re-evaluator to re-scan all tracked SBOMs.
	ListAllVersions(ctx context.Context) ([]*SBOMVersion, error)

	// ListAllVersionIDs returns the IDs of all SBOM versions across all projects.
	// This is a lightweight query that avoids loading raw_sbom data into memory.
	ListAllVersionIDs(ctx context.Context) ([]int64, error)

	// UpsertFindingStatus inserts or updates a finding status record.
	// When a status change occurs, an audit log entry is created.
	// Returns the upserted FindingStatus record.
	UpsertFindingStatus(ctx context.Context, fs *FindingStatus) (*FindingStatus, error)

	// GetFindingStatus retrieves a finding status by version ID, vulnerability ID, and purl.
	// Returns nil, nil if not found.
	GetFindingStatus(ctx context.Context, versionID int64, vulnID string, purl string) (*FindingStatus, error)

	// ListFindingStatuses returns all finding statuses for a version, optionally filtered by status.
	ListFindingStatuses(ctx context.Context, versionID int64, statusFilter []string) ([]*FindingStatus, error)

	// ListFindingStatusLog returns audit log entries for a given finding status ID.
	ListFindingStatusLog(ctx context.Context, findingStatusID int64) ([]*FindingStatusLog, error)

	// DeleteFindingStatus removes a finding status (resets to default 'open' behavior).
	DeleteFindingStatus(ctx context.Context, versionID int64, vulnID, purl string) error
}
