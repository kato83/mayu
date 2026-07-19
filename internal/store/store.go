// Package store defines the interface and implementation for persisting
// vulnerability data in PostgreSQL.
//
// The schema separates concerns:
//   - vulnerabilities: unified master table (source-agnostic)
//   - vulnerability_aliases: CVE/GHSA/etc cross-references
//   - osv_entries + osv_*: OSV-specific detail tables
//   - Future: kev_entries, epss_scores, etc.
package store

import (
	"context"

	"github.com/kato83/mayu/internal/model"
)

// Store defines the interface for vulnerability data persistence.
type Store interface {
	// Insert stores a single vulnerability and all its related data.
	// If a vulnerability with the same ID already exists, it is replaced (upsert).
	Insert(ctx context.Context, vuln *model.Vulnerability) error

	// UpsertBatch stores multiple vulnerabilities in a single transaction.
	// Each vulnerability is upserted (insert or replace).
	UpsertBatch(ctx context.Context, vulns []*model.Vulnerability) error

	// GetByID retrieves a single vulnerability by its OSV ID.
	// Returns nil, nil if not found.
	GetByID(ctx context.Context, id string) (*model.Vulnerability, error)

	// GetVulnerabilityDetail retrieves enriched vulnerability information by ID,
	// combining OSV, NVD, and MITRE data. The id can be a vulnerability_id,
	// osv_id, or alias. Returns nil, nil if not found.
	GetVulnerabilityDetail(ctx context.Context, id string) (*model.VulnerabilityDetail, error)

	// Search finds vulnerabilities matching the given query parameters.
	Search(ctx context.Context, query SearchQuery) ([]*model.Vulnerability, error)

	// Count returns the number of vulnerabilities matching the given query parameters.
	Count(ctx context.Context, query SearchQuery) (int64, error)

	// GetSyncState retrieves the sync state for a given source.
	// Returns nil, nil if no sync state exists for the source.
	GetSyncState(ctx context.Context, source string) (*SyncState, error)

	// UpdateSyncState creates or updates the sync state for a source.
	UpdateSyncState(ctx context.Context, state *SyncState) error

	// Close releases any resources held by the store.
	Close() error
}

// SearchQuery defines parameters for searching vulnerabilities.
type SearchQuery struct {
	// ID searches by exact vulnerability ID (e.g., "CVE-2024-1234", "GO-2024-2687")
	ID string

	// Ecosystem filters by package ecosystem (e.g., "Go", "PyPI")
	Ecosystem string

	// PackageName filters by package name (e.g., "golang.org/x/crypto")
	PackageName string

	// Alias searches in the vulnerability_aliases table
	Alias string

	// Severity filters by minimum CVSS severity level (critical, high, medium, low)
	Severity string

	// Since filters vulnerabilities modified on or after this date (RFC3339 or YYYY-MM-DD)
	Since string

	// Version filters by affected version (checks version ranges)
	Version string

	// Limit sets the maximum number of results (default: 100)
	Limit int

	// Offset for pagination
	Offset int
}

// SyncState tracks the incremental import state for a data source.
type SyncState struct {
	Source         string // e.g., "Go", "npm", "NVD", "Debian"
	LastModifiedAt string // ISO 8601 timestamp from modified_id.csv
	RecordCount    int64
}
