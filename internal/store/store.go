// Package store defines the interface and implementation for persisting
// vulnerability data in PostgreSQL.
//
// The schema separates concerns:
//   - vulnerabilities: unified master table (source-agnostic, no source column)
//   - vulnerability_aliases + alias_sources: CVE/GHSA/etc cross-references with provenance
//   - vulnerability_summary: pre-computed derived data for list/filter views
//   - product_identifiers: unified package/product search table (purl/CPE decomposed)
//   - osv_entries + osv_*: OSV-specific detail tables
//   - nvd_entries + nvd_*: NVD-specific detail tables
//   - mitre_entries + mitre_*: MITRE-specific detail tables
//   - epss_scores: EPSS scoring data
//   - kev_entries: CISA KEV catalog data
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

	// RefreshSummary recomputes vulnerability_summary rows for the given vulnerability IDs.
	// It aggregates scores from all sources (OSV severity, NVD metrics, MITRE metrics),
	// EPSS, KEV, LEV, ecosystems, and CWEs into the pre-computed summary table.
	// Called synchronously at the end of each import pipeline.
	RefreshSummary(ctx context.Context, vulnIDs []string) error

	// UpsertProductIdentifiers stores product identifiers for vulnerabilities.
	// It replaces all existing identifiers for the given (vulnerability_id, source)
	// combination and inserts the new ones.
	UpsertProductIdentifiers(ctx context.Context, identifiers []*model.ProductIdentifier) error

	// GetSyncState retrieves the sync state for a given source.
	// Returns nil, nil if no sync state exists for the source.
	GetSyncState(ctx context.Context, source string) (*SyncState, error)

	// UpdateSyncState creates or updates the sync state for a source.
	UpdateSyncState(ctx context.Context, state *SyncState) error

	// Close releases any resources held by the store.
	Close() error

	// ListOSVEcosystems returns all known OSV ecosystem names, sorted alphabetically.
	ListOSVEcosystems(ctx context.Context) ([]string, error)

	// UpsertOSVEcosystems inserts ecosystem names into osv_ecosystems (ignoring duplicates).
	UpsertOSVEcosystems(ctx context.Context, names []string) error
}

// SearchQuery defines parameters for searching vulnerabilities.
type SearchQuery struct {
	// ID searches by exact vulnerability ID (e.g., "CVE-2024-1234", "GO-2024-2687")
	ID string

	// Ecosystem filters by package ecosystem (e.g., "Go", "PyPI")
	Ecosystem string

	// PackageName filters by package name (e.g., "golang.org/x/crypto")
	PackageName string

	// Purl searches by Package URL (e.g., "pkg:npm/express")
	Purl string

	// CPE searches by CPE URI prefix (e.g., "cpe:2.3:a:apache:http_server")
	CPE string

	// Severity filters by normalized severity level (critical, high, medium, low, none).
	// Uses range overlap on vulnerability_summary.severity_worst/severity_best.
	Severity string

	// Since filters vulnerabilities modified on or after this date (RFC3339 or YYYY-MM-DD)
	Since string

	// Version filters by affected version (checks version ranges)
	Version string

	// InKEV filters to only vulnerabilities in the CISA KEV catalog
	InKEV *bool

	// Limit sets the maximum number of results (default: 100)
	Limit int

	// Offset for pagination (legacy, used when Cursor is empty)
	Offset int

	// Cursor is an opaque cursor string for keyset pagination.
	// When set, it takes precedence over Offset.
	// The cursor encodes (published, id) for stable ordering.
	Cursor string

	// Fields restricts the response to the specified fields only.
	// When set, the search uses a lightweight query that avoids fetching raw_json.
	// Supported fields: id, summary, modified, severity, ecosystem
	Fields []string
}

// SyncState tracks the incremental import state for a data source.
type SyncState struct {
	Source         string // e.g., "Go", "npm", "NVD", "Debian"
	LastModifiedAt string // ISO 8601 timestamp from modified_id.csv
	RecordCount    int64
}
