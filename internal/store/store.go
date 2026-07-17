// Package store defines the interface and implementation for persisting
// OSV vulnerability data in PostgreSQL.
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

	// Search finds vulnerabilities matching the given query parameters.
	Search(ctx context.Context, query SearchQuery) ([]*model.Vulnerability, error)

	// GetSyncState retrieves the sync state for a given ecosystem.
	// Returns nil, nil if no sync state exists for the ecosystem.
	GetSyncState(ctx context.Context, ecosystem string) (*SyncState, error)

	// UpdateSyncState creates or updates the sync state for an ecosystem.
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

	// Alias searches in the aliases array
	Alias string

	// Limit sets the maximum number of results (default: 100)
	Limit int

	// Offset for pagination
	Offset int
}

// SyncState tracks the incremental import state for an ecosystem.
type SyncState struct {
	Ecosystem      string
	LastModifiedAt string // ISO 8601 timestamp from modified_id.csv
	RecordCount    int64
}
