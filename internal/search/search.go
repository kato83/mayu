// Package search provides a full-text search abstraction layer.
// It defines the Engine interface that can be backed by different
// implementations (pg_trgm, Elasticsearch, or none/disabled).
package search

import (
	"context"
	"errors"
)

// ErrNotConfigured is returned when full-text search is not enabled.
var ErrNotConfigured = errors.New("full-text search is not configured; set search.engine in config.yaml")

// ErrNotInitialized is returned when the search engine requires initialization
// (e.g., pg_trgm indexes have not been created yet via "mayu search --init").
var ErrNotInitialized = errors.New("full-text search indexes not initialized; run \"mayu search --init\"")

// Query represents a full-text search request.
type Query struct {
	// Text is the free-text search query string.
	Text string
	// Ecosystem optionally restricts results to a specific ecosystem.
	Ecosystem string
	// Limit is the maximum number of results to return.
	Limit int
	// Offset is the number of results to skip for pagination.
	Offset int
}

// Result represents a single full-text search result.
type Result struct {
	// VulnerabilityID is the canonical vulnerability identifier.
	VulnerabilityID string
	// Summary is the vulnerability summary text.
	Summary string
	// Highlights contains snippets showing where the query matched.
	Highlights []string
	// Score is the relevance score (higher = more relevant).
	Score float64
	// Ecosystem is the primary ecosystem (if available).
	Ecosystem string
}

// InitProgress is called during initialization to report progress.
type InitProgress func(step string, current, total int)

// Engine is the interface for full-text search backends.
type Engine interface {
	// Search executes a full-text search query and returns matching results.
	Search(ctx context.Context, q Query) (results []Result, total int64, err error)

	// Init performs one-time initialization (e.g., creating extensions and indexes).
	// This may take significant time depending on data volume.
	// The progress callback, if non-nil, is called to report progress.
	Init(ctx context.Context, progress InitProgress) error

	// Available checks whether the engine is ready to serve queries.
	// Returns nil if ready, ErrNotInitialized if indexes need to be created,
	// or another error if the engine cannot function.
	Available(ctx context.Context) error
}
