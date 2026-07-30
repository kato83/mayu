package search

import "context"

// Noop is a no-op search engine that returns ErrNotConfigured for all operations.
// It is used when search.engine is set to "none" or not configured.
type Noop struct{}

// NewNoop creates a new no-op search engine.
func NewNoop() *Noop {
	return &Noop{}
}

// Search always returns ErrNotConfigured.
func (n *Noop) Search(_ context.Context, _ Query) ([]Result, int64, error) {
	return nil, 0, ErrNotConfigured
}

// Init always returns ErrNotConfigured.
func (n *Noop) Init(_ context.Context, _ InitProgress) error {
	return ErrNotConfigured
}

// Available always returns ErrNotConfigured.
func (n *Noop) Available(_ context.Context) error {
	return ErrNotConfigured
}
