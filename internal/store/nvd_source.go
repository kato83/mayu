package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"

	"github.com/kato83/mayu/internal/model"
)

// nvdSourceCache is a thread-safe in-memory cache for NVD source identifier → name mappings.
type nvdSourceCache struct {
	mu      sync.RWMutex
	entries map[string]string // source_identifier → name
}

// newNVDSourceCache creates a new empty cache.
func newNVDSourceCache() *nvdSourceCache {
	return &nvdSourceCache{
		entries: make(map[string]string),
	}
}

// get retrieves a name from the cache. Returns empty string if not found.
func (c *nvdSourceCache) get(identifier string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.entries[identifier]
}

// set stores a mapping in the cache.
func (c *nvdSourceCache) set(identifier, name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[identifier] = name
}

// loadAll replaces the entire cache contents (used during bulk refresh).
func (c *nvdSourceCache) loadAll(entries map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = entries
}

// nvdSourceResolver provides NVD source name resolution with caching.
type nvdSourceResolver struct {
	cache *nvdSourceCache
}

// resolveFromCache returns source names for identifiers that are in the cache.
// Returns a map of identifier → name for found entries only.
func (r *nvdSourceResolver) resolveFromCache(_ context.Context, identifiers []string) map[string]string {
	result := make(map[string]string, len(identifiers))
	for _, id := range identifiers {
		if name := r.cache.get(id); name != "" {
			result[id] = name
		}
	}
	return result
}

// UpsertNVDSources stores NVD source entries using INSERT ... ON CONFLICT DO UPDATE.
// It also refreshes the in-memory cache with the new data.
func (s *PostgresStore) UpsertNVDSources(ctx context.Context, sources []model.NVDSource) error {
	if len(sources) == 0 {
		return nil
	}

	// Deduplicate by SourceIdentifier (last-wins) to avoid PostgreSQL
	// "ON CONFLICT DO UPDATE command cannot affect row a second time" error
	// when the NVD Source API returns duplicate identifiers across organizations.
	seen := make(map[string]int, len(sources))
	deduped := make([]model.NVDSource, 0, len(sources))
	for _, src := range sources {
		if idx, exists := seen[src.SourceIdentifier]; exists {
			// Overwrite with the later entry (last-wins)
			deduped[idx] = src
		} else {
			seen[src.SourceIdentifier] = len(deduped)
			deduped = append(deduped, src)
		}
	}
	sources = deduped

	// Process in batches of 100 to avoid overly large queries
	const batchSize = 100
	for i := 0; i < len(sources); i += batchSize {
		end := i + batchSize
		if end > len(sources) {
			end = len(sources)
		}

		query, args := buildNVDSourceUpsertQuery(sources[i:end])
		if _, err := s.db.ExecContext(ctx, query, args...); err != nil {
			return fmt.Errorf("upsert NVD sources batch at offset %d: %w", i, err)
		}
	}

	// Refresh the cache with all entries
	for _, src := range sources {
		s.nvdSourceCache.set(src.SourceIdentifier, src.Name)
	}

	return nil
}

// buildNVDSourceUpsertQuery builds the INSERT ... ON CONFLICT query for a batch.
func buildNVDSourceUpsertQuery(sources []model.NVDSource) (string, []interface{}) {
	var sb strings.Builder
	sb.WriteString(`INSERT INTO nvd_sources (name, contact_email, source_identifier, acceptance_level, last_modified, created_at)
VALUES `)

	args := make([]interface{}, 0, len(sources)*6)
	for i, src := range sources {
		if i > 0 {
			sb.WriteString(", ")
		}
		base := i * 6
		fmt.Fprintf(&sb, "($%d, $%d, $%d, $%d, $%d, $%d)",
			base+1, base+2, base+3, base+4, base+5, base+6)

		args = append(args, src.Name, nilIfEmpty(src.ContactEmail), src.SourceIdentifier,
			nilIfEmpty(src.AcceptanceLevel), src.LastModified, src.CreatedAt)
	}

	sb.WriteString(` ON CONFLICT (source_identifier) DO UPDATE SET
		name = EXCLUDED.name,
		contact_email = EXCLUDED.contact_email,
		acceptance_level = EXCLUDED.acceptance_level,
		last_modified = EXCLUDED.last_modified,
		created_at = EXCLUDED.created_at`)

	return sb.String(), args
}

// nilIfEmpty returns nil if s is empty, otherwise returns s.
// Used to store NULL in the database instead of empty strings.
func nilIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// GetNVDSourceName retrieves the organization name for a source identifier.
// Uses the in-memory cache first; falls back to database on cache miss.
// Returns empty string if the identifier is not found.
func (s *PostgresStore) GetNVDSourceName(ctx context.Context, identifier string) (string, error) {
	if identifier == "" {
		return "", nil
	}

	// Check cache first
	if name := s.nvdSourceCache.get(identifier); name != "" {
		return name, nil
	}

	// Cache miss: query database
	var name string
	err := s.db.QueryRowContext(ctx,
		`SELECT name FROM nvd_sources WHERE source_identifier = $1`, identifier).Scan(&name)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("query nvd_sources for %q: %w", identifier, err)
	}

	// Populate cache
	s.nvdSourceCache.set(identifier, name)
	return name, nil
}

// GetNVDSourceNames retrieves organization names for multiple source identifiers.
// Uses the in-memory cache for available entries and queries the database for misses.
// Returns a map of identifier → name for all found entries.
func (s *PostgresStore) GetNVDSourceNames(ctx context.Context, identifiers []string) (map[string]string, error) {
	if len(identifiers) == 0 {
		return nil, nil
	}

	result := make(map[string]string, len(identifiers))
	var missing []string

	// Check cache first
	for _, id := range identifiers {
		if name := s.nvdSourceCache.get(id); name != "" {
			result[id] = name
		} else {
			missing = append(missing, id)
		}
	}

	if len(missing) == 0 {
		return result, nil
	}

	// Query database for cache misses
	rows, err := s.db.QueryContext(ctx,
		`SELECT source_identifier, name FROM nvd_sources WHERE source_identifier = ANY($1)`, missing)
	if err != nil {
		return nil, fmt.Errorf("query nvd_sources batch: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, fmt.Errorf("scan nvd_source: %w", err)
		}
		result[id] = name
		s.nvdSourceCache.set(id, name)
	}

	return result, rows.Err()
}

// LoadNVDSourceCache loads all NVD source mappings into the in-memory cache.
// Called once at startup or after a full sync to prime the cache.
func (s *PostgresStore) LoadNVDSourceCache(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT source_identifier, name FROM nvd_sources`)
	if err != nil {
		return fmt.Errorf("load nvd_sources cache: %w", err)
	}
	defer func() { _ = rows.Close() }()

	entries := make(map[string]string)
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			return fmt.Errorf("scan nvd_source for cache: %w", err)
		}
		entries[id] = name
	}
	if err := rows.Err(); err != nil {
		return err
	}

	s.nvdSourceCache.loadAll(entries)
	return nil
}
