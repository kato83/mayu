package store

import (
	"context"
	"fmt"
	"strings"
)

// ListOSVEcosystems returns all known OSV ecosystem names sorted alphabetically.
func (s *PostgresStore) ListOSVEcosystems(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT name FROM osv_ecosystems ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("query osv_ecosystems: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var ecosystems []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("scan ecosystem: %w", err)
		}
		ecosystems = append(ecosystems, name)
	}
	return ecosystems, rows.Err()
}

// UpsertOSVEcosystems inserts ecosystem names into osv_ecosystems, ignoring duplicates.
func (s *PostgresStore) UpsertOSVEcosystems(ctx context.Context, names []string) error {
	if len(names) == 0 {
		return nil
	}

	// Build batch insert with ON CONFLICT DO NOTHING
	const batchSize = 500
	for i := 0; i < len(names); i += batchSize {
		end := i + batchSize
		if end > len(names) {
			end = len(names)
		}
		batch := names[i:end]

		query := "INSERT INTO osv_ecosystems (name) VALUES "
		args := make([]interface{}, 0, len(batch))
		placeholders := make([]string, 0, len(batch))
		for j, name := range batch {
			placeholders = append(placeholders, fmt.Sprintf("($%d)", j+1))
			args = append(args, name)
		}
		query += strings.Join(placeholders, ", ") + " ON CONFLICT (name) DO NOTHING"

		if _, err := s.db.ExecContext(ctx, query, args...); err != nil {
			return fmt.Errorf("upsert osv_ecosystems: %w", err)
		}
	}
	return nil
}
