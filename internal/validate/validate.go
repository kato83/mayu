// Package validate provides shared input validation functions
// used by both the CLI and the API server.
package validate

import (
	"fmt"
	"time"
)

// DateInput checks that a date string is valid (YYYY-MM-DD or RFC3339).
func DateInput(s string) error {
	// Try RFC3339 first
	if _, err := time.Parse(time.RFC3339, s); err == nil {
		return nil
	}
	// Try YYYY-MM-DD
	if _, err := time.Parse("2006-01-02", s); err == nil {
		return nil
	}
	return fmt.Errorf("expected format YYYY-MM-DD or RFC3339 (e.g., 2024-01-15 or 2024-01-15T00:00:00Z)")
}
