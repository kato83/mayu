package sbommon

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"
)

// FindingExpirer handles automatic reopening of expired finding statuses.
// When a finding status has an expires_at date in the past, it is automatically
// reset to "open" status to ensure timely re-triage.
type FindingExpirer struct {
	db     *sql.DB
	logger *log.Logger
}

// NewFindingExpirer creates a new FindingExpirer.
func NewFindingExpirer(db *sql.DB, logger *log.Logger) *FindingExpirer {
	if logger == nil {
		logger = log.Default()
	}
	return &FindingExpirer{db: db, logger: logger}
}

// ExpireFindings finds all finding statuses with expires_at < NOW() and
// status != 'open', resets them to 'open', and creates audit log entries.
// Returns the number of findings that were reopened.
func (e *FindingExpirer) ExpireFindings(ctx context.Context) (int, error) {
	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Find all expired non-open statuses.
	rows, err := tx.QueryContext(ctx, `
		SELECT id, version_id, vuln_id, purl, status, updated_by
		FROM sbom_finding_statuses
		WHERE expires_at IS NOT NULL
		  AND expires_at < NOW()
		  AND status != 'open'`)
	if err != nil {
		return 0, fmt.Errorf("query expired findings: %w", err)
	}

	type expiredFinding struct {
		ID        int64
		VersionID int64
		VulnID    string
		Purl      string
		OldStatus string
		UpdatedBy int64
	}

	var expired []expiredFinding
	for rows.Next() {
		var f expiredFinding
		if err := rows.Scan(&f.ID, &f.VersionID, &f.VulnID, &f.Purl, &f.OldStatus, &f.UpdatedBy); err != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("scan expired finding: %w", err)
		}
		expired = append(expired, f)
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterate expired findings: %w", err)
	}
	_ = rows.Close()

	if len(expired) == 0 {
		return 0, nil
	}

	now := time.Now().UTC()

	// Reset each expired finding to 'open' and create audit log.
	for _, f := range expired {
		// Update status to open and clear expires_at.
		_, err := tx.ExecContext(ctx, `
			UPDATE sbom_finding_statuses
			SET status = 'open', justification = 'auto-reopened: status expired', updated_at = $2, expires_at = NULL
			WHERE id = $1`,
			f.ID, now)
		if err != nil {
			return 0, fmt.Errorf("reset finding %d: %w", f.ID, err)
		}

		// Create audit log entry.
		_, err = tx.ExecContext(ctx, `
			INSERT INTO sbom_finding_status_log (finding_status_id, old_status, new_status, justification, changed_by, changed_at)
			VALUES ($1, $2, 'open', 'auto-reopened: status expired', $3, $4)`,
			f.ID, f.OldStatus, f.UpdatedBy, now)
		if err != nil {
			return 0, fmt.Errorf("log finding %d expiry: %w", f.ID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit expired findings: %w", err)
	}

	e.logger.Printf("finding-expirer: reopened %d expired finding(s)", len(expired))
	return len(expired), nil
}

// RunPeriodicExpiry starts a background goroutine that runs ExpireFindings
// at the specified interval. It stops when the context is cancelled.
func (e *FindingExpirer) RunPeriodicExpiry(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run once immediately at startup.
	if _, err := e.ExpireFindings(ctx); err != nil {
		e.logger.Printf("finding-expirer: initial run error: %v", err)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := e.ExpireFindings(ctx); err != nil {
				e.logger.Printf("finding-expirer: error: %v", err)
			}
		}
	}
}
