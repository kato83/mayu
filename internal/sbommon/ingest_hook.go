package sbommon

import (
	"context"
	"log"
)

// SBOMReEvaluator re-scans all tracked SBOM versions when new vulnerabilities
// are ingested. It runs after the ingest pipeline completes and fires webhooks
// for any newly detected findings.
type SBOMReEvaluator struct {
	store   SBOMStore
	scanner *Scanner
	logger  *log.Logger
}

// NewSBOMReEvaluator creates a new SBOMReEvaluator.
func NewSBOMReEvaluator(store SBOMStore, scanner *Scanner, logger *log.Logger) *SBOMReEvaluator {
	if logger == nil {
		logger = log.Default()
	}
	return &SBOMReEvaluator{
		store:   store,
		scanner: scanner,
		logger:  logger,
	}
}

// ReEvaluate re-scans all SBOM versions against the current vulnerability database.
// It computes diffs and returns the total number of new findings detected across
// all versions. This method is designed to be called in a goroutine after ingest.
func (r *SBOMReEvaluator) ReEvaluate(ctx context.Context, _ []string) {
	versions, err := r.store.ListAllVersions(ctx)
	if err != nil {
		r.logger.Printf("sbom re-evaluator: failed to list versions: %v", err)
		return
	}

	if len(versions) == 0 {
		return
	}

	for _, version := range versions {
		if len(version.RawSBOM) == 0 {
			continue
		}

		// Run scan
		result, err := r.scanner.ScanVersion(ctx, version)
		if err != nil {
			r.logger.Printf("sbom re-evaluator: failed to scan version %d: %v", version.ID, err)
			continue
		}

		// Get previous result for diff
		prevResult, err := r.store.GetLatestScanResult(ctx, version.ID)
		if err != nil {
			r.logger.Printf("sbom re-evaluator: failed to get previous scan for version %d: %v", version.ID, err)
		}

		// Compute diff
		diff := ComputeDiff(result, prevResult)
		result.Trigger = "ingest"
		result.NewFindings = len(diff.NewFindings)
		result.ResolvedFindings = len(diff.ResolvedFindings)

		// Store result
		_, err = r.store.CreateScanResult(ctx, result)
		if err != nil {
			r.logger.Printf("sbom re-evaluator: failed to store scan result for version %d: %v", version.ID, err)
			continue
		}

		if len(diff.NewFindings) > 0 {
			r.logger.Printf("sbom re-evaluator: version %d has %d new findings", version.ID, len(diff.NewFindings))
		}
	}
}
