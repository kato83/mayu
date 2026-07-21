// Package audit provides SBOM risk analysis by matching SBOM components
// against vulnerability data stored in the local database.
package audit

import (
	"strings"

	"github.com/Masterminds/semver/v3"

	"github.com/kato83/mayu/internal/model"
)

// IsAffected determines whether the given version is affected by the vulnerability
// described in the Affected struct. It checks:
//  1. Exact match in the Versions list
//  2. Range-based match using SEMVER/ECOSYSTEM ranges (introduced/fixed/last_affected/limit)
//
// GIT-type ranges are skipped (commit hash comparison not supported).
// If the version string cannot be parsed as semver but ranges exist,
// the function returns true (fail-safe: assume affected).
func IsAffected(version string, affected model.Affected) bool {
	// Check 1: exact version match
	for _, v := range affected.Versions {
		if v == version {
			return true
		}
	}

	// Check 2: range-based match
	if len(affected.Ranges) == 0 {
		return false
	}

	for _, r := range affected.Ranges {
		switch r.Type {
		case model.RangeTypeSemVer, model.RangeTypeEcosystem:
			if isInRange(version, r) {
				return true
			}
		case model.RangeTypeGit:
			// GIT ranges use commit hashes — skip
			continue
		}
	}

	return false
}

// isInRange checks if a version falls within an OSV range definition.
// OSV ranges consist of pairs of events:
//   - introduced: start of affected range (inclusive)
//   - fixed: end of affected range (exclusive)
//   - last_affected: last known affected version (inclusive)
//   - limit: upper bound (exclusive), similar to fixed
//
// The events are processed in order to build intervals.
// A version is affected if it falls within any [introduced, fixed/limit/last_affected) interval.
func isInRange(version string, r model.Range) bool {
	ver, err := parseSemver(version)
	if err != nil {
		// Cannot parse version — fail safe (assume affected)
		return true
	}

	// Process events in order to determine affected intervals.
	// State machine: when we see "introduced", we potentially enter an affected range.
	// When we see "fixed" or "limit", we leave the affected range.
	// "last_affected" means we're affected up to and including that version.
	//
	// Important: A single range object may contain multiple introduced/fixed pairs,
	// each representing an independent interval. We track whether we've ever been
	// confirmed affected (and not subsequently fixed).
	var inRange bool
	for _, event := range r.Events {
		switch {
		case event.Introduced != "":
			intro := event.Introduced
			// "0" means "all versions from the beginning"
			if intro == "0" {
				inRange = true
			} else {
				introVer, err := parseSemver(intro)
				if err != nil {
					// Cannot parse introduced — fail safe
					inRange = true
				} else {
					// version >= introduced means we enter this interval
					if ver.Compare(introVer) >= 0 {
						inRange = true
					}
					// If version < introduced, do NOT reset inRange to false.
					// A previous interval may still apply if it wasn't closed.
				}
			}

		case event.Fixed != "":
			if inRange {
				fixedVer, err := parseSemver(event.Fixed)
				if err != nil {
					// Cannot parse fixed — stay in range (fail safe)
					continue
				}
				// version >= fixed means NOT affected by this interval
				if ver.Compare(fixedVer) >= 0 {
					inRange = false
				}
			}

		case event.LastAffected != "":
			if inRange {
				lastVer, err := parseSemver(event.LastAffected)
				if err != nil {
					// Cannot parse last_affected — stay in range (fail safe)
					continue
				}
				// version > last_affected means NOT affected
				if ver.Compare(lastVer) > 0 {
					inRange = false
				}
			}

		case event.Limit != "":
			if inRange {
				limitVer, err := parseSemver(event.Limit)
				if err != nil {
					// Cannot parse limit — stay in range (fail safe)
					continue
				}
				// version >= limit means NOT affected
				if ver.Compare(limitVer) >= 0 {
					inRange = false
				}
			}
		}
	}

	return inRange
}

// parseSemver parses a version string, tolerating common variations:
//   - Leading "v" prefix (e.g., "v1.2.3")
//   - Versions with only major.minor (e.g., "1.2" → "1.2.0")
func parseSemver(s string) (*semver.Version, error) {
	// Strip leading "v" prefix
	s = strings.TrimPrefix(s, "v")

	// Try parsing as-is first
	v, err := semver.NewVersion(s)
	if err == nil {
		return v, nil
	}

	// Try coercing (handles "1.2" → "1.2.0" etc.)
	v, err2 := semver.StrictNewVersion(s + ".0")
	if err2 == nil {
		return v, nil
	}

	return nil, err
}
