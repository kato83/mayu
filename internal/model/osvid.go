// Package model provides osv_id normalization logic for ecosystems whose
// OSV data uses bare CVE IDs instead of proper prefixed identifiers.
//
// Per the OSV schema specification (https://ossf.github.io/osv-schema/#id-modified-fields),
// the id field should be of the format <DB>-<ENTRYID>. However, some ecosystems
// (notably Debian Security Tracker) serve data via GCS with bare CVE-* IDs.
//
// mayu normalizes these IDs internally to prevent PK collisions in osv_entries,
// while preserving the original ID in raw_json for reversibility.
package model

import "strings"

// osvEcosystemPrefix maps ecosystem name prefixes to their OSV DB prefix.
// This is used to normalize bare CVE-* IDs from ecosystems that should use a prefix.
//
// Source: https://ossf.github.io/osv-schema/#id-modified-fields
var osvEcosystemPrefix = map[string]string{
	"Debian": "DEBIAN",
	// Add other ecosystems here if GCS data is found to use bare CVE IDs.
	// Ubuntu already uses UBUNTU-CVE-* prefix correctly.
	// Alpine uses ALPINE-* prefix correctly.
}

// NormalizeOSVID ensures that an osv_id follows the <DB>-<ENTRYID> format.
// If the raw ID is a bare CVE-* and the ecosystem has a defined OSV prefix,
// the prefix is prepended (e.g., "CVE-2024-1234" → "DEBIAN-CVE-2024-1234").
//
// If the ID already has a non-CVE prefix, it is returned as-is.
// This prevents double-prefixing if upstream later fixes their data.
//
// Parameters:
//   - rawID: the original osv_id from the OSV JSON
//   - ecosystem: the ecosystem string from affected[0].package.ecosystem (may include
//     version suffix like "Debian:11")
//
// Returns the normalized osv_id for storage in osv_entries.osv_id.
func NormalizeOSVID(rawID string, ecosystem string) string {
	// If the ID doesn't start with "CVE-", it already has a proper prefix
	if !strings.HasPrefix(rawID, "CVE-") {
		return rawID
	}

	// Extract the base ecosystem name (before any ':' version suffix)
	baseEcosystem := ecosystem
	if idx := strings.IndexByte(ecosystem, ':'); idx >= 0 {
		baseEcosystem = ecosystem[:idx]
	}

	// Look up the prefix for this ecosystem
	prefix, ok := osvEcosystemPrefix[baseEcosystem]
	if !ok {
		// No prefix defined for this ecosystem; return as-is.
		// This handles the case where CVE IDs ARE the canonical ID
		// (e.g., cve-osv-conversion bucket where the ecosystem is implicit).
		return rawID
	}

	return prefix + "-" + rawID
}

// ExtractEcosystemFromAffected extracts the ecosystem string from a Vulnerability's
// first affected package. Returns empty string if no affected packages exist.
func ExtractEcosystemFromAffected(vuln *Vulnerability) string {
	if len(vuln.Affected) == 0 {
		return ""
	}
	return vuln.Affected[0].Package.Ecosystem
}
