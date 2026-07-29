// Package license provides license compliance checking for SBOM components.
// It extracts license information from CycloneDX and SPDX documents, normalizes
// license identifiers to SPDX IDs, and evaluates them against a policy file.
package license

// Category represents a license category.
type Category string

const (
	// Permissive licenses allow redistribution with minimal restrictions.
	Permissive Category = "permissive"
	// WeakCopyleft licenses require sharing modifications to the library itself.
	WeakCopyleft Category = "weak-copyleft"
	// StrongCopyleft licenses require sharing the entire derivative work.
	StrongCopyleft Category = "strong-copyleft"
	// Commercial licenses are proprietary or require a commercial agreement.
	Commercial Category = "commercial"
	// Unknown is used when the license cannot be categorized.
	Unknown Category = "unknown"
)

// Info holds information about a detected license.
type Info struct {
	// SPDXID is the normalized SPDX identifier (e.g., "MIT").
	SPDXID string
	// Name is the human-readable license name.
	Name string
	// Category classifies the license type.
	Category Category
}

// ComponentLicense associates a component with its license.
type ComponentLicense struct {
	// Purl is the Package URL of the component.
	Purl string
	// Name is the package name.
	Name string
	// Version is the package version.
	Version string
	// License is the detected license information.
	License Info
}

// LookupSPDX returns the Info for a given SPDX ID, or an Unknown entry if not found.
func LookupSPDX(spdxID string) Info {
	if info, ok := spdxLicenses[spdxID]; ok {
		return info
	}
	return Info{
		SPDXID:   spdxID,
		Name:     spdxID,
		Category: Unknown,
	}
}
