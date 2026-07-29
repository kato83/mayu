package license

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Policy defines allowed, denied, and review-required licenses.
type Policy struct {
	// Allow lists licenses that are explicitly permitted.
	Allow []string `yaml:"allow"`
	// Deny lists licenses that are explicitly prohibited.
	Deny []string `yaml:"deny"`
	// Review lists licenses that require manual review.
	Review []string `yaml:"review"`
}

// PolicyFile is the top-level structure for a license policy YAML file.
type PolicyFile struct {
	LicensePolicy Policy `yaml:"license_policy"`
}

// Violation represents a policy violation for a component.
type Violation struct {
	// Component is the component that violates the policy.
	Component ComponentLicense
	// Action is the policy action triggered ("deny" or "review").
	Action string
	// Reason describes why this is a violation.
	Reason string
}

// LoadPolicy reads and parses a license policy YAML file.
func LoadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read license policy file: %w", err)
	}

	var pf PolicyFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("parse license policy: %w", err)
	}

	return &pf.LicensePolicy, nil
}

// ParsePolicy parses policy YAML data directly (useful for testing).
func ParsePolicy(data []byte) (*Policy, error) {
	var pf PolicyFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("parse license policy: %w", err)
	}
	return &pf.LicensePolicy, nil
}

// Evaluate checks the given components against the policy and returns any violations.
// Logic:
//   - If a license is in the Deny list: violation with action "deny"
//   - If a license is in the Review list: violation with action "review"
//   - If Allow is non-empty and the license is NOT in Allow, Deny, or Review:
//     violation with action "deny" (implicit deny for unlisted licenses)
//   - If the license is in Allow: no violation
//   - If Allow is empty (no allowlist defined): only explicit deny/review applies
func (p *Policy) Evaluate(components []ComponentLicense) []Violation {
	denySet := buildSet(p.Deny)
	reviewSet := buildSet(p.Review)
	allowSet := buildSet(p.Allow)
	hasAllowList := len(p.Allow) > 0

	var violations []Violation

	for _, comp := range components {
		spdxID := comp.License.SPDXID
		if spdxID == "" {
			// Unknown/empty license
			if hasAllowList {
				violations = append(violations, Violation{
					Component: comp,
					Action:    "deny",
					Reason:    "license not detected; not in allow list",
				})
			}
			continue
		}

		normalizedID := strings.ToUpper(spdxID)

		// Check deny list
		if _, ok := denySet[normalizedID]; ok {
			violations = append(violations, Violation{
				Component: comp,
				Action:    "deny",
				Reason:    fmt.Sprintf("license %q is in deny list", spdxID),
			})
			continue
		}

		// Check review list
		if _, ok := reviewSet[normalizedID]; ok {
			violations = append(violations, Violation{
				Component: comp,
				Action:    "review",
				Reason:    fmt.Sprintf("license %q requires review", spdxID),
			})
			continue
		}

		// Check allow list (implicit deny if allowlist is present and license not listed)
		if hasAllowList {
			if _, ok := allowSet[normalizedID]; !ok {
				violations = append(violations, Violation{
					Component: comp,
					Action:    "deny",
					Reason:    fmt.Sprintf("license %q is not in allow list", spdxID),
				})
			}
		}
	}

	return violations
}

// buildSet creates a case-insensitive lookup set from a slice of strings.
func buildSet(items []string) map[string]struct{} {
	s := make(map[string]struct{}, len(items))
	for _, item := range items {
		s[strings.ToUpper(item)] = struct{}{}
	}
	return s
}
