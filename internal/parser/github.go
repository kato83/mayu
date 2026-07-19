package parser

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/kato83/mayu/internal/model"
)

// GitHubAdvisory represents the GitHub REST API security advisory response format.
// See: https://docs.github.com/en/rest/security-advisories/repository-advisories
type GitHubAdvisory struct {
	GHSAID          string                 `json:"ghsa_id"`
	CVEID           string                 `json:"cve_id"`
	URL             string                 `json:"url"`
	HTMLURL         string                 `json:"html_url"`
	Summary         string                 `json:"summary"`
	Description     string                 `json:"description"`
	Severity        string                 `json:"severity"`
	State           string                 `json:"state"`
	Identifiers     []GitHubIdentifier     `json:"identifiers"`
	PublishedAt     *time.Time             `json:"published_at"`
	UpdatedAt       *time.Time             `json:"updated_at"`
	WithdrawnAt     *time.Time             `json:"withdrawn_at"`
	Vulns           []GitHubVulnerability  `json:"vulnerabilities"`
	CVSSSeverities  *GitHubCVSSSeverities  `json:"cvss_severities"`
	CVSS            *GitHubCVSS            `json:"cvss"`
	CWEs            []GitHubCWE            `json:"cwes"`
	CWEIDs          []string               `json:"cwe_ids"`
	Credits         []GitHubCredit         `json:"credits"`
	CreditsDetailed []GitHubCreditDetailed `json:"credits_detailed"`
}

// GitHubIdentifier represents a GHSA or CVE identifier.
type GitHubIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// GitHubVulnerability represents an affected package in GitHub advisory format.
type GitHubVulnerability struct {
	Package                GitHubPackage `json:"package"`
	VulnerableVersionRange string        `json:"vulnerable_version_range"`
	PatchedVersions        string        `json:"patched_versions"`
	VulnerableFunctions    []string      `json:"vulnerable_functions"`
}

// GitHubPackage represents a package in GitHub advisory format.
type GitHubPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// GitHubCVSSSeverities holds CVSS v3 and v4 scores.
type GitHubCVSSSeverities struct {
	CVSSV3 *GitHubCVSSScore `json:"cvss_v3"`
	CVSSV4 *GitHubCVSSScore `json:"cvss_v4"`
}

// GitHubCVSSScore holds a CVSS vector and score.
type GitHubCVSSScore struct {
	VectorString *string  `json:"vector_string"`
	Score        *float64 `json:"score"`
}

// GitHubCVSS is the legacy cvss field.
type GitHubCVSS struct {
	VectorString *string  `json:"vector_string"`
	Score        *float64 `json:"score"`
}

// GitHubCWE represents a CWE entry.
type GitHubCWE struct {
	CWEID string `json:"cwe_id"`
	Name  string `json:"name"`
}

// GitHubCredit represents a credit entry (simple).
type GitHubCredit struct {
	Login string `json:"login"`
	Type  string `json:"type"`
}

// GitHubCreditDetailed represents a detailed credit entry.
type GitHubCreditDetailed struct {
	User struct {
		Login string `json:"login"`
	} `json:"user"`
	Type  string `json:"type"`
	State string `json:"state"`
}

// IsGitHubAdvisoryJSON detects whether the given JSON data is a GitHub REST API
// security advisory response (as opposed to OSV format).
//
// Detection heuristic: presence of "ghsa_id" top-level key.
func IsGitHubAdvisoryJSON(data []byte) bool {
	var probe struct {
		GHSAID string `json:"ghsa_id"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	return probe.GHSAID != ""
}

// ConvertGitHubToOSV converts a GitHub REST API advisory JSON response
// into an OSV-format model.Vulnerability.
func ConvertGitHubToOSV(data []byte) (*model.Vulnerability, error) {
	var adv GitHubAdvisory
	if err := json.Unmarshal(data, &adv); err != nil {
		return nil, fmt.Errorf("unmarshal GitHub advisory: %w", err)
	}

	if adv.GHSAID == "" {
		return nil, fmt.Errorf("missing ghsa_id in GitHub advisory")
	}

	vuln := &model.Vulnerability{
		SchemaVersion: "1.6.0",
		ID:            adv.GHSAID,
		Summary:       cleanMarkdown(adv.Summary),
		Details:       normalizeNewlines(adv.Description),
	}

	// Set timestamps
	if adv.UpdatedAt != nil {
		vuln.Modified = *adv.UpdatedAt
	} else if adv.PublishedAt != nil {
		vuln.Modified = *adv.PublishedAt
	} else {
		vuln.Modified = time.Now().UTC()
	}

	if adv.PublishedAt != nil {
		vuln.Published = adv.PublishedAt
	}

	if adv.WithdrawnAt != nil {
		vuln.Withdrawn = adv.WithdrawnAt
	}

	// Build aliases from identifiers (exclude the GHSA ID itself)
	for _, ident := range adv.Identifiers {
		if ident.Value != adv.GHSAID && ident.Value != "" {
			vuln.Aliases = append(vuln.Aliases, ident.Value)
		}
	}
	// Also add cve_id if not already in aliases
	if adv.CVEID != "" && !containsString(vuln.Aliases, adv.CVEID) {
		vuln.Aliases = append([]string{adv.CVEID}, vuln.Aliases...)
	}

	// Build severity from CVSS vectors
	vuln.Severity = buildSeverity(&adv)

	// Build affected packages
	vuln.Affected = buildAffected(adv.Vulns)

	// Build references
	if adv.HTMLURL != "" {
		vuln.References = append(vuln.References, model.Reference{
			Type: model.ReferenceTypeAdvisory,
			URL:  adv.HTMLURL,
		})
	}

	// Build credits
	vuln.Credits = buildCredits(&adv)

	// Serialize as OSV JSON for RawJSON storage
	osvJSON, err := json.Marshal(vuln)
	if err != nil {
		return nil, fmt.Errorf("marshal OSV JSON: %w", err)
	}
	vuln.RawJSON = osvJSON

	return vuln, nil
}

// buildSeverity extracts CVSS vectors from the advisory.
func buildSeverity(adv *GitHubAdvisory) []model.Severity {
	var severities []model.Severity

	// Try cvss_severities.cvss_v4 first (preferred)
	if adv.CVSSSeverities != nil && adv.CVSSSeverities.CVSSV4 != nil &&
		adv.CVSSSeverities.CVSSV4.VectorString != nil && *adv.CVSSSeverities.CVSSV4.VectorString != "" {
		severities = append(severities, model.Severity{
			Type:  model.SeverityTypeCVSSV4,
			Score: *adv.CVSSSeverities.CVSSV4.VectorString,
		})
	}

	// Try cvss_severities.cvss_v3
	if adv.CVSSSeverities != nil && adv.CVSSSeverities.CVSSV3 != nil &&
		adv.CVSSSeverities.CVSSV3.VectorString != nil && *adv.CVSSSeverities.CVSSV3.VectorString != "" {
		severities = append(severities, model.Severity{
			Type:  model.SeverityTypeCVSSV3,
			Score: *adv.CVSSSeverities.CVSSV3.VectorString,
		})
	}

	// Fallback to legacy cvss field
	if len(severities) == 0 && adv.CVSS != nil &&
		adv.CVSS.VectorString != nil && *adv.CVSS.VectorString != "" {
		severities = append(severities, model.Severity{
			Type:  model.SeverityTypeCVSSV3,
			Score: *adv.CVSS.VectorString,
		})
	}

	return severities
}

// buildAffected converts GitHub vulnerability entries to OSV affected packages.
func buildAffected(vulns []GitHubVulnerability) []model.Affected {
	// Group vulnerabilities by (ecosystem, name) to merge ranges
	type pkgKey struct {
		ecosystem string
		name      string
	}
	grouped := make(map[pkgKey][]model.Range)

	for _, v := range vulns {
		key := pkgKey{
			ecosystem: normalizeEcosystem(v.Package.Ecosystem),
			name:      v.Package.Name,
		}

		r := parseVersionRange(v.VulnerableVersionRange, v.PatchedVersions)
		if r != nil {
			grouped[key] = append(grouped[key], *r)
		}
	}

	var affected []model.Affected
	for key, ranges := range grouped {
		affected = append(affected, model.Affected{
			Package: model.Package{
				Ecosystem: key.ecosystem,
				Name:      key.name,
			},
			Ranges: ranges,
		})
	}

	return affected
}

// parseVersionRange converts GitHub's version range format to OSV range events.
// Examples:
//   - "6.8.0 - 6.8.5" with patched "6.8.6" → introduced=6.8.0, fixed=6.8.6
//   - ">= 1.0, < 2.0" with patched "2.0" → introduced=1.0, fixed=2.0
//   - "< 1.5.0" with patched "1.5.0" → introduced=0, fixed=1.5.0
func parseVersionRange(versionRange, patchedVersions string) *model.Range {
	if versionRange == "" && patchedVersions == "" {
		return nil
	}

	var events []model.Event

	introduced := extractIntroduced(versionRange)
	if introduced != "" {
		events = append(events, model.Event{Introduced: introduced})
	} else {
		// Default: affected from the start
		events = append(events, model.Event{Introduced: "0"})
	}

	if patchedVersions != "" {
		events = append(events, model.Event{Fixed: patchedVersions})
	}

	if len(events) == 0 {
		return nil
	}

	return &model.Range{
		Type:   model.RangeTypeEcosystem,
		Events: events,
	}
}

// extractIntroduced attempts to extract the lower bound version from
// GitHub's version range format.
func extractIntroduced(versionRange string) string {
	if versionRange == "" {
		return ""
	}

	// Format: "X.Y.Z - X.Y.Z" (dash-separated range)
	if parts := strings.SplitN(versionRange, " - ", 2); len(parts) == 2 {
		return strings.TrimSpace(parts[0])
	}

	// Format: ">= X.Y.Z, < X.Y.Z" or ">= X.Y.Z"
	for _, part := range strings.Split(versionRange, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, ">=") {
			return strings.TrimSpace(strings.TrimPrefix(part, ">="))
		}
		if strings.HasPrefix(part, ">") {
			return strings.TrimSpace(strings.TrimPrefix(part, ">"))
		}
	}

	// Format: "= X.Y.Z" (exact version)
	if strings.HasPrefix(versionRange, "=") {
		return strings.TrimSpace(strings.TrimPrefix(versionRange, "="))
	}

	return ""
}

// normalizeEcosystem capitalizes the ecosystem name to match OSV conventions.
func normalizeEcosystem(ecosystem string) string {
	// GitHub uses lowercase; OSV typically uses title case or specific names
	switch strings.ToLower(ecosystem) {
	case "npm":
		return "npm"
	case "pip":
		return "PyPI"
	case "rubygems":
		return "RubyGems"
	case "go":
		return "Go"
	case "maven":
		return "Maven"
	case "nuget":
		return "NuGet"
	case "composer":
		return "Packagist"
	case "rust", "crates.io":
		return "crates.io"
	case "pub":
		return "Pub"
	case "erlang", "hex":
		return "Hex"
	case "swift":
		return "SwiftURL"
	case "actions":
		return "GitHub Actions"
	default:
		// Title case the first letter for unknown ecosystems
		if len(ecosystem) == 0 {
			return ecosystem
		}
		return strings.ToUpper(ecosystem[:1]) + ecosystem[1:]
	}
}

// buildCredits extracts credit information from the advisory.
func buildCredits(adv *GitHubAdvisory) []model.Credit {
	var credits []model.Credit

	// Prefer credits_detailed
	for _, c := range adv.CreditsDetailed {
		if c.User.Login != "" {
			credits = append(credits, model.Credit{
				Name: c.User.Login,
				Type: mapCreditType(c.Type),
			})
		}
	}

	// Fallback to simple credits
	if len(credits) == 0 {
		for _, c := range adv.Credits {
			if c.Login != "" {
				credits = append(credits, model.Credit{
					Name: c.Login,
					Type: mapCreditType(c.Type),
				})
			}
		}
	}

	return credits
}

// mapCreditType maps GitHub credit types to OSV credit types.
func mapCreditType(ghType string) model.CreditType {
	switch strings.ToLower(ghType) {
	case "analyst", "finder", "reporter":
		return model.CreditTypeFinder
	case "coordinator":
		return model.CreditTypeCoordinator
	case "remediation_developer", "fix_developer":
		return model.CreditTypeRemediationDeveloper
	case "remediation_reviewer", "fix_reviewer":
		return model.CreditTypeRemediationReviewer
	case "remediation_verifier", "fix_verifier":
		return model.CreditTypeRemediationVerifier
	case "sponsor":
		return model.CreditTypeSponsor
	default:
		return model.CreditTypeFinder
	}
}

// cleanMarkdown removes backtick formatting from summary text.
func cleanMarkdown(s string) string {
	return strings.ReplaceAll(s, "`", "")
}

// normalizeNewlines converts \r\n to \n.
func normalizeNewlines(s string) string {
	return strings.ReplaceAll(s, "\r\n", "\n")
}

// containsString checks if a slice contains a specific string.
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
