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

// cleanMarkdown removes backtick formatting from summary text.
func cleanMarkdown(s string) string {
	return strings.ReplaceAll(s, "`", "")
}

// normalizeNewlines converts \r\n to \n.
func normalizeNewlines(s string) string {
	return strings.ReplaceAll(s, "\r\n", "\n")
}

// ParseGitHubToGHSAEntry converts a GitHub REST API advisory JSON response
// into a model.GHSAEntry for storage in the dedicated ghsa_entries table.
// Unlike ConvertGitHubToOSV, this preserves the original GitHub data structure
// and stores the raw JSON as-is for full reversibility.
func ParseGitHubToGHSAEntry(data []byte) (*model.GHSAEntry, error) {
	var adv GitHubAdvisory
	if err := json.Unmarshal(data, &adv); err != nil {
		return nil, fmt.Errorf("unmarshal GitHub advisory: %w", err)
	}

	if adv.GHSAID == "" {
		return nil, fmt.Errorf("missing ghsa_id in GitHub advisory")
	}

	entry := &model.GHSAEntry{
		GHSAID:      adv.GHSAID,
		CVEID:       adv.CVEID,
		Summary:     cleanMarkdown(adv.Summary),
		Description: normalizeNewlines(adv.Description),
		Severity:    adv.Severity,
		State:       adv.State,
		HTMLURL:     adv.HTMLURL,
		PublishedAt: adv.PublishedAt,
		UpdatedAt:   adv.UpdatedAt,
		WithdrawnAt: adv.WithdrawnAt,
		RawJSON:     data,
	}

	// Extract CVSS vectors and scores
	if adv.CVSSSeverities != nil {
		if adv.CVSSSeverities.CVSSV3 != nil {
			if adv.CVSSSeverities.CVSSV3.VectorString != nil && *adv.CVSSSeverities.CVSSV3.VectorString != "" {
				entry.CVSSV3Vector = *adv.CVSSSeverities.CVSSV3.VectorString
			}
			if adv.CVSSSeverities.CVSSV3.Score != nil {
				entry.CVSSV3Score = adv.CVSSSeverities.CVSSV3.Score
			}
		}
		if adv.CVSSSeverities.CVSSV4 != nil {
			if adv.CVSSSeverities.CVSSV4.VectorString != nil && *adv.CVSSSeverities.CVSSV4.VectorString != "" {
				entry.CVSSV4Vector = *adv.CVSSSeverities.CVSSV4.VectorString
			}
			if adv.CVSSSeverities.CVSSV4.Score != nil {
				entry.CVSSV4Score = adv.CVSSSeverities.CVSSV4.Score
			}
		}
	}
	// Fallback to legacy cvss field for v3
	if entry.CVSSV3Vector == "" && adv.CVSS != nil &&
		adv.CVSS.VectorString != nil && *adv.CVSS.VectorString != "" {
		entry.CVSSV3Vector = *adv.CVSS.VectorString
		entry.CVSSV3Score = adv.CVSS.Score
	}

	// Default state
	if entry.State == "" {
		entry.State = "published"
	}

	// Build vulnerabilities (affected packages)
	for _, v := range adv.Vulns {
		entry.Vulnerabilities = append(entry.Vulnerabilities, model.GHSAVulnerability{
			Ecosystem:              normalizeEcosystem(v.Package.Ecosystem),
			PackageName:            v.Package.Name,
			VulnerableVersionRange: v.VulnerableVersionRange,
			PatchedVersions:        v.PatchedVersions,
			VulnerableFunctions:    v.VulnerableFunctions,
		})
	}

	// Build credits
	for _, c := range adv.CreditsDetailed {
		if c.User.Login != "" {
			entry.Credits = append(entry.Credits, model.GHSACredit{
				Login:      c.User.Login,
				CreditType: c.Type,
			})
		}
	}
	// Fallback to simple credits if no detailed credits
	if len(entry.Credits) == 0 {
		for _, c := range adv.Credits {
			if c.Login != "" {
				entry.Credits = append(entry.Credits, model.GHSACredit{
					Login:      c.Login,
					CreditType: c.Type,
				})
			}
		}
	}

	// Build CWEs
	for _, cwe := range adv.CWEs {
		entry.CWEs = append(entry.CWEs, model.GHSACWE{
			CWEID: cwe.CWEID,
			Name:  cwe.Name,
		})
	}
	// Fallback to cwe_ids if CWEs list is empty
	if len(entry.CWEs) == 0 && len(adv.CWEIDs) > 0 {
		for _, id := range adv.CWEIDs {
			entry.CWEs = append(entry.CWEs, model.GHSACWE{
				CWEID: id,
			})
		}
	}

	return entry, nil
}
