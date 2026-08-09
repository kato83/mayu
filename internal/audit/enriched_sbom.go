package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/kato83/mayu/internal/sbom"
	"github.com/kato83/mayu/internal/store"
)

// EnrichmentStore defines the interface for fetching enrichment data
// needed for enriched SBOM generation.
type EnrichmentStore interface {
	GetVulnSummariesByIDs(ctx context.Context, ids []string) (map[string]*store.VulnSummaryRow, error)
}

// EnrichedSBOMOptions controls enriched SBOM generation.
type EnrichedSBOMOptions struct {
	// OriginalData is the raw input SBOM bytes.
	OriginalData []byte

	// Format is the detected SBOM format ("CycloneDX" or "SPDX").
	Format string

	// Components is the parsed list of SBOM components.
	Components []sbom.Component

	// Findings is the audit findings from vulnerability matching.
	Findings []Finding
}

// CycloneDX vulnerability structures for enriched SBOM output.

type cdxVulnerability struct {
	ID             string        `json:"id"`
	Source         cdxSource     `json:"source"`
	Ratings        []cdxRating   `json:"ratings,omitempty"`
	Description    string        `json:"description,omitempty"`
	Recommendation string        `json:"recommendation,omitempty"`
	Affects        []cdxAffects  `json:"affects,omitempty"`
	Properties     []cdxProperty `json:"properties,omitempty"`
}

type cdxSource struct {
	Name string `json:"name"`
}

type cdxRating struct {
	Severity string `json:"severity,omitempty"`
	Method   string `json:"method,omitempty"`
}

type cdxAffects struct {
	Ref string `json:"ref"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// GenerateEnrichedSBOM produces a CycloneDX SBOM with a vulnerabilities section added.
// If the input is CycloneDX, the original JSON is preserved and the vulnerabilities key is added.
// If the input is SPDX, a new CycloneDX BOM is constructed with only the vulnerabilities section.
func GenerateEnrichedSBOM(ctx context.Context, enrichStore EnrichmentStore, opts EnrichedSBOMOptions) ([]byte, error) {
	if len(opts.Findings) == 0 {
		// No findings — return original data unchanged for CycloneDX,
		// or a minimal CycloneDX BOM for SPDX
		if opts.Format == sbom.FormatCycloneDX {
			return opts.OriginalData, nil
		}
		return buildMinimalCycloneDXWithVulns(nil)
	}

	// Collect unique vuln IDs
	vulnIDSet := make(map[string]struct{})
	for _, f := range opts.Findings {
		vulnIDSet[f.VulnID] = struct{}{}
	}
	vulnIDs := make([]string, 0, len(vulnIDSet))
	for id := range vulnIDSet {
		vulnIDs = append(vulnIDs, id)
	}

	// Batch fetch enrichment data
	summaries, err := enrichStore.GetVulnSummariesByIDs(ctx, vulnIDs)
	if err != nil {
		return nil, fmt.Errorf("fetch enrichment data: %w", err)
	}

	// Group findings by vuln ID
	grouped := make(map[string][]Finding)
	for _, f := range opts.Findings {
		grouped[f.VulnID] = append(grouped[f.VulnID], f)
	}

	// Build CycloneDX vulnerabilities
	vulns := make([]cdxVulnerability, 0, len(grouped))
	for _, vulnID := range vulnIDs {
		findings := grouped[vulnID]
		if len(findings) == 0 {
			continue
		}

		vuln := buildCDXVulnerability(vulnID, findings, summaries[vulnID])
		vulns = append(vulns, vuln)
	}

	// Produce output
	if opts.Format == sbom.FormatCycloneDX {
		return injectVulnerabilitiesIntoCycloneDX(opts.OriginalData, vulns)
	}
	return buildMinimalCycloneDXWithVulns(vulns)
}

// buildCDXVulnerability constructs a single CycloneDX vulnerability entry.
func buildCDXVulnerability(vulnID string, findings []Finding, summary *store.VulnSummaryRow) cdxVulnerability {
	vuln := cdxVulnerability{
		ID:     vulnID,
		Source: cdxSource{Name: "mayu"},
	}

	// Use first finding for description and severity
	first := findings[0]
	vuln.Description = first.Summary

	// Ratings from severity
	severity := strings.ToLower(first.Severity)
	if severity != "" && severity != "unknown" {
		vuln.Ratings = []cdxRating{
			{Severity: severity, Method: "other"},
		}
	}

	// Recommendation from fixed version
	if first.FixedVersion != "" {
		vuln.Recommendation = "Upgrade to version " + first.FixedVersion
	}

	// Affects — collect all unique purls from findings
	purlSet := make(map[string]struct{})
	for _, f := range findings {
		if f.Component.Purl != "" {
			purlSet[f.Component.Purl] = struct{}{}
		}
	}
	for purl := range purlSet {
		vuln.Affects = append(vuln.Affects, cdxAffects{Ref: purl})
	}

	// Properties from enrichment data
	if summary != nil {
		vuln.Properties = buildEnrichmentProperties(summary)
	}

	return vuln
}

// buildEnrichmentProperties builds CycloneDX properties from enrichment data.
// Properties with nil/zero values are omitted.
func buildEnrichmentProperties(summary *store.VulnSummaryRow) []cdxProperty {
	var props []cdxProperty

	if summary.EPSSScore != nil {
		props = append(props, cdxProperty{
			Name:  "mayu:epss:score",
			Value: strconv.FormatFloat(*summary.EPSSScore, 'f', -1, 64),
		})
	}
	if summary.EPSSPercentile != nil {
		props = append(props, cdxProperty{
			Name:  "mayu:epss:percentile",
			Value: strconv.FormatFloat(*summary.EPSSPercentile, 'f', -1, 64),
		})
	}
	if summary.LEVScore != nil {
		props = append(props, cdxProperty{
			Name:  "mayu:lev:score",
			Value: strconv.FormatFloat(*summary.LEVScore, 'f', -1, 64),
		})
	}
	if summary.InKEV {
		props = append(props, cdxProperty{
			Name:  "mayu:kev",
			Value: "true",
		})
	}
	if summary.SeverityWorst > 0 {
		props = append(props, cdxProperty{
			Name:  "mayu:severity:worst",
			Value: severityLabel(summary.SeverityWorst),
		})
	}

	return props
}

// injectVulnerabilitiesIntoCycloneDX takes the original CycloneDX JSON and injects
// the vulnerabilities array into it, preserving all other fields.
func injectVulnerabilitiesIntoCycloneDX(originalData []byte, vulns []cdxVulnerability) ([]byte, error) {
	// Decode original as generic map to preserve all fields
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(originalData, &doc); err != nil {
		return nil, fmt.Errorf("decode original CycloneDX: %w", err)
	}

	// Marshal vulnerabilities
	vulnsJSON, err := json.Marshal(vulns)
	if err != nil {
		return nil, fmt.Errorf("marshal vulnerabilities: %w", err)
	}

	// Add/replace vulnerabilities key
	doc["vulnerabilities"] = vulnsJSON

	return json.MarshalIndent(doc, "", "  ")
}

// buildMinimalCycloneDXWithVulns creates a minimal CycloneDX BOM with only vulnerabilities.
// Used when input is SPDX format.
func buildMinimalCycloneDXWithVulns(vulns []cdxVulnerability) ([]byte, error) {
	type minimalBOM struct {
		BOMFormat       string             `json:"bomFormat"`
		SpecVersion     string             `json:"specVersion"`
		Version         int                `json:"version"`
		Vulnerabilities []cdxVulnerability `json:"vulnerabilities,omitempty"`
	}

	bom := minimalBOM{
		BOMFormat:       "CycloneDX",
		SpecVersion:     "1.6",
		Version:         1,
		Vulnerabilities: vulns,
	}

	return json.MarshalIndent(bom, "", "  ")
}
