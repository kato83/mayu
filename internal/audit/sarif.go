package audit

import (
	"encoding/json"
	"fmt"
)

// SARIF schema constants.
const (
	sarifVersion   = "2.1.0"
	sarifSchemaURI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
)

// sarifLog is the top-level SARIF document structure.
type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

// sarifRun represents a single analysis run.
type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

// sarifTool describes the analysis tool.
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

// sarifDriver describes the tool driver (name, version, rules).
type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules"`
}

// sarifRule describes a reporting descriptor (one per unique vuln ID).
type sarifRule struct {
	ID               string              `json:"id"`
	ShortDescription sarifMessage        `json:"shortDescription"`
	HelpURI          string              `json:"helpUri"`
	Properties       sarifRuleProperties `json:"properties"`
}

// sarifRuleProperties holds additional rule metadata.
type sarifRuleProperties struct {
	SecuritySeverity string `json:"security-severity"`
}

// sarifResult represents a single finding.
type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	RuleIndex int             `json:"ruleIndex"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

// sarifLocation represents a location associated with a result.
type sarifLocation struct {
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations"`
}

// sarifLogicalLocation identifies a logical construct (e.g., a package).
type sarifLogicalLocation struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// sarifMessage holds message text.
type sarifMessage struct {
	Text string `json:"text"`
}

// GenerateSARIF produces a SARIF v2.1.0 JSON document from an AuditResult.
// The toolVersion parameter is embedded in the SARIF tool.driver.version field.
func GenerateSARIF(result *AuditResult, toolVersion string) ([]byte, error) {
	// Build rules (one per unique vuln ID) and a map for rule index lookup.
	ruleIndex := make(map[string]int)
	var rules []sarifRule

	for _, f := range result.Findings {
		if _, exists := ruleIndex[f.VulnID]; exists {
			continue
		}
		idx := len(rules)
		ruleIndex[f.VulnID] = idx

		rules = append(rules, sarifRule{
			ID:               f.VulnID,
			ShortDescription: sarifMessage{Text: f.Summary},
			HelpURI:          fmt.Sprintf("https://osv.dev/vulnerability/%s", f.VulnID),
			Properties: sarifRuleProperties{
				SecuritySeverity: securitySeverityValue(f.SeverityLevel),
			},
		})
	}

	// Build results (one per finding).
	var results []sarifResult
	for _, f := range result.Findings {
		results = append(results, sarifResult{
			RuleID:    f.VulnID,
			RuleIndex: ruleIndex[f.VulnID],
			Level:     sarifLevel(f.SeverityLevel),
			Message: sarifMessage{
				Text: fmt.Sprintf("Vulnerability %s found in %s@%s: %s",
					f.VulnID, f.Component.Name, f.Component.Version, f.Summary),
			},
			Locations: []sarifLocation{
				{
					LogicalLocations: []sarifLogicalLocation{
						{
							Name: fmt.Sprintf("%s@%s", f.Component.Name, f.Component.Version),
							Kind: "package",
						},
					},
				},
			},
		})
	}

	// Ensure non-nil slices for valid JSON output.
	if rules == nil {
		rules = []sarifRule{}
	}
	if results == nil {
		results = []sarifResult{}
	}

	log := sarifLog{
		Version: sarifVersion,
		Schema:  sarifSchemaURI,
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "mayu",
						InformationURI: "https://github.com/kato83/mayu",
						Version:        toolVersion,
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal SARIF: %w", err)
	}
	return data, nil
}

// securitySeverityValue maps a SeverityLevel to the numeric string used in
// SARIF rule properties for GitHub Security tab integration.
func securitySeverityValue(level int) string {
	switch level {
	case 5:
		return "9.0"
	case 4:
		return "7.0"
	case 3:
		return "4.0"
	case 2:
		return "2.0"
	default:
		return "0.0"
	}
}

// sarifLevel maps a SeverityLevel to the SARIF result level string.
func sarifLevel(level int) string {
	switch level {
	case 5, 4:
		return "error"
	case 3:
		return "warning"
	default:
		return "note"
	}
}
