package vex

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/kato83/mayu/internal/audit"
	"github.com/kato83/mayu/internal/sbommon"
)

// ImportResult holds the result of importing a VEX document.
type ImportResult struct {
	// Statuses contains the finding statuses derived from VEX statements.
	Statuses []sbommon.FindingStatus

	// TotalStatements is the number of statements processed.
	TotalStatements int

	// ImportedStatements is the number of statements successfully converted.
	ImportedStatements int
}

// vexToFindingStatus maps VEX status values to mayu finding status values.
var vexToFindingStatus = map[string]string{
	StatusNotAffected:        sbommon.FindingStatusFalsePositive,
	StatusAffected:           sbommon.FindingStatusOpen,
	StatusFixed:              sbommon.FindingStatusResolved,
	StatusUnderInvestigation: sbommon.FindingStatusInTriage,
}

// ImportFile reads a VEX document from a file path and converts it to finding statuses.
func ImportFile(path string) (*ImportResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read VEX file: %w", err)
	}
	return Import(data)
}

// Import parses a VEX document from JSON bytes and converts it to finding statuses.
func Import(data []byte) (*ImportResult, error) {
	var doc Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse VEX document: %w", err)
	}

	if err := validateDocument(&doc); err != nil {
		return nil, err
	}

	result := &ImportResult{
		TotalStatements: len(doc.Statements),
	}

	for _, stmt := range doc.Statements {
		findingStatus, ok := vexToFindingStatus[stmt.Status]
		if !ok {
			continue
		}

		for _, product := range stmt.Products {
			fs := sbommon.FindingStatus{
				VulnID:        stmt.Vulnerability.ID,
				Purl:          product.ID,
				Status:        findingStatus,
				Justification: buildJustification(stmt),
			}
			result.Statuses = append(result.Statuses, fs)
			result.ImportedStatements++
		}
	}

	return result, nil
}

// SuppressedVulnIDs extracts vulnerability IDs that have "not_affected" status
// in the VEX document. These can be used to filter audit findings.
func SuppressedVulnIDs(data []byte) (map[string]bool, error) {
	var doc Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse VEX document: %w", err)
	}

	suppressed := make(map[string]bool)
	for _, stmt := range doc.Statements {
		if stmt.Status == StatusNotAffected {
			suppressed[stmt.Vulnerability.ID] = true
		}
	}
	return suppressed, nil
}

// FilterFindingsByVEX removes findings that are suppressed by the VEX document.
// It checks both blanket vulnerability suppression and product-specific suppression.
func FilterFindingsByVEX(findings []audit.Finding, vexData []byte) ([]audit.Finding, error) {
	var doc Document
	if err := json.Unmarshal(vexData, &doc); err != nil {
		return nil, fmt.Errorf("parse VEX document: %w", err)
	}

	// Build suppression sets
	suppressedVulns := make(map[string]bool)            // vuln IDs with no products (blanket)
	suppressedPairs := make(map[string]bool)            // vuln_id|purl pairs
	suppressedVulnWithProducts := make(map[string]bool) // vuln IDs that have product-level suppression

	for _, stmt := range doc.Statements {
		if stmt.Status != StatusNotAffected {
			continue
		}
		if len(stmt.Products) == 0 {
			suppressedVulns[stmt.Vulnerability.ID] = true
		} else {
			suppressedVulnWithProducts[stmt.Vulnerability.ID] = true
			for _, product := range stmt.Products {
				key := stmt.Vulnerability.ID + "|" + product.ID
				suppressedPairs[key] = true
			}
		}
	}

	var filtered []audit.Finding
	for _, f := range findings {
		// Check blanket suppression by vuln ID or alias
		if isSuppressedByVuln(f, suppressedVulns) {
			continue
		}
		// Check product-specific suppression
		if isSuppressedByProduct(f, suppressedPairs) {
			continue
		}
		filtered = append(filtered, f)
	}
	return filtered, nil
}

// isSuppressedByVuln checks if a finding is suppressed by blanket vuln ID matching.
func isSuppressedByVuln(f audit.Finding, suppressedVulns map[string]bool) bool {
	if suppressedVulns[f.VulnID] {
		return true
	}
	for _, alias := range f.Aliases {
		if suppressedVulns[alias] {
			return true
		}
	}
	return false
}

// isSuppressedByProduct checks if a finding is suppressed by product-specific matching.
func isSuppressedByProduct(f audit.Finding, suppressedPairs map[string]bool) bool {
	if f.Component.Purl == "" {
		return false
	}
	key := f.VulnID + "|" + f.Component.Purl
	if suppressedPairs[key] {
		return true
	}
	for _, alias := range f.Aliases {
		aliasKey := alias + "|" + f.Component.Purl
		if suppressedPairs[aliasKey] {
			return true
		}
	}
	return false
}

// validateDocument performs basic validation on an OpenVEX document.
func validateDocument(doc *Document) error {
	if doc.Context == "" {
		return fmt.Errorf("VEX document missing @context field")
	}
	for i, stmt := range doc.Statements {
		if stmt.Vulnerability.ID == "" {
			return fmt.Errorf("statement[%d]: missing vulnerability ID", i)
		}
		if !ValidStatuses[stmt.Status] {
			return fmt.Errorf("statement[%d]: invalid status %q", i, stmt.Status)
		}
	}
	return nil
}

// buildJustification constructs a justification string from a VEX statement.
func buildJustification(stmt Statement) string {
	if stmt.Justification != "" && stmt.ImpactStatement != "" {
		return stmt.Justification + ": " + stmt.ImpactStatement
	}
	if stmt.Justification != "" {
		return stmt.Justification
	}
	if stmt.ImpactStatement != "" {
		return stmt.ImpactStatement
	}
	return "imported from VEX document"
}
