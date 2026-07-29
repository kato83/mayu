package vex

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/kato83/mayu/internal/sbommon"
)

// ExportOptions configures VEX document generation.
type ExportOptions struct {
	// Author is the document author identifier.
	Author string

	// DocumentID is the unique identifier for the VEX document.
	// If empty, a default ID is generated.
	DocumentID string
}

// findingStatusToVEX maps mayu finding status values to VEX status values.
var findingStatusToVEX = map[string]string{
	sbommon.FindingStatusFalsePositive: StatusNotAffected,
	sbommon.FindingStatusOpen:          StatusAffected,
	sbommon.FindingStatusResolved:      StatusFixed,
	sbommon.FindingStatusInTriage:      StatusUnderInvestigation,
	sbommon.FindingStatusSuppressed:    StatusNotAffected,
	sbommon.FindingStatusRiskAccepted:  StatusNotAffected,
}

// Export generates an OpenVEX document from a list of finding statuses.
func Export(statuses []*sbommon.FindingStatus, opts ExportOptions) (*Document, error) {
	if len(statuses) == 0 {
		return nil, fmt.Errorf("no finding statuses to export")
	}

	author := opts.Author
	if author == "" {
		author = "mayu"
	}

	docID := opts.DocumentID
	if docID == "" {
		docID = fmt.Sprintf("urn:mayu:vex:%d", time.Now().UnixNano())
	}

	doc := &Document{
		Context:   OpenVEXContext,
		ID:        docID,
		Author:    author,
		Timestamp: time.Now().UTC(),
	}

	// Group statuses by vulnerability ID to create consolidated statements
	type stmtKey struct {
		vulnID string
		status string
	}
	grouped := make(map[stmtKey]*Statement)

	for _, fs := range statuses {
		vexStatus, ok := findingStatusToVEX[fs.Status]
		if !ok {
			continue
		}

		key := stmtKey{vulnID: fs.VulnID, status: vexStatus}
		stmt, exists := grouped[key]
		if !exists {
			stmt = &Statement{
				Vulnerability: VexVulnerability{ID: fs.VulnID},
				Status:        vexStatus,
				Justification: fs.Justification,
			}
			grouped[key] = stmt
		}

		if fs.Purl != "" {
			stmt.Products = append(stmt.Products, Product{ID: fs.Purl})
		}
	}

	// Convert map to ordered slice
	for _, stmt := range grouped {
		doc.Statements = append(doc.Statements, *stmt)
	}

	return doc, nil
}

// ExportJSON generates an OpenVEX document as formatted JSON bytes.
func ExportJSON(statuses []*sbommon.FindingStatus, opts ExportOptions) ([]byte, error) {
	doc, err := Export(statuses, opts)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(doc, "", "  ")
}
