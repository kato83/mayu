package parser

import (
	"errors"
	"fmt"

	"github.com/kato83/mayu/internal/model"
)

// ErrMITRENotPublished is returned when a MITRE CVE record's state is not "PUBLISHED".
// This is used for skip counting during ingestion (REJECTED/RESERVED records are expected
// to be skipped, not treated as hard errors).
var ErrMITRENotPublished = errors.New("MITRE CVE record state is not PUBLISHED")

// MITREParseResult contains the results of parsing a batch of MITRE CVE records.
type MITREParseResult struct {
	// Entries contains successfully parsed and validated MITRE CVE records.
	Entries []*model.MITRECVERecord

	// Errors contains records that failed parsing or validation.
	Errors []ParseError
}

// ParseMITRERecord parses and validates a single MITRE CVE JSON 5.x record.
// It calls model.ParseMITREEntry for basic JSON parsing, then applies
// ingestion-specific validation:
//   - cveId must match CVE-YYYY-NNNN+ pattern
//   - state must be "PUBLISHED" (REJECTED/RESERVED return ErrMITRENotPublished)
//   - datePublished should be present for PUBLISHED records (warning if missing)
//   - Must have at least one container (CNA)
//
// In strict mode, validation failures return an error immediately.
// In non-strict mode, non-PUBLISHED records return ErrMITRENotPublished,
// and other validation failures return an error after logging.
func (p *Parser) ParseMITRERecord(data []byte) (*model.MITRECVERecord, error) {
	// Delegate basic JSON parsing to the model layer.
	record, err := model.ParseMITREEntry(data)
	if err != nil {
		return nil, fmt.Errorf("parse MITRE entry: %w", err)
	}

	cveID := record.CVEMetadata.CVEID

	// Validate CVE ID format.
	if !isValidCVEID(cveID) {
		return nil, fmt.Errorf("invalid CVE ID format: %s", cveID)
	}

	// Check state: only PUBLISHED records are ingested.
	if record.CVEMetadata.State != "PUBLISHED" {
		return nil, ErrMITRENotPublished
	}

	// For PUBLISHED records, datePublished should be present.
	if record.CVEMetadata.DatePublished.Time.IsZero() {
		p.logf("MITRE CVE %s: datePublished is missing for PUBLISHED record", cveID)
	}

	// Must have at least one container (CNA).
	if record.Containers.CNA == nil {
		err := fmt.Errorf("MITRE CVE %s: missing CNA container", cveID)
		if p.Strict {
			return nil, err
		}
		p.logf("%v", err)
		return nil, err
	}

	return record, nil
}

// ParseMITREBatch parses multiple MITRE CVE JSON 5.x records.
// It iterates over the raw JSON entries, calling ParseMITRERecord on each.
// Successfully parsed records are collected into Entries; failures go to Errors.
// This method never returns a top-level error — individual failures are collected
// in the Errors slice.
func (p *Parser) ParseMITREBatch(entries [][]byte) (*MITREParseResult, error) {
	result := &MITREParseResult{}

	for i, data := range entries {
		record, err := p.ParseMITRERecord(data)
		if err != nil {
			id := fmt.Sprintf("entry[%d]", i)
			// Try to extract the CVE ID for better error reporting.
			if record != nil {
				id = record.CVEMetadata.CVEID
			} else {
				// Attempt a quick parse just for the ID.
				if partial, parseErr := model.ParseMITREEntry(data); parseErr == nil && partial.CVEMetadata.CVEID != "" {
					id = partial.CVEMetadata.CVEID
				}
			}
			result.Errors = append(result.Errors, ParseError{
				ID:    id,
				Error: err,
			})
			continue
		}
		result.Entries = append(result.Entries, record)
	}

	return result, nil
}
