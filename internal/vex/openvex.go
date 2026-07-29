// Package vex provides OpenVEX document import and export functionality.
// It implements the OpenVEX specification (https://github.com/openvex/spec)
// for Vulnerability Exploitability eXchange (VEX) documents.
package vex

import "time"

// OpenVEX context URI as defined by the specification.
const OpenVEXContext = "https://openvex.dev/ns/v0.2.0"

// VEX status values as defined by the OpenVEX specification.
const (
	StatusNotAffected        = "not_affected"
	StatusAffected           = "affected"
	StatusFixed              = "fixed"
	StatusUnderInvestigation = "under_investigation"
)

// Document represents an OpenVEX document.
type Document struct {
	Context    string      `json:"@context"`
	ID         string      `json:"@id"`
	Author     string      `json:"author"`
	Timestamp  time.Time   `json:"timestamp"`
	Statements []Statement `json:"statements"`
}

// Statement represents a single VEX statement within a document.
type Statement struct {
	Vulnerability   VexVulnerability `json:"vulnerability"`
	Products        []Product        `json:"products"`
	Status          string           `json:"status"`
	Justification   string           `json:"justification,omitempty"`
	ImpactStatement string           `json:"impact_statement,omitempty"`
}

// VexVulnerability identifies a vulnerability in a VEX statement.
type VexVulnerability struct {
	ID string `json:"@id"`
}

// Product identifies a product (typically by purl) in a VEX statement.
type Product struct {
	ID string `json:"@id"`
}

// ValidStatuses is the set of valid VEX status values.
var ValidStatuses = map[string]bool{
	StatusNotAffected:        true,
	StatusAffected:           true,
	StatusFixed:              true,
	StatusUnderInvestigation: true,
}
