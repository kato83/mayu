package vex

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/kato83/mayu/internal/sbommon"
)

func TestExport(t *testing.T) {
	now := time.Now()
	statuses := []*sbommon.FindingStatus{
		{
			VulnID:        "CVE-2024-1111",
			Purl:          "pkg:npm/foo@1.0.0",
			Status:        sbommon.FindingStatusFalsePositive,
			Justification: "not reachable",
			UpdatedAt:     now,
		},
		{
			VulnID:        "CVE-2024-2222",
			Purl:          "pkg:npm/bar@2.0.0",
			Status:        sbommon.FindingStatusOpen,
			Justification: "",
			UpdatedAt:     now,
		},
		{
			VulnID:        "CVE-2024-3333",
			Purl:          "pkg:golang/example.com/lib@1.0.0",
			Status:        sbommon.FindingStatusResolved,
			Justification: "upgraded",
			UpdatedAt:     now,
		},
		{
			VulnID:        "CVE-2024-4444",
			Purl:          "pkg:pypi/requests@2.28.0",
			Status:        sbommon.FindingStatusInTriage,
			Justification: "investigating",
			UpdatedAt:     now,
		},
	}

	doc, err := Export(statuses, ExportOptions{
		Author:     "test@example.com",
		DocumentID: "urn:test:export:001",
	})
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}

	if doc.Context != OpenVEXContext {
		t.Errorf("Context = %q, want %q", doc.Context, OpenVEXContext)
	}
	if doc.ID != "urn:test:export:001" {
		t.Errorf("ID = %q, want %q", doc.ID, "urn:test:export:001")
	}
	if doc.Author != "test@example.com" {
		t.Errorf("Author = %q, want %q", doc.Author, "test@example.com")
	}
	if len(doc.Statements) != 4 {
		t.Fatalf("len(Statements) = %d, want 4", len(doc.Statements))
	}

	// Build a map for easier assertion
	stmtMap := make(map[string]Statement)
	for _, stmt := range doc.Statements {
		stmtMap[stmt.Vulnerability.ID] = stmt
	}

	// Check status mapping
	tests := []struct {
		vulnID     string
		wantStatus string
	}{
		{"CVE-2024-1111", StatusNotAffected},
		{"CVE-2024-2222", StatusAffected},
		{"CVE-2024-3333", StatusFixed},
		{"CVE-2024-4444", StatusUnderInvestigation},
	}

	for _, tc := range tests {
		stmt, ok := stmtMap[tc.vulnID]
		if !ok {
			t.Errorf("missing statement for %s", tc.vulnID)
			continue
		}
		if stmt.Status != tc.wantStatus {
			t.Errorf("%s status = %q, want %q", tc.vulnID, stmt.Status, tc.wantStatus)
		}
	}
}

func TestExport_GroupsByVulnerability(t *testing.T) {
	statuses := []*sbommon.FindingStatus{
		{
			VulnID: "CVE-2024-1111",
			Purl:   "pkg:npm/foo@1.0.0",
			Status: sbommon.FindingStatusFalsePositive,
		},
		{
			VulnID: "CVE-2024-1111",
			Purl:   "pkg:npm/foo@2.0.0",
			Status: sbommon.FindingStatusFalsePositive,
		},
	}

	doc, err := Export(statuses, ExportOptions{Author: "test"})
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}

	// Should be grouped into 1 statement with 2 products
	if len(doc.Statements) != 1 {
		t.Fatalf("len(Statements) = %d, want 1", len(doc.Statements))
	}
	if len(doc.Statements[0].Products) != 2 {
		t.Errorf("len(Products) = %d, want 2", len(doc.Statements[0].Products))
	}
}

func TestExport_SameVulnDifferentStatus(t *testing.T) {
	statuses := []*sbommon.FindingStatus{
		{
			VulnID: "CVE-2024-1111",
			Purl:   "pkg:npm/foo@1.0.0",
			Status: sbommon.FindingStatusFalsePositive,
		},
		{
			VulnID: "CVE-2024-1111",
			Purl:   "pkg:npm/foo@2.0.0",
			Status: sbommon.FindingStatusOpen,
		},
	}

	doc, err := Export(statuses, ExportOptions{Author: "test"})
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}

	// Same vuln with different status → separate statements
	if len(doc.Statements) != 2 {
		t.Fatalf("len(Statements) = %d, want 2", len(doc.Statements))
	}
}

func TestExport_EmptyStatuses(t *testing.T) {
	_, err := Export(nil, ExportOptions{Author: "test"})
	if err == nil {
		t.Fatal("expected error for empty statuses")
	}
}

func TestExport_DefaultAuthor(t *testing.T) {
	statuses := []*sbommon.FindingStatus{
		{
			VulnID: "CVE-2024-1111",
			Purl:   "pkg:npm/foo@1.0.0",
			Status: sbommon.FindingStatusOpen,
		},
	}

	doc, err := Export(statuses, ExportOptions{})
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}
	if doc.Author != "mayu" {
		t.Errorf("Author = %q, want %q", doc.Author, "mayu")
	}
}

func TestExportJSON(t *testing.T) {
	statuses := []*sbommon.FindingStatus{
		{
			VulnID:        "CVE-2024-1111",
			Purl:          "pkg:npm/foo@1.0.0",
			Status:        sbommon.FindingStatusFalsePositive,
			Justification: "not reachable",
		},
	}

	data, err := ExportJSON(statuses, ExportOptions{
		Author:     "test@example.com",
		DocumentID: "urn:test:json:001",
	})
	if err != nil {
		t.Fatalf("ExportJSON() error = %v", err)
	}

	// Verify it's valid JSON
	var doc Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal exported JSON: %v", err)
	}

	if doc.Context != OpenVEXContext {
		t.Errorf("Context = %q, want %q", doc.Context, OpenVEXContext)
	}
	if doc.ID != "urn:test:json:001" {
		t.Errorf("ID = %q, want %q", doc.ID, "urn:test:json:001")
	}
	if len(doc.Statements) != 1 {
		t.Fatalf("len(Statements) = %d, want 1", len(doc.Statements))
	}
	if doc.Statements[0].Status != StatusNotAffected {
		t.Errorf("status = %q, want %q", doc.Statements[0].Status, StatusNotAffected)
	}
	if doc.Statements[0].Justification != "not reachable" {
		t.Errorf("justification = %q, want %q", doc.Statements[0].Justification, "not reachable")
	}
}

func TestExport_SuppressedMapsToNotAffected(t *testing.T) {
	statuses := []*sbommon.FindingStatus{
		{
			VulnID: "CVE-2024-1111",
			Purl:   "pkg:npm/foo@1.0.0",
			Status: sbommon.FindingStatusSuppressed,
		},
		{
			VulnID: "CVE-2024-2222",
			Purl:   "pkg:npm/bar@1.0.0",
			Status: sbommon.FindingStatusRiskAccepted,
		},
	}

	doc, err := Export(statuses, ExportOptions{Author: "test"})
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}

	for _, stmt := range doc.Statements {
		if stmt.Status != StatusNotAffected {
			t.Errorf("status for %s = %q, want %q", stmt.Vulnerability.ID, stmt.Status, StatusNotAffected)
		}
	}
}
