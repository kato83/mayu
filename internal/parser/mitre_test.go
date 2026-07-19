package parser

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestParseMITRERecord_Published(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "mitre", "CVE-2024-0011.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	p := New()
	record, err := p.ParseMITRERecord(data)
	if err != nil {
		t.Fatalf("ParseMITRERecord returned error: %v", err)
	}

	if record.CVEMetadata.CVEID != "CVE-2024-0011" {
		t.Errorf("CVEID = %q, want %q", record.CVEMetadata.CVEID, "CVE-2024-0011")
	}
	if record.CVEMetadata.State != "PUBLISHED" {
		t.Errorf("State = %q, want %q", record.CVEMetadata.State, "PUBLISHED")
	}
	if record.Containers.CNA == nil {
		t.Fatal("CNA container is nil")
	}
	if record.Containers.CNA.Title == "" {
		t.Error("CNA title is empty")
	}
	if record.CVEMetadata.DatePublished.IsZero() {
		t.Error("DatePublished is zero")
	}
	if len(record.RawJSON) == 0 {
		t.Error("RawJSON is empty")
	}
}

func TestParseMITRERecord_Rejected(t *testing.T) {
	data := []byte(`{
		"dataType": "CVE_RECORD",
		"dataVersion": "5.1",
		"cveMetadata": {
			"cveId": "CVE-2024-9999",
			"assignerOrgId": "test-org",
			"state": "REJECTED"
		},
		"containers": {}
	}`)

	p := New()
	_, err := p.ParseMITRERecord(data)
	if err == nil {
		t.Fatal("expected error for REJECTED record, got nil")
	}
	if !errors.Is(err, ErrMITRENotPublished) {
		t.Errorf("error = %v, want ErrMITRENotPublished", err)
	}
}

func TestParseMITRERecord_Reserved(t *testing.T) {
	data := []byte(`{
		"dataType": "CVE_RECORD",
		"dataVersion": "5.0",
		"cveMetadata": {
			"cveId": "CVE-2024-8888",
			"assignerOrgId": "test-org",
			"state": "RESERVED"
		},
		"containers": {}
	}`)

	p := New()
	_, err := p.ParseMITRERecord(data)
	if err == nil {
		t.Fatal("expected error for RESERVED record, got nil")
	}
	if !errors.Is(err, ErrMITRENotPublished) {
		t.Errorf("error = %v, want ErrMITRENotPublished", err)
	}
}

func TestParseMITRERecord_InvalidCVEID(t *testing.T) {
	data := []byte(`{
		"dataType": "CVE_RECORD",
		"dataVersion": "5.1",
		"cveMetadata": {
			"cveId": "INVALID-ID",
			"assignerOrgId": "test-org",
			"state": "PUBLISHED"
		},
		"containers": {
			"cna": {
				"descriptions": [{"lang": "en", "value": "test"}]
			}
		}
	}`)

	p := New()
	_, err := p.ParseMITRERecord(data)
	if err == nil {
		t.Fatal("expected error for invalid CVE ID, got nil")
	}
	if errors.Is(err, ErrMITRENotPublished) {
		t.Error("should not be ErrMITRENotPublished for invalid CVE ID")
	}
}

func TestParseMITRERecord_EmptyData(t *testing.T) {
	p := New()
	_, err := p.ParseMITRERecord([]byte{})
	if err == nil {
		t.Fatal("expected error for empty data, got nil")
	}
}

func TestParseMITREBatch(t *testing.T) {
	validData, err := os.ReadFile(filepath.Join("..", "..", "testdata", "mitre", "CVE-2024-0011.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	rejectedData := []byte(`{
		"dataType": "CVE_RECORD",
		"dataVersion": "5.1",
		"cveMetadata": {
			"cveId": "CVE-2024-7777",
			"assignerOrgId": "test-org",
			"state": "REJECTED"
		},
		"containers": {}
	}`)

	invalidData := []byte(`{not valid json}`)

	entries := [][]byte{validData, rejectedData, invalidData}

	p := New()
	result, err := p.ParseMITREBatch(entries)
	if err != nil {
		t.Fatalf("ParseMITREBatch returned error: %v", err)
	}

	if len(result.Entries) != 1 {
		t.Errorf("Entries count = %d, want 1", len(result.Entries))
	}
	if len(result.Errors) != 2 {
		t.Errorf("Errors count = %d, want 2", len(result.Errors))
	}

	// Verify the successful entry.
	if len(result.Entries) > 0 && result.Entries[0].CVEMetadata.CVEID != "CVE-2024-0011" {
		t.Errorf("Entries[0].CVEID = %q, want %q", result.Entries[0].CVEMetadata.CVEID, "CVE-2024-0011")
	}

	// Verify the rejected entry error references the correct CVE ID.
	foundRejected := false
	for _, pe := range result.Errors {
		if pe.ID == "CVE-2024-7777" && errors.Is(pe.Error, ErrMITRENotPublished) {
			foundRejected = true
		}
	}
	if !foundRejected {
		t.Error("expected REJECTED entry error with CVE-2024-7777 ID")
	}
}

func TestParseMITREBatch_AllValid(t *testing.T) {
	validData, err := os.ReadFile(filepath.Join("..", "..", "testdata", "mitre", "CVE-2024-0011.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	entries := [][]byte{validData, validData, validData}

	p := New()
	result, err := p.ParseMITREBatch(entries)
	if err != nil {
		t.Fatalf("ParseMITREBatch returned error: %v", err)
	}

	if len(result.Entries) != 3 {
		t.Errorf("Entries count = %d, want 3", len(result.Entries))
	}
	if len(result.Errors) != 0 {
		t.Errorf("Errors count = %d, want 0", len(result.Errors))
	}

	for i, entry := range result.Entries {
		if entry.CVEMetadata.CVEID != "CVE-2024-0011" {
			t.Errorf("Entries[%d].CVEID = %q, want %q", i, entry.CVEMetadata.CVEID, "CVE-2024-0011")
		}
	}
}
