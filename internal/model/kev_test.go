package model

import (
	"testing"
	"time"
)

func TestParseKEVCatalog(t *testing.T) {
	data := []byte(`{
		"title": "CISA Catalog of Known Exploited Vulnerabilities",
		"catalogVersion": "2026.07.16",
		"dateReleased": "2026-07-16T17:00:15.6845Z",
		"count": 2,
		"vulnerabilities": [
			{
				"cveID": "CVE-2026-58644",
				"vendorProject": "Microsoft",
				"product": "SharePoint",
				"vulnerabilityName": "Microsoft SharePoint Deserialization Vulnerability",
				"dateAdded": "2026-07-16",
				"shortDescription": "Microsoft SharePoint contains a deserialization vulnerability.",
				"requiredAction": "Apply mitigations per vendor instructions.",
				"dueDate": "2026-07-19",
				"knownRansomwareCampaignUse": "Unknown",
				"notes": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-58644",
				"cwes": ["CWE-502"]
			},
			{
				"cveID": "CVE-2023-38831",
				"vendorProject": "RARLAB",
				"product": "WinRAR",
				"vulnerabilityName": "RARLAB WinRAR Code Execution Vulnerability",
				"dateAdded": "2023-08-23",
				"shortDescription": "RARLAB WinRAR contains a code execution vulnerability.",
				"requiredAction": "Apply mitigations per vendor instructions.",
				"dueDate": "2023-09-14",
				"knownRansomwareCampaignUse": "Known",
				"notes": "",
				"cwes": ["CWE-345"]
			}
		]
	}`)

	catalog, err := ParseKEVCatalog(data)
	if err != nil {
		t.Fatalf("ParseKEVCatalog() error = %v", err)
	}

	if catalog.Title != "CISA Catalog of Known Exploited Vulnerabilities" {
		t.Errorf("Title = %q, want %q", catalog.Title, "CISA Catalog of Known Exploited Vulnerabilities")
	}
	if catalog.CatalogVersion != "2026.07.16" {
		t.Errorf("CatalogVersion = %q, want %q", catalog.CatalogVersion, "2026.07.16")
	}
	if catalog.Count != 2 {
		t.Errorf("Count = %d, want 2", catalog.Count)
	}
	if len(catalog.Vulnerabilities) != 2 {
		t.Fatalf("len(Vulnerabilities) = %d, want 2", len(catalog.Vulnerabilities))
	}

	// Check first entry
	entry := catalog.Vulnerabilities[0]
	if entry.CVEID != "CVE-2026-58644" {
		t.Errorf("Vulnerabilities[0].CVEID = %q, want %q", entry.CVEID, "CVE-2026-58644")
	}
	if entry.VendorProject != "Microsoft" {
		t.Errorf("Vulnerabilities[0].VendorProject = %q, want %q", entry.VendorProject, "Microsoft")
	}
	if entry.Product != "SharePoint" {
		t.Errorf("Vulnerabilities[0].Product = %q, want %q", entry.Product, "SharePoint")
	}
	if entry.KnownRansomwareCampaignUse != "Unknown" {
		t.Errorf("Vulnerabilities[0].KnownRansomwareCampaignUse = %q, want %q", entry.KnownRansomwareCampaignUse, "Unknown")
	}
	if len(entry.CWEs) != 1 || entry.CWEs[0] != "CWE-502" {
		t.Errorf("Vulnerabilities[0].CWEs = %v, want [CWE-502]", entry.CWEs)
	}
	if entry.RawJSON == nil {
		t.Error("Vulnerabilities[0].RawJSON is nil, want non-nil")
	}

	// Check second entry
	entry2 := catalog.Vulnerabilities[1]
	if entry2.KnownRansomwareCampaignUse != "Known" {
		t.Errorf("Vulnerabilities[1].KnownRansomwareCampaignUse = %q, want %q", entry2.KnownRansomwareCampaignUse, "Known")
	}

	// Parse into KEVRecord
	record, err := entry.ParseKEVRecord()
	if err != nil {
		t.Fatalf("ParseKEVRecord() error = %v", err)
	}
	if record.CVEID != "CVE-2026-58644" {
		t.Errorf("CVEID = %q, want %q", record.CVEID, "CVE-2026-58644")
	}
	if record.VendorProject != "Microsoft" {
		t.Errorf("VendorProject = %q, want %q", record.VendorProject, "Microsoft")
	}
	if record.Product != "SharePoint" {
		t.Errorf("Product = %q, want %q", record.Product, "SharePoint")
	}
	expectedDateAdded := time.Date(2026, 7, 16, 0, 0, 0, 0, time.UTC)
	if !record.DateAdded.Equal(expectedDateAdded) {
		t.Errorf("DateAdded = %v, want %v", record.DateAdded, expectedDateAdded)
	}
	expectedDueDate := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)
	if !record.DueDate.Equal(expectedDueDate) {
		t.Errorf("DueDate = %v, want %v", record.DueDate, expectedDueDate)
	}
	if record.KnownRansomwareCampaignUse != "Unknown" {
		t.Errorf("KnownRansomwareCampaignUse = %q, want %q", record.KnownRansomwareCampaignUse, "Unknown")
	}
	if record.RawJSON == nil {
		t.Error("RawJSON is nil, want non-nil")
	}
}

func TestParseKEVCatalog_Empty(t *testing.T) {
	_, err := ParseKEVCatalog([]byte{})
	if err == nil {
		t.Fatal("expected error for empty data")
	}
}

func TestParseKEVCatalog_InvalidJSON(t *testing.T) {
	_, err := ParseKEVCatalog([]byte(`{invalid`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseKEVCatalog_MissingTitle(t *testing.T) {
	data := []byte(`{"catalogVersion": "2026.01.01", "vulnerabilities": []}`)
	_, err := ParseKEVCatalog(data)
	if err == nil {
		t.Fatal("expected error for missing title")
	}
}

func TestKEVEntry_ParseKEVRecord_MissingCVE(t *testing.T) {
	entry := KEVEntry{
		CVEID:             "",
		VendorProject:     "Microsoft",
		Product:           "SharePoint",
		VulnerabilityName: "Test",
		DateAdded:         "2026-01-01",
		ShortDescription:  "Test desc",
		RequiredAction:    "Apply patch",
		DueDate:           "2026-01-15",
	}
	_, err := entry.ParseKEVRecord()
	if err == nil {
		t.Fatal("expected error for missing CVE ID")
	}
}

func TestKEVEntry_ParseKEVRecord_InvalidCVE(t *testing.T) {
	entry := KEVEntry{
		CVEID:             "GHSA-xxxx",
		VendorProject:     "Microsoft",
		Product:           "SharePoint",
		VulnerabilityName: "Test",
		DateAdded:         "2026-01-01",
		ShortDescription:  "Test desc",
		RequiredAction:    "Apply patch",
		DueDate:           "2026-01-15",
	}
	_, err := entry.ParseKEVRecord()
	if err == nil {
		t.Fatal("expected error for invalid CVE ID")
	}
}

func TestKEVEntry_ParseKEVRecord_MissingVendor(t *testing.T) {
	entry := KEVEntry{
		CVEID:             "CVE-2026-1234",
		VendorProject:     "",
		Product:           "SharePoint",
		VulnerabilityName: "Test",
		DateAdded:         "2026-01-01",
		ShortDescription:  "Test desc",
		RequiredAction:    "Apply patch",
		DueDate:           "2026-01-15",
	}
	_, err := entry.ParseKEVRecord()
	if err == nil {
		t.Fatal("expected error for missing vendorProject")
	}
}

func TestKEVEntry_ParseKEVRecord_MissingProduct(t *testing.T) {
	entry := KEVEntry{
		CVEID:             "CVE-2026-1234",
		VendorProject:     "Microsoft",
		Product:           "",
		VulnerabilityName: "Test",
		DateAdded:         "2026-01-01",
		ShortDescription:  "Test desc",
		RequiredAction:    "Apply patch",
		DueDate:           "2026-01-15",
	}
	_, err := entry.ParseKEVRecord()
	if err == nil {
		t.Fatal("expected error for missing product")
	}
}

func TestKEVEntry_ParseKEVRecord_InvalidDateAdded(t *testing.T) {
	entry := KEVEntry{
		CVEID:             "CVE-2026-1234",
		VendorProject:     "Microsoft",
		Product:           "SharePoint",
		VulnerabilityName: "Test",
		DateAdded:         "invalid-date",
		ShortDescription:  "Test desc",
		RequiredAction:    "Apply patch",
		DueDate:           "2026-01-15",
	}
	_, err := entry.ParseKEVRecord()
	if err == nil {
		t.Fatal("expected error for invalid dateAdded")
	}
}

func TestKEVEntry_ParseKEVRecord_InvalidDueDate(t *testing.T) {
	entry := KEVEntry{
		CVEID:             "CVE-2026-1234",
		VendorProject:     "Microsoft",
		Product:           "SharePoint",
		VulnerabilityName: "Test",
		DateAdded:         "2026-01-01",
		ShortDescription:  "Test desc",
		RequiredAction:    "Apply patch",
		DueDate:           "not-a-date",
	}
	_, err := entry.ParseKEVRecord()
	if err == nil {
		t.Fatal("expected error for invalid dueDate")
	}
}

func TestKEVEntry_ParseKEVRecord_DefaultRansomwareUse(t *testing.T) {
	entry := KEVEntry{
		CVEID:                      "CVE-2026-1234",
		VendorProject:              "Microsoft",
		Product:                    "SharePoint",
		VulnerabilityName:          "Test Vulnerability",
		DateAdded:                  "2026-01-01",
		ShortDescription:           "Test description",
		RequiredAction:             "Apply patch",
		DueDate:                    "2026-01-15",
		KnownRansomwareCampaignUse: "",
	}
	record, err := entry.ParseKEVRecord()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if record.KnownRansomwareCampaignUse != "Unknown" {
		t.Errorf("KnownRansomwareCampaignUse = %q, want %q", record.KnownRansomwareCampaignUse, "Unknown")
	}
}

func TestKEVEntry_ParseKEVRecord_WithCWEs(t *testing.T) {
	entry := KEVEntry{
		CVEID:             "CVE-2026-1234",
		VendorProject:     "Microsoft",
		Product:           "SharePoint",
		VulnerabilityName: "Test Vulnerability",
		DateAdded:         "2026-01-01",
		ShortDescription:  "Test description",
		RequiredAction:    "Apply patch",
		DueDate:           "2026-01-15",
		CWEs:              []string{"CWE-502", "CWE-78"},
	}
	record, err := entry.ParseKEVRecord()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(record.CWEs) != 2 {
		t.Fatalf("len(CWEs) = %d, want 2", len(record.CWEs))
	}
	if record.CWEs[0] != "CWE-502" {
		t.Errorf("CWEs[0] = %q, want %q", record.CWEs[0], "CWE-502")
	}
	if record.CWEs[1] != "CWE-78" {
		t.Errorf("CWEs[1] = %q, want %q", record.CWEs[1], "CWE-78")
	}
}

func TestKEVEntry_ParseKEVRecord_LowercaseCVE(t *testing.T) {
	entry := KEVEntry{
		CVEID:             "cve-2026-1234",
		VendorProject:     "Microsoft",
		Product:           "SharePoint",
		VulnerabilityName: "Test Vulnerability",
		DateAdded:         "2026-01-01",
		ShortDescription:  "Test description",
		RequiredAction:    "Apply patch",
		DueDate:           "2026-01-15",
	}
	record, err := entry.ParseKEVRecord()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if record.CVEID != "CVE-2026-1234" {
		t.Errorf("CVEID = %q, want %q", record.CVEID, "CVE-2026-1234")
	}
}
