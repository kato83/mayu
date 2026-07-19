package model

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestParseMITREEntry_ValidRecord(t *testing.T) {
	data, err := os.ReadFile("../../testdata/mitre/CVE-2024-0011.json")
	if err != nil {
		t.Fatalf("failed to read test fixture: %v", err)
	}

	record, err := ParseMITREEntry(data)
	if err != nil {
		t.Fatalf("ParseMITREEntry failed: %v", err)
	}

	// Verify top-level fields
	if record.DataType != "CVE_RECORD" {
		t.Errorf("DataType = %q, want %q", record.DataType, "CVE_RECORD")
	}
	if record.DataVersion != "5.1" {
		t.Errorf("DataVersion = %q, want %q", record.DataVersion, "5.1")
	}

	// Verify cveMetadata
	meta := record.CVEMetadata
	if meta.CVEID != "CVE-2024-0011" {
		t.Errorf("CVEID = %q, want %q", meta.CVEID, "CVE-2024-0011")
	}
	if meta.AssignerOrgID != "d6c1279f-00f6-4ef7-9217-f89ffe703ec0" {
		t.Errorf("AssignerOrgID = %q, want %q", meta.AssignerOrgID, "d6c1279f-00f6-4ef7-9217-f89ffe703ec0")
	}
	if meta.State != "PUBLISHED" {
		t.Errorf("State = %q, want %q", meta.State, "PUBLISHED")
	}
	if meta.AssignerShortName != "palo_alto" {
		t.Errorf("AssignerShortName = %q, want %q", meta.AssignerShortName, "palo_alto")
	}
	if meta.DateReserved.Year() != 2023 || meta.DateReserved.Month() != 11 || meta.DateReserved.Day() != 9 {
		t.Errorf("DateReserved = %v, want 2023-11-09", meta.DateReserved.Time)
	}
	if meta.DatePublished.Year() != 2024 || meta.DatePublished.Month() != 2 || meta.DatePublished.Day() != 14 {
		t.Errorf("DatePublished = %v, want 2024-02-14", meta.DatePublished.Time)
	}
	if meta.DateUpdated.Year() != 2024 || meta.DateUpdated.Month() != 8 || meta.DateUpdated.Day() != 1 {
		t.Errorf("DateUpdated = %v, want 2024-08-01", meta.DateUpdated.Time)
	}

	// Verify CNA container
	cna := record.Containers.CNA
	if cna == nil {
		t.Fatal("CNA container is nil")
	}
	if cna.Title != "PAN-OS: Reflected Cross-Site Scripting (XSS) Vulnerability in Captive Portal" {
		t.Errorf("CNA.Title = %q", cna.Title)
	}

	// Verify affected
	if len(cna.Affected) != 1 {
		t.Fatalf("len(Affected) = %d, want 1", len(cna.Affected))
	}
	affected := cna.Affected[0]
	if affected.Vendor != "Palo Alto Networks" {
		t.Errorf("Affected[0].Vendor = %q, want %q", affected.Vendor, "Palo Alto Networks")
	}
	if affected.Product != "PAN-OS" {
		t.Errorf("Affected[0].Product = %q, want %q", affected.Product, "PAN-OS")
	}
	if affected.DefaultStatus != "unaffected" {
		t.Errorf("Affected[0].DefaultStatus = %q, want %q", affected.DefaultStatus, "unaffected")
	}
	if len(affected.Versions) != 4 {
		t.Fatalf("len(Versions) = %d, want 4", len(affected.Versions))
	}
	if affected.Versions[0].Version != "8.1" {
		t.Errorf("Versions[0].Version = %q, want %q", affected.Versions[0].Version, "8.1")
	}
	if affected.Versions[0].Status != "affected" {
		t.Errorf("Versions[0].Status = %q, want %q", affected.Versions[0].Status, "affected")
	}
	if affected.Versions[0].LessThan != "8.1.24" {
		t.Errorf("Versions[0].LessThan = %q, want %q", affected.Versions[0].LessThan, "8.1.24")
	}
	if affected.Versions[0].Changes == nil {
		t.Error("Versions[0].Changes is nil, want non-nil json.RawMessage")
	}
	if len(affected.Platforms) != 1 || affected.Platforms[0] != "Firewall" {
		t.Errorf("Affected[0].Platforms = %v, want [Firewall]", affected.Platforms)
	}
	if len(affected.Modules) != 1 || affected.Modules[0] != "captive-portal" {
		t.Errorf("Affected[0].Modules = %v, want [captive-portal]", affected.Modules)
	}

	// Verify descriptions
	if len(cna.Descriptions) != 1 {
		t.Fatalf("len(Descriptions) = %d, want 1", len(cna.Descriptions))
	}
	if cna.Descriptions[0].Lang != "en" {
		t.Errorf("Descriptions[0].Lang = %q, want %q", cna.Descriptions[0].Lang, "en")
	}
	if cna.Descriptions[0].SupportingMedia == nil {
		t.Error("Descriptions[0].SupportingMedia is nil")
	}

	// Verify metrics (CVSS v3.1)
	if len(cna.Metrics) != 1 {
		t.Fatalf("len(Metrics) = %d, want 1", len(cna.Metrics))
	}
	metric := cna.Metrics[0]
	if metric.Format != "CVSS" {
		t.Errorf("Metrics[0].Format = %q, want %q", metric.Format, "CVSS")
	}
	if len(metric.Scenarios) != 1 || metric.Scenarios[0].Value != "GENERAL" {
		t.Errorf("Metrics[0].Scenarios = %v", metric.Scenarios)
	}
	if metric.CvssV3_1 == nil {
		t.Fatal("Metrics[0].CvssV3_1 is nil")
	}
	var cvssData map[string]interface{}
	if err := json.Unmarshal(metric.CvssV3_1, &cvssData); err != nil {
		t.Fatalf("CvssV3_1 is not valid JSON: %v", err)
	}
	if cvssData["baseScore"] != 4.3 {
		t.Errorf("cvssV3_1.baseScore = %v, want 4.3", cvssData["baseScore"])
	}
	if cvssData["baseSeverity"] != "MEDIUM" {
		t.Errorf("cvssV3_1.baseSeverity = %v, want MEDIUM", cvssData["baseSeverity"])
	}

	// Verify problemTypes
	if len(cna.ProblemTypes) != 1 {
		t.Fatalf("len(ProblemTypes) = %d, want 1", len(cna.ProblemTypes))
	}
	if len(cna.ProblemTypes[0].Descriptions) != 1 {
		t.Fatalf("len(ProblemTypes[0].Descriptions) = %d, want 1", len(cna.ProblemTypes[0].Descriptions))
	}
	pt := cna.ProblemTypes[0].Descriptions[0]
	if pt.Type != "CWE" {
		t.Errorf("ProblemTypes[0].Descriptions[0].Type = %q, want %q", pt.Type, "CWE")
	}
	if pt.CWEID != "CWE-79" {
		t.Errorf("ProblemTypes[0].Descriptions[0].CWEID = %q, want %q", pt.CWEID, "CWE-79")
	}

	// Verify references
	if len(cna.References) != 1 {
		t.Fatalf("len(References) = %d, want 1", len(cna.References))
	}
	if cna.References[0].URL != "https://security.paloaltonetworks.com/CVE-2024-0011" {
		t.Errorf("References[0].URL = %q", cna.References[0].URL)
	}
	if len(cna.References[0].Tags) != 1 || cna.References[0].Tags[0] != "vendor-advisory" {
		t.Errorf("References[0].Tags = %v, want [vendor-advisory]", cna.References[0].Tags)
	}

	// Verify credits
	if len(cna.Credits) != 1 {
		t.Fatalf("len(Credits) = %d, want 1", len(cna.Credits))
	}
	if cna.Credits[0].Type != "finder" {
		t.Errorf("Credits[0].Type = %q, want %q", cna.Credits[0].Type, "finder")
	}
	if cna.Credits[0].Value != "Darek Jensen of Corelight" {
		t.Errorf("Credits[0].Value = %q", cna.Credits[0].Value)
	}

	// Verify solutions, workarounds, exploits, configurations
	if len(cna.Solutions) != 1 {
		t.Errorf("len(Solutions) = %d, want 1", len(cna.Solutions))
	}
	if len(cna.Workarounds) != 1 {
		t.Errorf("len(Workarounds) = %d, want 1", len(cna.Workarounds))
	}
	if len(cna.Exploits) != 1 {
		t.Errorf("len(Exploits) = %d, want 1", len(cna.Exploits))
	}
	if len(cna.Configurations) != 1 {
		t.Errorf("len(Configurations) = %d, want 1", len(cna.Configurations))
	}

	// Verify source (json.RawMessage)
	if cna.Source == nil {
		t.Fatal("CNA.Source is nil")
	}
	var source map[string]interface{}
	if err := json.Unmarshal(cna.Source, &source); err != nil {
		t.Fatalf("Source is not valid JSON: %v", err)
	}
	if source["discovery"] != "EXTERNAL" {
		t.Errorf("source.discovery = %v, want EXTERNAL", source["discovery"])
	}

	// Verify timeline
	if len(cna.Timeline) != 1 {
		t.Fatalf("len(Timeline) = %d, want 1", len(cna.Timeline))
	}
	if cna.Timeline[0].Value != "Initial publication" {
		t.Errorf("Timeline[0].Value = %q, want %q", cna.Timeline[0].Value, "Initial publication")
	}

	// Verify providerMetadata
	if cna.ProviderMetadata.OrgID != "d6c1279f-00f6-4ef7-9217-f89ffe703ec0" {
		t.Errorf("ProviderMetadata.OrgID = %q", cna.ProviderMetadata.OrgID)
	}
	if cna.ProviderMetadata.ShortName != "palo_alto" {
		t.Errorf("ProviderMetadata.ShortName = %q, want %q", cna.ProviderMetadata.ShortName, "palo_alto")
	}

	// Verify ADP container
	if len(record.Containers.ADP) != 1 {
		t.Fatalf("len(ADP) = %d, want 1", len(record.Containers.ADP))
	}
	adp := record.Containers.ADP[0]
	if adp.Title != "CISA ADP Vulnrichment" {
		t.Errorf("ADP[0].Title = %q, want %q", adp.Title, "CISA ADP Vulnrichment")
	}
	if adp.ProviderMetadata.ShortName != "CISA-ADP" {
		t.Errorf("ADP[0].ProviderMetadata.ShortName = %q, want %q", adp.ProviderMetadata.ShortName, "CISA-ADP")
	}
	if len(adp.Metrics) != 1 {
		t.Fatalf("len(ADP[0].Metrics) = %d, want 1", len(adp.Metrics))
	}
	if adp.Metrics[0].Other == nil {
		t.Fatal("ADP[0].Metrics[0].Other is nil")
	}
	if len(adp.References) != 1 {
		t.Fatalf("len(ADP[0].References) = %d, want 1", len(adp.References))
	}
}

func TestParseMITREEntry_EmptyData(t *testing.T) {
	_, err := ParseMITREEntry([]byte{})
	if err == nil {
		t.Error("expected error for empty data, got nil")
	}
	if err.Error() != "empty data" {
		t.Errorf("error = %q, want %q", err.Error(), "empty data")
	}
}

func TestParseMITREEntry_MissingCVEID(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "empty cveMetadata",
			data: []byte(`{"dataType": "CVE_RECORD", "dataVersion": "5.1", "cveMetadata": {}, "containers": {}}`),
		},
		{
			name: "cveId is empty string",
			data: []byte(`{"dataType": "CVE_RECORD", "dataVersion": "5.1", "cveMetadata": {"cveId": ""}, "containers": {}}`),
		},
		{
			name: "no cveMetadata field",
			data: []byte(`{"dataType": "CVE_RECORD", "dataVersion": "5.1", "containers": {}}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseMITREEntry(tt.data)
			if err == nil {
				t.Error("expected error, got nil")
			}
			expected := "MITRE CVE record missing required field: cveMetadata.cveId"
			if err.Error() != expected {
				t.Errorf("error = %q, want %q", err.Error(), expected)
			}
		})
	}
}

func TestParseMITREEntry_RawJSONPreserved(t *testing.T) {
	data, err := os.ReadFile("../../testdata/mitre/CVE-2024-0011.json")
	if err != nil {
		t.Fatalf("failed to read test fixture: %v", err)
	}

	record, err := ParseMITREEntry(data)
	if err != nil {
		t.Fatalf("ParseMITREEntry failed: %v", err)
	}

	// RawJSON must be populated
	if record.RawJSON == nil {
		t.Fatal("RawJSON is nil")
	}

	// RawJSON must not be empty
	if len(record.RawJSON) == 0 {
		t.Fatal("RawJSON is empty")
	}

	// Verify it's valid JSON
	if !json.Valid(record.RawJSON) {
		t.Fatal("RawJSON is not valid JSON")
	}

	// Verify RawJSON is compact (should be shorter than the indented source)
	if len(record.RawJSON) >= len(data) {
		t.Errorf("RawJSON len (%d) should be less than source len (%d) due to compaction", len(record.RawJSON), len(data))
	}

	// Verify RawJSON can be re-parsed to the same struct
	var reparsed MITRECVERecord
	if err := json.Unmarshal(record.RawJSON, &reparsed); err != nil {
		t.Fatalf("failed to re-parse RawJSON: %v", err)
	}
	if reparsed.CVEMetadata.CVEID != record.CVEMetadata.CVEID {
		t.Errorf("re-parsed CVEID = %q, want %q", reparsed.CVEMetadata.CVEID, record.CVEMetadata.CVEID)
	}
	if reparsed.DataType != record.DataType {
		t.Errorf("re-parsed DataType = %q, want %q", reparsed.DataType, record.DataType)
	}
	if reparsed.DataVersion != record.DataVersion {
		t.Errorf("re-parsed DataVersion = %q, want %q", reparsed.DataVersion, record.DataVersion)
	}
}

func TestMITRETime_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantYear int
		wantMon  time.Month
		wantDay  int
		wantHour int
		wantMin  int
		wantSec  int
	}{
		{
			name:     "RFC3339 with milliseconds and Z",
			input:    `"2024-02-14T17:32:34.809Z"`,
			wantYear: 2024, wantMon: 2, wantDay: 14,
			wantHour: 17, wantMin: 32, wantSec: 34,
		},
		{
			name:     "RFC3339 without milliseconds",
			input:    `"2024-02-14T17:32:34Z"`,
			wantYear: 2024, wantMon: 2, wantDay: 14,
			wantHour: 17, wantMin: 32, wantSec: 34,
		},
		{
			name:     "RFC3339 with timezone offset",
			input:    `"2024-02-14T17:32:34+00:00"`,
			wantYear: 2024, wantMon: 2, wantDay: 14,
			wantHour: 17, wantMin: 32, wantSec: 34,
		},
		{
			name:     "RFC3339 with non-UTC offset",
			input:    `"2024-02-14T09:32:34-08:00"`,
			wantYear: 2024, wantMon: 2, wantDay: 14,
			wantHour: 17, wantMin: 32, wantSec: 34,
		},
		{
			name:     "without timezone (assumed UTC)",
			input:    `"2024-02-14T17:32:34.809"`,
			wantYear: 2024, wantMon: 2, wantDay: 14,
			wantHour: 17, wantMin: 32, wantSec: 34,
		},
		{
			name:     "without milliseconds and without timezone",
			input:    `"2024-02-14T17:32:34"`,
			wantYear: 2024, wantMon: 2, wantDay: 14,
			wantHour: 17, wantMin: 32, wantSec: 34,
		},
		{
			name:     "milliseconds with fewer digits",
			input:    `"2023-11-09T18:56:10.4Z"`,
			wantYear: 2023, wantMon: 11, wantDay: 9,
			wantHour: 18, wantMin: 56, wantSec: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mt MITRETime
			if err := mt.UnmarshalJSON([]byte(tt.input)); err != nil {
				t.Fatalf("UnmarshalJSON(%s) failed: %v", tt.input, err)
			}
			if mt.Year() != tt.wantYear {
				t.Errorf("year = %d, want %d", mt.Year(), tt.wantYear)
			}
			if mt.Month() != tt.wantMon {
				t.Errorf("month = %v, want %v", mt.Month(), tt.wantMon)
			}
			if mt.Day() != tt.wantDay {
				t.Errorf("day = %d, want %d", mt.Day(), tt.wantDay)
			}
			if mt.Hour() != tt.wantHour {
				t.Errorf("hour = %d, want %d", mt.Hour(), tt.wantHour)
			}
			if mt.Minute() != tt.wantMin {
				t.Errorf("minute = %d, want %d", mt.Minute(), tt.wantMin)
			}
			if mt.Second() != tt.wantSec {
				t.Errorf("second = %d, want %d", mt.Second(), tt.wantSec)
			}
			// All times should be stored as UTC
			if mt.Location() != time.UTC {
				t.Errorf("location = %v, want UTC", mt.Location())
			}
		})
	}
}

func TestMITRETime_UnmarshalJSON_Empty(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "empty string", input: `""`},
		{name: "null", input: `null`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mt MITRETime
			if err := mt.UnmarshalJSON([]byte(tt.input)); err != nil {
				t.Fatalf("UnmarshalJSON(%s) returned error: %v", tt.input, err)
			}
			if !mt.IsZero() {
				t.Errorf("expected zero time, got %v", mt.Time)
			}
		})
	}
}

func TestMITRETime_MarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		time MITRETime
		want string
	}{
		{
			name: "zero time",
			time: MITRETime{},
			want: `null`,
		},
		{
			name: "specific time",
			time: MITRETime{Time: time.Date(2024, 2, 14, 17, 32, 34, 809000000, time.UTC)},
			want: `"2024-02-14T17:32:34.809Z"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.time.MarshalJSON()
			if err != nil {
				t.Fatalf("MarshalJSON failed: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("MarshalJSON = %s, want %s", string(got), tt.want)
			}
		})
	}
}

func TestParseMITREEntry_InvalidJSON(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "invalid JSON",
			data: []byte(`{invalid json`),
		},
		{
			name: "array instead of object",
			data: []byte(`[1, 2, 3]`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseMITREEntry(tt.data)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}
