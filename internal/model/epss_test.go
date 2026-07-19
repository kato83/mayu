package model

import (
	"testing"
	"time"
)

func TestParseEPSSAPIResponse(t *testing.T) {
	data := []byte(`{
		"status": "OK",
		"status-code": 200,
		"version": "1.0",
		"access": "public",
		"total": 2,
		"offset": 0,
		"limit": 100,
		"data": [
			{
				"cve": "CVE-2023-38831",
				"epss": "0.942180000",
				"percentile": "0.999230000",
				"date": "2026-07-19"
			},
			{
				"cve": "CVE-2022-27225",
				"epss": "0.003210000",
				"percentile": "0.712340000",
				"date": "2026-07-19"
			}
		]
	}`)

	resp, err := ParseEPSSAPIResponse(data)
	if err != nil {
		t.Fatalf("ParseEPSSAPIResponse() error = %v", err)
	}

	if resp.Status != "OK" {
		t.Errorf("Status = %q, want %q", resp.Status, "OK")
	}
	if resp.Total != 2 {
		t.Errorf("Total = %d, want 2", resp.Total)
	}
	if len(resp.Data) != 2 {
		t.Fatalf("len(Data) = %d, want 2", len(resp.Data))
	}

	// Check first entry
	entry := resp.Data[0]
	if entry.CVE != "CVE-2023-38831" {
		t.Errorf("Data[0].CVE = %q, want %q", entry.CVE, "CVE-2023-38831")
	}
	if entry.EPSS != "0.942180000" {
		t.Errorf("Data[0].EPSS = %q, want %q", entry.EPSS, "0.942180000")
	}
	if entry.RawJSON == nil {
		t.Error("Data[0].RawJSON is nil, want non-nil")
	}

	// Parse into EPSSScore
	score, err := entry.ParseEPSSScore()
	if err != nil {
		t.Fatalf("ParseEPSSScore() error = %v", err)
	}
	if score.CVEID != "CVE-2023-38831" {
		t.Errorf("CVEID = %q, want %q", score.CVEID, "CVE-2023-38831")
	}
	if score.EPSS != 0.94218 {
		t.Errorf("EPSS = %f, want 0.94218", score.EPSS)
	}
	if score.Percentile != 0.99923 {
		t.Errorf("Percentile = %f, want 0.99923", score.Percentile)
	}
	expectedDate := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)
	if !score.ScoreDate.Equal(expectedDate) {
		t.Errorf("ScoreDate = %v, want %v", score.ScoreDate, expectedDate)
	}
}

func TestParseEPSSAPIResponse_NonOK(t *testing.T) {
	data := []byte(`{"status": "ERROR", "status-code": 400}`)
	_, err := ParseEPSSAPIResponse(data)
	if err == nil {
		t.Fatal("expected error for non-OK status")
	}
}

func TestParseEPSSAPIResponse_Empty(t *testing.T) {
	_, err := ParseEPSSAPIResponse([]byte{})
	if err == nil {
		t.Fatal("expected error for empty data")
	}
}

func TestEPSSEntry_ParseEPSSScore_MissingCVE(t *testing.T) {
	entry := EPSSEntry{CVE: "", EPSS: "0.5", Percentile: "0.5", Date: "2026-01-01"}
	_, err := entry.ParseEPSSScore()
	if err == nil {
		t.Fatal("expected error for missing CVE")
	}
}

func TestEPSSEntry_ParseEPSSScore_InvalidCVE(t *testing.T) {
	entry := EPSSEntry{CVE: "GHSA-xxxx", EPSS: "0.5", Percentile: "0.5", Date: "2026-01-01"}
	_, err := entry.ParseEPSSScore()
	if err == nil {
		t.Fatal("expected error for invalid CVE ID")
	}
}

func TestEPSSEntry_ParseEPSSScore_InvalidEPSS(t *testing.T) {
	entry := EPSSEntry{CVE: "CVE-2023-1234", EPSS: "not-a-number", Percentile: "0.5", Date: "2026-01-01"}
	_, err := entry.ParseEPSSScore()
	if err == nil {
		t.Fatal("expected error for invalid EPSS score")
	}
}

func TestEPSSEntry_ParseEPSSScore_OutOfRange(t *testing.T) {
	entry := EPSSEntry{CVE: "CVE-2023-1234", EPSS: "1.5", Percentile: "0.5", Date: "2026-01-01"}
	_, err := entry.ParseEPSSScore()
	if err == nil {
		t.Fatal("expected error for out-of-range EPSS score")
	}
}

func TestEPSSEntry_ParseEPSSScore_InvalidDate(t *testing.T) {
	entry := EPSSEntry{CVE: "CVE-2023-1234", EPSS: "0.5", Percentile: "0.5", Date: "invalid"}
	_, err := entry.ParseEPSSScore()
	if err == nil {
		t.Fatal("expected error for invalid date")
	}
}

func TestParseEPSSCSVLine(t *testing.T) {
	scoreDate := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		line     string
		wantCVE  string
		wantEPSS float64
		wantPerc float64
		wantErr  bool
	}{
		{
			name:     "valid line",
			line:     "CVE-2023-38831,0.94218,0.99923",
			wantCVE:  "CVE-2023-38831",
			wantEPSS: 0.94218,
			wantPerc: 0.99923,
		},
		{
			name:     "lowercase cve",
			line:     "cve-2023-38831,0.94218,0.99923",
			wantCVE:  "CVE-2023-38831",
			wantEPSS: 0.94218,
			wantPerc: 0.99923,
		},
		{
			name:    "too few fields",
			line:    "CVE-2023-38831,0.94218",
			wantErr: true,
		},
		{
			name:    "invalid CVE",
			line:    "GHSA-xxxx,0.5,0.5",
			wantErr: true,
		},
		{
			name:    "invalid EPSS",
			line:    "CVE-2023-1234,notanumber,0.5",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, err := ParseEPSSCSVLine(tt.line, scoreDate)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if score.CVEID != tt.wantCVE {
				t.Errorf("CVEID = %q, want %q", score.CVEID, tt.wantCVE)
			}
			if score.EPSS != tt.wantEPSS {
				t.Errorf("EPSS = %f, want %f", score.EPSS, tt.wantEPSS)
			}
			if score.Percentile != tt.wantPerc {
				t.Errorf("Percentile = %f, want %f", score.Percentile, tt.wantPerc)
			}
			if score.RawJSON == nil {
				t.Error("RawJSON is nil, want non-nil")
			}
		})
	}
}
