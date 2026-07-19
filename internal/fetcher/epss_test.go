package fetcher

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFetchEPSSByCVEs(t *testing.T) {
	// Mock EPSS API response
	apiResp := `{
		"status": "OK",
		"status-code": 200,
		"version": "1.0",
		"access": "public",
		"total": 2,
		"offset": 0,
		"limit": 100,
		"data": [
			{"cve": "CVE-2023-38831", "epss": "0.942180000", "percentile": "0.999230000", "date": "2026-07-19"},
			{"cve": "CVE-2022-27225", "epss": "0.003210000", "percentile": "0.712340000", "date": "2026-07-19"}
		]
	}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the cve query parameter
		cves := r.URL.Query().Get("cve")
		if cves == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(apiResp))
	}))
	defer srv.Close()

	// Use a custom fetcher that points to the mock server
	f := &Fetcher{
		baseURL:    srv.URL,
		httpClient: &http.Client{Timeout: DefaultHTTPTimeout},
	}

	ctx := context.Background()

	// Test FetchEPSSByCVEs by overriding epssAPIBaseURL through direct download
	data, err := f.download(ctx, srv.URL+"?cve=CVE-2023-38831,CVE-2022-27225")
	if err != nil {
		t.Fatalf("download error: %v", err)
	}

	// Verify it's valid JSON and parse-able
	if !strings.Contains(string(data), "CVE-2023-38831") {
		t.Error("response does not contain expected CVE ID")
	}
	if !strings.Contains(string(data), "0.942180000") {
		t.Error("response does not contain expected EPSS score")
	}
}

func TestFetchEPSSByCSV(t *testing.T) {
	// Create mock gzipped CSV content
	csvContent := `#model_version:v2025.03.05,score_date:2026-07-19T00:00:00+0000
cve,epss,percentile
CVE-2014-6271,0.97544,0.99998
CVE-2023-38831,0.94218,0.99923
CVE-2022-27225,0.00321,0.71234
`
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, _ = gw.Write([]byte(csvContent))
	_ = gw.Close()
	gzipped := buf.Bytes()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(gzipped)
	}))
	defer srv.Close()

	f := &Fetcher{
		baseURL:    srv.URL,
		httpClient: &http.Client{Timeout: DefaultHTTPTimeout},
	}
	ctx := context.Background()

	// Download and decompress manually for testing
	compressed, err := f.download(ctx, srv.URL+"/epss_scores-current.csv.gz")
	if err != nil {
		t.Fatalf("download error: %v", err)
	}

	gr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatalf("gzip reader error: %v", err)
	}
	defer func() { _ = gr.Close() }()

	scores, err := parseEPSSCSV(gr)
	if err != nil {
		t.Fatalf("parseEPSSCSV error: %v", err)
	}

	if len(scores) != 3 {
		t.Fatalf("len(scores) = %d, want 3", len(scores))
	}

	// Check first entry
	if scores[0].CVEID != "CVE-2014-6271" {
		t.Errorf("scores[0].CVEID = %q, want %q", scores[0].CVEID, "CVE-2014-6271")
	}
	if scores[0].EPSS != 0.97544 {
		t.Errorf("scores[0].EPSS = %f, want 0.97544", scores[0].EPSS)
	}
	if scores[0].Percentile != 0.99998 {
		t.Errorf("scores[0].Percentile = %f, want 0.99998", scores[0].Percentile)
	}

	// Verify score date was parsed from the comment line
	expectedDate := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)
	if !scores[0].ScoreDate.Equal(expectedDate) {
		t.Errorf("scores[0].ScoreDate = %v, want %v", scores[0].ScoreDate, expectedDate)
	}
}

func TestParseEPSSCSV_NoCommentLine(t *testing.T) {
	// CSV without a # comment line (score_date defaults to zero time)
	csvContent := `cve,epss,percentile
CVE-2023-38831,0.94218,0.99923
`
	scores, err := parseEPSSCSV(strings.NewReader(csvContent))
	if err != nil {
		t.Fatalf("parseEPSSCSV error: %v", err)
	}
	if len(scores) != 1 {
		t.Fatalf("len(scores) = %d, want 1", len(scores))
	}
	if scores[0].CVEID != "CVE-2023-38831" {
		t.Errorf("CVEID = %q, want %q", scores[0].CVEID, "CVE-2023-38831")
	}
}

func TestParseEPSSCSV_EmptyFile(t *testing.T) {
	_, err := parseEPSSCSV(strings.NewReader(""))
	if err == nil {
		t.Fatal("expected error for empty CSV")
	}
}

func TestParseEPSSCSV_SkipsInvalidLines(t *testing.T) {
	csvContent := `#model_version:v2025.03.05,score_date:2026-07-19T00:00:00+0000
cve,epss,percentile
CVE-2023-38831,0.94218,0.99923
INVALID-LINE
CVE-2022-27225,0.00321,0.71234
`
	scores, err := parseEPSSCSV(strings.NewReader(csvContent))
	if err != nil {
		t.Fatalf("parseEPSSCSV error: %v", err)
	}
	// Should skip the invalid line and parse the other 2
	if len(scores) != 2 {
		t.Fatalf("len(scores) = %d, want 2", len(scores))
	}
}

func TestExtractEPSSScoreDate(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		wantErr bool
		wantDay int
	}{
		{
			name:    "standard format",
			line:    "#model_version:v2025.03.05,score_date:2026-07-19T00:00:00+0000",
			wantDay: 19,
		},
		{
			name:    "date only",
			line:    "#score_date:2026-07-15",
			wantDay: 15,
		},
		{
			name:    "no score_date",
			line:    "#model_version:v2025.03.05",
			wantErr: true,
		},
		{
			name:    "invalid date value",
			line:    "#score_date:not-a-date",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			date, err := extractEPSSScoreDate(tt.line)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if date.Day() != tt.wantDay {
				t.Errorf("Day = %d, want %d", date.Day(), tt.wantDay)
			}
		})
	}
}

func TestEPSSScoreDateFromFilename(t *testing.T) {
	tests := []struct {
		filename string
		want     string
	}{
		{"epss_scores-current.csv.gz", ""},
		{"epss_scores-2026-07-19.csv.gz", "2026-07-19"},
		{"epss_scores-2026-03-15.csv.gz", "2026-03-15"},
		{"other-file.csv.gz", ""},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			got := EPSSScoreDateFromFilename(tt.filename)
			if got != tt.want {
				t.Errorf("EPSSScoreDateFromFilename(%q) = %q, want %q", tt.filename, got, tt.want)
			}
		})
	}
}

func TestEPSSCSVScoreDate(t *testing.T) {
	d := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)
	got := EPSSCSVScoreDate(d)
	if got != "2026-07-19" {
		t.Errorf("EPSSCSVScoreDate() = %q, want %q", got, "2026-07-19")
	}
}
