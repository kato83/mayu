package fetcher

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// createTestGzip creates gzip-compressed data from the given content.
func createTestGzip(t *testing.T, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(content); err != nil {
		t.Fatalf("write gzip: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	return buf.Bytes()
}

func TestParseNVDMeta(t *testing.T) {
	metaContent := `lastModifiedDate:2026-07-19T10:00:00-04:00
size:14108373
zipSize:1002849
gzSize:1002709
sha256:D7F1385C8423826AA903B78BCA5AD29B33253B47C093CC3E3BA0F5DB49BD2D2A
`

	meta, err := parseNVDMeta([]byte(metaContent))
	if err != nil {
		t.Fatalf("parseNVDMeta failed: %v", err)
	}

	// Verify lastModifiedDate
	expectedTime, _ := time.Parse(time.RFC3339, "2026-07-19T10:00:00-04:00")
	if !meta.LastModifiedDate.Equal(expectedTime) {
		t.Errorf("LastModifiedDate = %v, want %v", meta.LastModifiedDate, expectedTime)
	}

	// Verify size fields
	if meta.Size != 14108373 {
		t.Errorf("Size = %d, want 14108373", meta.Size)
	}
	if meta.ZipSize != 1002849 {
		t.Errorf("ZipSize = %d, want 1002849", meta.ZipSize)
	}
	if meta.GzSize != 1002709 {
		t.Errorf("GzSize = %d, want 1002709", meta.GzSize)
	}

	// Verify SHA256
	if meta.SHA256 != "D7F1385C8423826AA903B78BCA5AD29B33253B47C093CC3E3BA0F5DB49BD2D2A" {
		t.Errorf("SHA256 = %q, want D7F1385C8423826AA903B78BCA5AD29B33253B47C093CC3E3BA0F5DB49BD2D2A", meta.SHA256)
	}
}

func TestParseNVDMeta_MissingSHA256(t *testing.T) {
	metaContent := `lastModifiedDate:2026-07-19T10:00:00-04:00
size:14108373
`

	_, err := parseNVDMeta([]byte(metaContent))
	if err == nil {
		t.Fatal("expected error for missing sha256, got nil")
	}
}

func TestParseNVDMeta_InvalidSize(t *testing.T) {
	metaContent := `lastModifiedDate:2026-07-19T10:00:00-04:00
size:not_a_number
sha256:ABC123
`

	_, err := parseNVDMeta([]byte(metaContent))
	if err == nil {
		t.Fatal("expected error for invalid size, got nil")
	}
}

func TestParseNVDMeta_InvalidDate(t *testing.T) {
	metaContent := `lastModifiedDate:not-a-valid-date
size:100
sha256:ABC123
`

	_, err := parseNVDMeta([]byte(metaContent))
	if err == nil {
		t.Fatal("expected error for invalid date, got nil")
	}
}

func TestParseNVDMeta_EmptyLines(t *testing.T) {
	metaContent := `
lastModifiedDate:2026-07-19T10:00:00-04:00

size:14108373
zipSize:1002849

gzSize:1002709
sha256:ABCDEF1234567890

`

	meta, err := parseNVDMeta([]byte(metaContent))
	if err != nil {
		t.Fatalf("parseNVDMeta failed: %v", err)
	}
	if meta.SHA256 != "ABCDEF1234567890" {
		t.Errorf("SHA256 = %q, want ABCDEF1234567890", meta.SHA256)
	}
}

func TestFetchNVDMeta(t *testing.T) {
	metaContent := `lastModifiedDate:2026-07-19T10:00:00-04:00
size:14108373
zipSize:1002849
gzSize:1002709
sha256:D7F1385C8423826AA903B78BCA5AD29B33253B47C093CC3E3BA0F5DB49BD2D2A
`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/nvdcve-2.0-2024.meta":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(metaContent))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	f := New(WithHTTPClient(server.Client()))
	// Override the nvdFeedBaseURL by using downloadAndGunzip indirectly;
	// We need to test via the method, so we'll use a custom approach.
	// Since nvdFeedBaseURL is a constant, we'll test by calling download directly.

	// Instead, let's test the full FetchNVDMeta by overriding the URL through
	// a wrapper approach. Since the base URL is a constant, we test parseNVDMeta
	// separately and test the download integration via a direct test.

	// Direct integration test: download meta content from httptest server
	data, err := f.download(context.Background(), server.URL+"/nvdcve-2.0-2024.meta")
	if err != nil {
		t.Fatalf("download failed: %v", err)
	}

	meta, err := parseNVDMeta(data)
	if err != nil {
		t.Fatalf("parseNVDMeta failed: %v", err)
	}

	expectedTime, _ := time.Parse(time.RFC3339, "2026-07-19T10:00:00-04:00")
	if !meta.LastModifiedDate.Equal(expectedTime) {
		t.Errorf("LastModifiedDate = %v, want %v", meta.LastModifiedDate, expectedTime)
	}
	if meta.Size != 14108373 {
		t.Errorf("Size = %d, want 14108373", meta.Size)
	}
	if meta.SHA256 != "D7F1385C8423826AA903B78BCA5AD29B33253B47C093CC3E3BA0F5DB49BD2D2A" {
		t.Errorf("SHA256 = %q", meta.SHA256)
	}
}

func TestFetchNVDFeed(t *testing.T) {
	jsonContent := `{"format":"NVD_CVE","version":"2.0","vulnerabilities":[{"cve":{"id":"CVE-2024-1234"}}]}`
	gzData := createTestGzip(t, []byte(jsonContent))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/nvdcve-2.0-2024.json.gz":
			w.Header().Set("Content-Type", "application/gzip")
			_, _ = w.Write(gzData)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	f := New(WithHTTPClient(server.Client()))

	// Test downloadAndGunzip directly with the httptest server URL
	data, err := f.downloadAndGunzip(context.Background(), server.URL+"/nvdcve-2.0-2024.json.gz")
	if err != nil {
		t.Fatalf("downloadAndGunzip failed: %v", err)
	}

	if string(data) != jsonContent {
		t.Errorf("content mismatch:\ngot:  %q\nwant: %q", string(data), jsonContent)
	}
}

func TestFetchNVDModifiedFeed(t *testing.T) {
	jsonContent := `{"format":"NVD_CVE","version":"2.0","vulnerabilities":[{"cve":{"id":"CVE-2024-5678","vulnStatus":"Modified"}}]}`
	gzData := createTestGzip(t, []byte(jsonContent))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/nvdcve-2.0-modified.json.gz":
			w.Header().Set("Content-Type", "application/gzip")
			_, _ = w.Write(gzData)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	f := New(WithHTTPClient(server.Client()))

	// Test downloadAndGunzip for modified feed
	data, err := f.downloadAndGunzip(context.Background(), server.URL+"/nvdcve-2.0-modified.json.gz")
	if err != nil {
		t.Fatalf("downloadAndGunzip for modified feed failed: %v", err)
	}

	if string(data) != jsonContent {
		t.Errorf("content mismatch:\ngot:  %q\nwant: %q", string(data), jsonContent)
	}
}

func TestFetchNVDFeed_InvalidGzip(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return invalid data that is not gzip
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write([]byte("this is not gzip data"))
	}))
	defer server.Close()

	f := New(WithHTTPClient(server.Client()))

	_, err := f.downloadAndGunzip(context.Background(), server.URL+"/bad.json.gz")
	if err == nil {
		t.Fatal("expected error for invalid gzip data, got nil")
	}
}

func TestFetchNVDFeed_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer server.Close()

	f := New(WithHTTPClient(server.Client()))

	_, err := f.downloadAndGunzip(context.Background(), server.URL+"/nonexistent.json.gz")
	if err == nil {
		t.Fatal("expected error for 404, got nil")
	}
}

func TestNVDFeedYears(t *testing.T) {
	years := NVDFeedYears()

	if len(years) == 0 {
		t.Fatal("NVDFeedYears returned empty slice")
	}

	// First year should be 2002
	if years[0] != 2002 {
		t.Errorf("first year = %d, want 2002", years[0])
	}

	// Last year should be current year
	currentYear := time.Now().Year()
	if years[len(years)-1] != currentYear {
		t.Errorf("last year = %d, want %d", years[len(years)-1], currentYear)
	}

	// Length should be currentYear - 2002 + 1
	expectedLen := currentYear - 2002 + 1
	if len(years) != expectedLen {
		t.Errorf("len(years) = %d, want %d", len(years), expectedLen)
	}

	// Verify sequential
	for i := 1; i < len(years); i++ {
		if years[i] != years[i-1]+1 {
			t.Errorf("years not sequential at index %d: %d, %d", i, years[i-1], years[i])
		}
	}
}

func TestNVDFeedURL(t *testing.T) {
	tests := []struct {
		year int
		want string
	}{
		{2002, "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2002.json.gz"},
		{2024, "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2024.json.gz"},
		{2026, "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2026.json.gz"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("year_%d", tt.year), func(t *testing.T) {
			got := nvdFeedURL(tt.year)
			if got != tt.want {
				t.Errorf("nvdFeedURL(%d) = %q, want %q", tt.year, got, tt.want)
			}
		})
	}
}

func TestNVDMetaURL(t *testing.T) {
	tests := []struct {
		year int
		want string
	}{
		{2002, "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2002.meta"},
		{2024, "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2024.meta"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("year_%d", tt.year), func(t *testing.T) {
			got := nvdMetaURL(tt.year)
			if got != tt.want {
				t.Errorf("nvdMetaURL(%d) = %q, want %q", tt.year, got, tt.want)
			}
		})
	}
}

func TestDownloadAndGunzip_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(5 * time.Second):
			_, _ = w.Write([]byte("too slow"))
		}
	}))
	defer server.Close()

	f := New(WithHTTPClient(server.Client()))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := f.downloadAndGunzip(ctx, server.URL+"/slow.json.gz")
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}

func TestParseNVDMeta_LowercaseSHA256(t *testing.T) {
	// SHA256 value should be uppercased regardless of input
	metaContent := `lastModifiedDate:2026-01-01T00:00:00Z
size:100
sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
`

	meta, err := parseNVDMeta([]byte(metaContent))
	if err != nil {
		t.Fatalf("parseNVDMeta failed: %v", err)
	}
	if meta.SHA256 != "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789" {
		t.Errorf("SHA256 not uppercased: %q", meta.SHA256)
	}
}
