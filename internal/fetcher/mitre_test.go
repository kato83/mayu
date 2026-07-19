package fetcher

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// createMITRETestZip creates an in-memory zip archive with CVE entries
// matching the MITRE cves/ directory structure.
func createMITRETestZip(t *testing.T, cves map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	for cveID, content := range cves {
		// Build path: cves/YYYY/NNNNxxx/CVE-YYYY-NNNN.json
		// Extract year and number from CVE ID (e.g., CVE-2024-1234)
		var year, num int
		_, err := fmt.Sscanf(cveID, "CVE-%d-%d", &year, &num)
		if err != nil {
			t.Fatalf("invalid CVE ID format %q: %v", cveID, err)
		}
		// NNNNxxx bucket: e.g., 1234 -> 1xxx, 12345 -> 12xxx
		bucket := fmt.Sprintf("%dxxx", num/1000)
		path := fmt.Sprintf("cves/%d/%s/%s.json", year, bucket, cveID)

		f, err := w.Create(path)
		if err != nil {
			t.Fatalf("create zip file %s: %v", path, err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatalf("write zip file %s: %v", path, err)
		}
	}

	// Add a non-CVE file to verify filtering.
	f, err := w.Create("README.md")
	if err != nil {
		t.Fatalf("create README.md: %v", err)
	}
	if _, err := f.Write([]byte("not a CVE")); err != nil {
		t.Fatalf("write README.md: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}
	return buf.Bytes()
}

func TestMITREBaselineURL(t *testing.T) {
	tests := []struct {
		date    string
		wantURL string
		wantTag string
	}{
		{
			date:    "2026-07-19",
			wantURL: "https://github.com/CVEProject/cvelistV5/releases/download/cve_2026-07-19_0000Z/2026-07-19_all_CVEs_at_midnight.zip",
			wantTag: "cve_2026-07-19_0000Z",
		},
		{
			date:    "2024-01-01",
			wantURL: "https://github.com/CVEProject/cvelistV5/releases/download/cve_2024-01-01_0000Z/2024-01-01_all_CVEs_at_midnight.zip",
			wantTag: "cve_2024-01-01_0000Z",
		},
		{
			date:    "2025-12-31",
			wantURL: "https://github.com/CVEProject/cvelistV5/releases/download/cve_2025-12-31_0000Z/2025-12-31_all_CVEs_at_midnight.zip",
			wantTag: "cve_2025-12-31_0000Z",
		},
	}

	for _, tt := range tests {
		t.Run(tt.date, func(t *testing.T) {
			gotURL := mitreBaselineURL(tt.date)
			if gotURL != tt.wantURL {
				t.Errorf("mitreBaselineURL(%q) = %q, want %q", tt.date, gotURL, tt.wantURL)
			}
			gotTag := mitreBaselineTag(tt.date)
			if gotTag != tt.wantTag {
				t.Errorf("mitreBaselineTag(%q) = %q, want %q", tt.date, gotTag, tt.wantTag)
			}
		})
	}
}

func TestMITREDeltaURL(t *testing.T) {
	tests := []struct {
		date    string
		hour    int
		wantURL string
		wantTag string
	}{
		{
			date:    "2026-07-19",
			hour:    6,
			wantURL: "https://github.com/CVEProject/cvelistV5/releases/download/cve_2026-07-19_0600Z/2026-07-19_delta_CVEs_at_0600Z.zip",
			wantTag: "cve_2026-07-19_0600Z",
		},
		{
			date:    "2024-03-15",
			hour:    14,
			wantURL: "https://github.com/CVEProject/cvelistV5/releases/download/cve_2024-03-15_1400Z/2024-03-15_delta_CVEs_at_1400Z.zip",
			wantTag: "cve_2024-03-15_1400Z",
		},
		{
			date:    "2025-11-01",
			hour:    23,
			wantURL: "https://github.com/CVEProject/cvelistV5/releases/download/cve_2025-11-01_2300Z/2025-11-01_delta_CVEs_at_2300Z.zip",
			wantTag: "cve_2025-11-01_2300Z",
		},
	}

	for _, tt := range tests {
		name := fmt.Sprintf("%s_%02d", tt.date, tt.hour)
		t.Run(name, func(t *testing.T) {
			gotURL := mitreDeltaURL(tt.date, tt.hour)
			if gotURL != tt.wantURL {
				t.Errorf("mitreDeltaURL(%q, %d) = %q, want %q", tt.date, tt.hour, gotURL, tt.wantURL)
			}
			gotTag := mitreDeltaTag(tt.date, tt.hour)
			if gotTag != tt.wantTag {
				t.Errorf("mitreDeltaTag(%q, %d) = %q, want %q", tt.date, tt.hour, gotTag, tt.wantTag)
			}
		})
	}
}

func TestFindMITRELatestMidnightTag(t *testing.T) {
	// Build a mock GitHub API response with a mix of midnight and hourly releases.
	releases := []mitreRelease{
		{
			TagName:     "cve_2026-07-19_1400Z",
			PublishedAt: time.Date(2026, 7, 19, 14, 0, 0, 0, time.UTC),
			Assets: []mitreReleaseAsset{
				{Name: "2026-07-19_delta_CVEs_at_1400Z.zip", BrowserDownloadURL: "https://example.com/delta.zip"},
				{Name: "2026-07-19_all_CVEs_at_midnight.zip.zip", BrowserDownloadURL: "https://example.com/baseline-latest.zip"},
			},
		},
		{
			TagName:     "cve_2026-07-19_0000Z",
			PublishedAt: time.Date(2026, 7, 19, 0, 5, 0, 0, time.UTC),
			Assets: []mitreReleaseAsset{
				{Name: "2026-07-18_all_CVEs_at_midnight.zip.zip", BrowserDownloadURL: "https://example.com/baseline.zip"},
			},
		},
		{
			TagName:     "cve_2026-07-18_0000Z",
			PublishedAt: time.Date(2026, 7, 18, 0, 5, 0, 0, time.UTC),
			Assets: []mitreReleaseAsset{
				{Name: "2026-07-18_all_CVEs_at_midnight.zip.zip", BrowserDownloadURL: "https://example.com/old-baseline.zip"},
			},
		},
	}

	releasesJSON, err := json.Marshal(releases)
	if err != nil {
		t.Fatalf("marshal releases: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(releasesJSON)
	}))
	defer server.Close()

	f := &Fetcher{
		httpClient: &http.Client{
			Transport: &mitreTestTransport{
				handler: func(req *http.Request) (*http.Response, error) {
					req.URL.Scheme = "http"
					req.URL.Host = server.Listener.Addr().String()
					req.URL.Path = "/"
					req.URL.RawQuery = ""
					return http.DefaultTransport.RoundTrip(req)
				},
			},
		},
	}

	// FindMITRELatestMidnightTag still works (returns first midnight tag)
	tag, date, err := f.FindMITRELatestMidnightTag(context.Background())
	if err != nil {
		t.Fatalf("FindMITRELatestMidnightTag failed: %v", err)
	}

	if tag != "cve_2026-07-19_0000Z" {
		t.Errorf("tag = %q, want %q", tag, "cve_2026-07-19_0000Z")
	}
	if date != "2026-07-19" {
		t.Errorf("date = %q, want %q", date, "2026-07-19")
	}

	// FindMITREBaselineURL returns the first baseline asset URL found
	baselineURL, err := f.FindMITREBaselineURL(context.Background())
	if err != nil {
		t.Fatalf("FindMITREBaselineURL failed: %v", err)
	}
	if baselineURL != "https://example.com/baseline-latest.zip" {
		t.Errorf("baselineURL = %q, want %q", baselineURL, "https://example.com/baseline-latest.zip")
	}
}

// mitreTestTransport is a custom http.RoundTripper for testing.
type mitreTestTransport struct {
	handler func(*http.Request) (*http.Response, error)
}

func (t *mitreTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.handler(req)
}

func TestStreamMITREBaselineZip(t *testing.T) {
	cve1 := `{"cveMetadata":{"cveId":"CVE-2024-1234"},"containers":{}}`
	cve2 := `{"cveMetadata":{"cveId":"CVE-2024-5678"},"containers":{}}`

	zipData := createMITRETestZip(t, map[string]string{
		"CVE-2024-1234": cve1,
		"CVE-2024-5678": cve2,
	})

	// Single test server that handles both the releases API and the zip download.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/CVEProject/cvelistV5/releases":
			// BrowserDownloadURL uses a relative-like path that our transport will resolve.
			releases := []mitreRelease{
				{
					TagName:     "cve_2026-07-19_1400Z",
					PublishedAt: time.Now().UTC(),
					Assets: []mitreReleaseAsset{
						{
							Name:               "2026-07-19_all_CVEs_at_midnight.zip.zip",
							BrowserDownloadURL: "http://test-server/baseline.zip",
						},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(releases)
		case "/baseline.zip":
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(zipData)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	// Create a fetcher whose HTTP client redirects all requests to our test server.
	f := &Fetcher{
		httpClient: &http.Client{
			Transport: &mitreTestTransport{
				handler: func(req *http.Request) (*http.Response, error) {
					// Rewrite any request to go to our test server, preserving the path.
					req.URL.Scheme = "http"
					req.URL.Host = server.Listener.Addr().String()
					return http.DefaultTransport.RoundTrip(req)
				},
			},
		},
	}

	entries, errCh, err := f.StreamMITREBaselineZip(context.Background())
	if err != nil {
		t.Fatalf("StreamMITREBaselineZip failed: %v", err)
	}

	// Collect all entries.
	results := make(map[string]string)
	for entry := range entries {
		results[entry.Name] = string(entry.Data)
	}

	// Check for streaming errors.
	if streamErr := <-errCh; streamErr != nil {
		t.Fatalf("stream error: %v", streamErr)
	}

	// Verify results.
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d: %v", len(results), results)
	}
	if results["CVE-2024-1234"] != cve1 {
		t.Errorf("CVE-2024-1234 content mismatch: got %q", results["CVE-2024-1234"])
	}
	if results["CVE-2024-5678"] != cve2 {
		t.Errorf("CVE-2024-5678 content mismatch: got %q", results["CVE-2024-5678"])
	}
}

func TestStreamMITREBaselineZip_FiltersNonCVE(t *testing.T) {
	// Verify that non-CVE files (README, etc.) are filtered out.
	cve1 := `{"cveMetadata":{"cveId":"CVE-2024-9999"}}`

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	// Valid CVE entry.
	f1, _ := w.Create("cves/2024/9xxx/CVE-2024-9999.json")
	_, _ = f1.Write([]byte(cve1))

	// Non-CVE entries that should be filtered.
	f2, _ := w.Create("README.md")
	_, _ = f2.Write([]byte("readme"))
	f3, _ := w.Create("other/file.json")
	_, _ = f3.Write([]byte(`{}`))
	f4, _ := w.Create("cves/metadata.txt")
	_, _ = f4.Write([]byte("metadata"))

	_ = w.Close()
	zipData := buf.Bytes()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/CVEProject/cvelistV5/releases":
			releases := []mitreRelease{
				{
					TagName:     "cve_2026-07-19_1400Z",
					PublishedAt: time.Now().UTC(),
					Assets: []mitreReleaseAsset{
						{
							Name:               "2026-07-19_all_CVEs_at_midnight.zip.zip",
							BrowserDownloadURL: "http://test-server/baseline.zip",
						},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(releases)
		case "/baseline.zip":
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(zipData)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	fetcher := &Fetcher{
		httpClient: &http.Client{
			Transport: &mitreTestTransport{
				handler: func(req *http.Request) (*http.Response, error) {
					req.URL.Scheme = "http"
					req.URL.Host = server.Listener.Addr().String()
					return http.DefaultTransport.RoundTrip(req)
				},
			},
		},
	}

	entries, errCh, err := fetcher.StreamMITREBaselineZip(context.Background())
	if err != nil {
		t.Fatalf("StreamMITREBaselineZip failed: %v", err)
	}

	results := make(map[string]string)
	for entry := range entries {
		results[entry.Name] = string(entry.Data)
	}
	if streamErr := <-errCh; streamErr != nil {
		t.Fatalf("stream error: %v", streamErr)
	}

	// Only the valid CVE entry should come through.
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d: %v", len(results), results)
	}
	if _, ok := results["CVE-2024-9999"]; !ok {
		t.Error("expected CVE-2024-9999 in results")
	}
}

func TestIsMITRECVEEntry(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"valid CVE path", "cves/2024/1xxx/CVE-2024-1234.json", true},
		{"valid deep path", "cves/2025/99xxx/CVE-2025-99001.json", true},
		{"no cves prefix", "other/2024/1xxx/CVE-2024-1234.json", false},
		{"not json", "cves/2024/1xxx/CVE-2024-1234.txt", false},
		{"readme in cves", "cves/README.md", false},
		{"empty", "", false},
		{"just cves/", "cves/", false},
		{"cves with json suffix", "cves/file.json", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isMITRECVEEntry(tt.path)
			if got != tt.want {
				t.Errorf("isMITRECVEEntry(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
