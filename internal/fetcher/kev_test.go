package fetcher

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchKEVCatalog(t *testing.T) {
	// Mock KEV catalog JSON response
	catalogResp := `{
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
	}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(catalogResp))
	}))
	defer srv.Close()

	f := &Fetcher{
		baseURL:    srv.URL,
		httpClient: &http.Client{Timeout: DefaultHTTPTimeout},
	}

	ctx := context.Background()

	catalog, err := f.FetchKEVCatalogFromURL(ctx, srv.URL+"/known_exploited_vulnerabilities.json")
	if err != nil {
		t.Fatalf("FetchKEVCatalogFromURL() error = %v", err)
	}

	if catalog.Title != "CISA Catalog of Known Exploited Vulnerabilities" {
		t.Errorf("Title = %q, want %q", catalog.Title, "CISA Catalog of Known Exploited Vulnerabilities")
	}
	if catalog.Count != 2 {
		t.Errorf("Count = %d, want 2", catalog.Count)
	}
	if len(catalog.Vulnerabilities) != 2 {
		t.Fatalf("len(Vulnerabilities) = %d, want 2", len(catalog.Vulnerabilities))
	}

	// Verify first entry
	entry := catalog.Vulnerabilities[0]
	if entry.CVEID != "CVE-2026-58644" {
		t.Errorf("Vulnerabilities[0].CVEID = %q, want %q", entry.CVEID, "CVE-2026-58644")
	}
	if entry.VendorProject != "Microsoft" {
		t.Errorf("Vulnerabilities[0].VendorProject = %q, want %q", entry.VendorProject, "Microsoft")
	}
	if entry.RawJSON == nil {
		t.Error("Vulnerabilities[0].RawJSON is nil, want non-nil")
	}

	// Verify records can be parsed
	record, err := entry.ParseKEVRecord()
	if err != nil {
		t.Fatalf("ParseKEVRecord() error = %v", err)
	}
	if record.CVEID != "CVE-2026-58644" {
		t.Errorf("record.CVEID = %q, want %q", record.CVEID, "CVE-2026-58644")
	}
}

func TestFetchKEVCatalog_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	f := &Fetcher{
		baseURL:    srv.URL,
		httpClient: &http.Client{Timeout: DefaultHTTPTimeout},
	}

	ctx := context.Background()
	_, err := f.FetchKEVCatalogFromURL(ctx, srv.URL+"/not-found.json")
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
}

func TestFetchKEVCatalog_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{invalid json`))
	}))
	defer srv.Close()

	f := &Fetcher{
		baseURL:    srv.URL,
		httpClient: &http.Client{Timeout: DefaultHTTPTimeout},
	}

	ctx := context.Background()
	_, err := f.FetchKEVCatalogFromURL(ctx, srv.URL+"/bad.json")
	if err == nil {
		t.Fatal("expected error for invalid JSON response")
	}
}

func TestFetchKEVCatalog_EmptyResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte{})
	}))
	defer srv.Close()

	f := &Fetcher{
		baseURL:    srv.URL,
		httpClient: &http.Client{Timeout: DefaultHTTPTimeout},
	}

	ctx := context.Background()
	_, err := f.FetchKEVCatalogFromURL(ctx, srv.URL+"/empty.json")
	if err == nil {
		t.Fatal("expected error for empty response")
	}
}
