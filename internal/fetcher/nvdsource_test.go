package fetcher

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchNVDSources(t *testing.T) {
	responseBody := `{
		"totalResults": 2,
		"sources": [
			{
				"name": "kernel.org",
				"contactEmail": "cve@kernel.org",
				"sourceIdentifiers": ["416baaa9-dc9f-4396-8d5f-8c081fb06d67"],
				"lastModified": "2024-02-20T13:15:08.140",
				"created": "2024-02-20T13:15:08.140"
			},
			{
				"name": "CISA-ADP",
				"sourceIdentifiers": ["134c704f-9b21-4f2e-91b3-4a467353bcc0"],
				"lastModified": "2024-03-01T00:00:00.000",
				"created": "2024-03-01T00:00:00.000"
			}
		]
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/json/source/2.0" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(responseBody))
	}))
	defer server.Close()

	f := New(WithNVDSourceURL(server.URL + "/rest/json/source/2.0"))

	data, err := f.FetchNVDSources(context.Background())
	if err != nil {
		t.Fatalf("FetchNVDSources() error = %v", err)
	}

	if len(data) == 0 {
		t.Fatal("FetchNVDSources() returned empty data")
	}

	// Verify we got the expected JSON
	if string(data) != responseBody {
		t.Errorf("FetchNVDSources() data mismatch")
	}
}

func TestFetchNVDSourcesHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	f := New(WithNVDSourceURL(server.URL + "/rest/json/source/2.0"))

	_, err := f.FetchNVDSources(context.Background())
	if err == nil {
		t.Fatal("FetchNVDSources() expected error for HTTP 503")
	}
}

func TestFetchNVDSourcesCancelled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a slow response
		<-r.Context().Done()
	}))
	defer server.Close()

	f := New(WithNVDSourceURL(server.URL + "/rest/json/source/2.0"))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := f.FetchNVDSources(ctx)
	if err == nil {
		t.Fatal("FetchNVDSources() expected error for cancelled context")
	}
}
