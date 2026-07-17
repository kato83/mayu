package fetcher

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListEcosystems(t *testing.T) {
	// Simulate GCS JSON API with pagination.
	page1 := gcsListResponse{
		Prefixes:      []string{"AlmaLinux/", "Alpine/", "Alpine:v3.10/", "Go/"},
		NextPageToken: "page2token",
	}
	page2 := gcsListResponse{
		Prefixes:      []string{"npm/", "PyPI/", "all/", "icons/", "[EMPTY]/"},
		NextPageToken: "",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("pageToken")
		delimiter := r.URL.Query().Get("delimiter")

		if delimiter != "/" {
			t.Errorf("expected delimiter=/, got %q", delimiter)
		}

		w.Header().Set("Content-Type", "application/json")
		var resp gcsListResponse
		if token == "" {
			resp = page1
		} else if token == "page2token" {
			resp = page2
		} else {
			http.NotFound(w, r)
			return
		}

		data, _ := json.Marshal(resp)
		_, _ = w.Write(data)
	}))
	defer server.Close()

	f := New()

	ecosystems, err := f.listEcosystems(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("ListEcosystems failed: %v", err)
	}

	expected := []string{"AlmaLinux", "Alpine", "Alpine:v3.10", "Go", "npm", "PyPI"}
	if len(ecosystems) != len(expected) {
		t.Fatalf("expected %d ecosystems, got %d: %v", len(expected), len(ecosystems), ecosystems)
	}

	for i, eco := range ecosystems {
		if eco != expected[i] {
			t.Errorf("ecosystems[%d] = %q, want %q", i, eco, expected[i])
		}
	}
}

func TestListEcosystems_ExcludesNonEcosystems(t *testing.T) {
	resp := gcsListResponse{
		Prefixes: []string{"Go/", "all/", "icons/", "[EMPTY]/", "npm/"},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		data, _ := json.Marshal(resp)
		_, _ = w.Write(data)
	}))
	defer server.Close()

	f := New()

	ecosystems, err := f.listEcosystems(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("ListEcosystems failed: %v", err)
	}

	if len(ecosystems) != 2 {
		t.Fatalf("expected 2 ecosystems, got %d: %v", len(ecosystems), ecosystems)
	}
	if ecosystems[0] != "Go" || ecosystems[1] != "npm" {
		t.Errorf("ecosystems = %v, want [Go, npm]", ecosystems)
	}
}

func TestListEcosystems_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer server.Close()

	f := New()

	_, err := f.listEcosystems(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected error for HTTP 403, got nil")
	}
}

func TestListEcosystems_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Will never respond (context should cancel)
		<-r.Context().Done()
	}))
	defer server.Close()

	f := New()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := f.listEcosystems(ctx, server.URL)
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}
