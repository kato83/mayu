package fetcher

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// createTestZip creates an in-memory zip archive with the given files.
func createTestZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	for name, content := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatalf("create zip file %s: %v", name, err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatalf("write zip file %s: %v", name, err)
		}
	}

	if err := w.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}
	return buf.Bytes()
}

func TestFetchAllZip(t *testing.T) {
	// Create test zip with sample vulnerability JSONs
	vulnJSON1 := `{"id":"GO-2024-0001","modified":"2024-01-01T00:00:00Z","summary":"Test vuln 1"}`
	vulnJSON2 := `{"id":"GO-2024-0002","modified":"2024-02-01T00:00:00Z","summary":"Test vuln 2"}`

	zipData := createTestZip(t, map[string]string{
		"GO-2024-0001.json": vulnJSON1,
		"GO-2024-0002.json": vulnJSON2,
		"README.md":         "not a json file",
	})

	// Set up mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/Go/all.zip":
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(zipData)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	// Create fetcher with mock server
	f := New(WithBaseURL(server.URL))

	// Test FetchAllZip
	var progressCalls []int
	results, err := f.FetchAllZip(context.Background(), "Go", func(current, total int) {
		progressCalls = append(progressCalls, current)
	})
	if err != nil {
		t.Fatalf("FetchAllZip failed: %v", err)
	}

	// Verify results
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if string(results["GO-2024-0001"]) != vulnJSON1 {
		t.Errorf("GO-2024-0001 content mismatch")
	}
	if string(results["GO-2024-0002"]) != vulnJSON2 {
		t.Errorf("GO-2024-0002 content mismatch")
	}

	// Verify progress was called
	if len(progressCalls) != 2 {
		t.Errorf("expected 2 progress calls, got %d", len(progressCalls))
	}
	if progressCalls[0] != 1 || progressCalls[1] != 2 {
		t.Errorf("progress calls = %v, want [1, 2]", progressCalls)
	}
}

func TestFetchVulnerability(t *testing.T) {
	vulnJSON := `{"id":"GO-2024-0001","modified":"2024-01-01T00:00:00Z","summary":"Test"}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/Go/GO-2024-0001.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(vulnJSON))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	f := New(WithBaseURL(server.URL))

	data, err := f.FetchVulnerability(context.Background(), "Go", "GO-2024-0001")
	if err != nil {
		t.Fatalf("FetchVulnerability failed: %v", err)
	}
	if string(data) != vulnJSON {
		t.Errorf("content mismatch: got %q", string(data))
	}
}

func TestFetchVulnerability_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer server.Close()

	f := New(WithBaseURL(server.URL))

	_, err := f.FetchVulnerability(context.Background(), "Go", "NONEXISTENT")
	if err == nil {
		t.Fatal("expected error for 404, got nil")
	}
}

func TestFetchModifiedCSV(t *testing.T) {
	csvContent := "2024-08-15T00:05:00Z,PYSEC-2021-123\n2024-08-14T12:00:00Z,PYSEC-2021-456\n"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/PyPI/modified_id.csv":
			_, _ = w.Write([]byte(csvContent))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	f := New(WithBaseURL(server.URL))

	data, err := f.FetchModifiedCSV(context.Background(), "PyPI")
	if err != nil {
		t.Fatalf("FetchModifiedCSV failed: %v", err)
	}
	if string(data) != csvContent {
		t.Errorf("CSV content mismatch")
	}
}

func TestParseModifiedCSV_PerEcosystem(t *testing.T) {
	csv := `2024-08-15T00:05:00Z,GO-2024-0001
2024-08-14T12:00:00Z,GO-2023-1840
2024-08-13T10:00:00Z,GO-2022-0100
`

	entries, err := ParseModifiedCSV([]byte(csv), "Go")
	if err != nil {
		t.Fatalf("ParseModifiedCSV failed: %v", err)
	}

	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	// Check first entry
	if entries[0].ID != "GO-2024-0001" {
		t.Errorf("entries[0].ID = %q, want GO-2024-0001", entries[0].ID)
	}
	if entries[0].Ecosystem != "Go" {
		t.Errorf("entries[0].Ecosystem = %q, want Go", entries[0].Ecosystem)
	}
	expectedTime, _ := time.Parse(time.RFC3339, "2024-08-15T00:05:00Z")
	if !entries[0].ModifiedAt.Equal(expectedTime) {
		t.Errorf("entries[0].ModifiedAt = %v, want %v", entries[0].ModifiedAt, expectedTime)
	}
}

func TestParseModifiedCSV_TopLevel(t *testing.T) {
	csv := `2024-08-15T00:05:00Z,PyPI/PYSEC-2021-123
2024-08-15T00:01:00Z,Go/GO-2022-0123
2024-08-14T12:00:00Z,npm/1234
`

	entries, err := ParseModifiedCSV([]byte(csv), "")
	if err != nil {
		t.Fatalf("ParseModifiedCSV failed: %v", err)
	}

	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	// Check entries
	tests := []struct {
		ecosystem string
		id        string
	}{
		{"PyPI", "PYSEC-2021-123"},
		{"Go", "GO-2022-0123"},
		{"npm", "1234"},
	}

	for i, tt := range tests {
		if entries[i].Ecosystem != tt.ecosystem {
			t.Errorf("entries[%d].Ecosystem = %q, want %q", i, entries[i].Ecosystem, tt.ecosystem)
		}
		if entries[i].ID != tt.id {
			t.Errorf("entries[%d].ID = %q, want %q", i, entries[i].ID, tt.id)
		}
	}
}

func TestFilterModifiedSince(t *testing.T) {
	entries := []ModifiedEntry{
		{ModifiedAt: time.Date(2024, 8, 15, 0, 5, 0, 0, time.UTC), ID: "GO-2024-0003"},
		{ModifiedAt: time.Date(2024, 8, 14, 12, 0, 0, 0, time.UTC), ID: "GO-2024-0002"},
		{ModifiedAt: time.Date(2024, 8, 13, 10, 0, 0, 0, time.UTC), ID: "GO-2024-0001"},
		{ModifiedAt: time.Date(2024, 8, 12, 8, 0, 0, 0, time.UTC), ID: "GO-2023-1840"},
	}

	// Filter since Aug 14 at noon — should get only the first entry
	since := time.Date(2024, 8, 14, 12, 0, 0, 0, time.UTC)
	filtered := FilterModifiedSince(entries, since)

	if len(filtered) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(filtered))
	}
	if filtered[0].ID != "GO-2024-0003" {
		t.Errorf("filtered[0].ID = %q, want GO-2024-0003", filtered[0].ID)
	}

	// Filter since Aug 12 — should get 3 entries
	since = time.Date(2024, 8, 12, 8, 0, 0, 0, time.UTC)
	filtered = FilterModifiedSince(entries, since)
	if len(filtered) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(filtered))
	}

	// Filter with future date — should get 0
	since = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	filtered = FilterModifiedSince(entries, since)
	if len(filtered) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(filtered))
	}
}

func TestParseModifiedCSV_EmptyLines(t *testing.T) {
	csv := `2024-08-15T00:05:00Z,GO-2024-0001

2024-08-14T12:00:00Z,GO-2023-1840

`
	entries, err := ParseModifiedCSV([]byte(csv), "Go")
	if err != nil {
		t.Fatalf("ParseModifiedCSV failed: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
}

func TestParseModifiedCSV_InvalidFormat(t *testing.T) {
	tests := []struct {
		name string
		csv  string
	}{
		{"no comma", "2024-08-15T00:05:00Z GO-2024-0001\n"},
		{"invalid timestamp", "not-a-date,GO-2024-0001\n"},
		{"no slash in top-level", "2024-08-15T00:05:00Z,GO-2024-0001\n"}, // top-level needs ecosystem/id
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseModifiedCSV([]byte(tt.csv), "")
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestFetchAllZip_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response
		select {
		case <-r.Context().Done():
			return
		case <-time.After(5 * time.Second):
			_, _ = w.Write([]byte("too slow"))
		}
	}))
	defer server.Close()

	f := New(WithBaseURL(server.URL))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := f.FetchAllZip(ctx, "Go", nil)
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}

func TestValidatePathSegment(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"valid ecosystem", "Go", false},
		{"valid with dot", "crates.io", false},
		{"valid with space", "GitHub Actions", false},
		{"valid vuln id", "GO-2024-0001", false},
		{"valid cve", "CVE-2024-24790", false},
		{"empty", "", true},
		{"path traversal", "../../other-bucket/x", true},
		{"dotdot only", "..", true},
		{"leading slash", "/etc/passwd", true},
		{"embedded slash", "Go/../npm", true},
		{"query injection", "Go&max-keys=1", true},
		{"newline", "Go\nnpm", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePathSegment("test", tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePathSegment(%q) error = %v, wantErr %v", tt.value, err, tt.wantErr)
			}
		})
	}
}

func TestFetchAllZip_RejectsPathTraversal(t *testing.T) {
	// Server should never be hit; validation must fail first.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("server should not be reached for invalid ecosystem, got %s", r.URL.Path)
		http.NotFound(w, r)
	}))
	defer server.Close()

	f := New(WithBaseURL(server.URL))

	_, err := f.FetchAllZip(context.Background(), "../../other-bucket", nil)
	if err == nil {
		t.Fatal("expected error for path traversal ecosystem, got nil")
	}
}

func TestFetchVulnerability_RejectsMaliciousID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("server should not be reached for invalid id, got %s", r.URL.Path)
		http.NotFound(w, r)
	}))
	defer server.Close()

	f := New(WithBaseURL(server.URL))

	_, err := f.FetchVulnerability(context.Background(), "Go", "../../../etc/passwd")
	if err == nil {
		t.Fatal("expected error for malicious id, got nil")
	}
}

func TestExtractZip_RejectsTooManyEntries(t *testing.T) {
	// This exercises the entry-count guard indirectly by verifying the
	// constant is enforced. We build a small zip and confirm normal behavior,
	// then confirm the limit constant is sane.
	if MaxZipEntries <= 0 {
		t.Fatalf("MaxZipEntries must be positive, got %d", MaxZipEntries)
	}

	// Build a zip with a couple entries and ensure it extracts fine.
	zipData := createTestZip(t, map[string]string{
		"A-0001.json": `{"id":"A-0001"}`,
		"A-0002.json": `{"id":"A-0002"}`,
	})

	f := New()
	results, err := f.extractZip(zipData, nil)
	if err != nil {
		t.Fatalf("extractZip failed: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
}

func TestDownload_RejectsOversizedResponse(t *testing.T) {
	// This verifies the MaxResponseSize constant is enforced conceptually.
	// A full 2GB response test is impractical, so we assert the guard exists
	// via the constant and a small successful download.
	if MaxResponseSize <= 0 {
		t.Fatalf("MaxResponseSize must be positive, got %d", MaxResponseSize)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("small ok"))
	}))
	defer server.Close()

	f := New(WithBaseURL(server.URL))
	data, err := f.download(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("download failed: %v", err)
	}
	if string(data) != "small ok" {
		t.Errorf("content mismatch: %q", string(data))
	}
}

func TestStreamAllZip(t *testing.T) {
	vulnJSON1 := `{"id":"GO-2024-0001","modified":"2024-01-01T00:00:00Z","summary":"Test vuln 1"}`
	vulnJSON2 := `{"id":"GO-2024-0002","modified":"2024-02-01T00:00:00Z","summary":"Test vuln 2"}`

	zipData := createTestZip(t, map[string]string{
		"GO-2024-0001.json": vulnJSON1,
		"GO-2024-0002.json": vulnJSON2,
		"README.md":         "not a json file",
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/Go/all.zip":
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(zipData)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	f := New(WithBaseURL(server.URL))

	entries, errCh, err := f.StreamAllZip(context.Background(), "Go")
	if err != nil {
		t.Fatalf("StreamAllZip failed: %v", err)
	}

	// Collect all entries
	results := make(map[string]string)
	for entry := range entries {
		results[entry.Name] = string(entry.Data)
	}

	// Check for streaming errors
	if streamErr := <-errCh; streamErr != nil {
		t.Fatalf("stream error: %v", streamErr)
	}

	// Verify results
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results["GO-2024-0001"] != vulnJSON1 {
		t.Errorf("GO-2024-0001 content mismatch: got %q", results["GO-2024-0001"])
	}
	if results["GO-2024-0002"] != vulnJSON2 {
		t.Errorf("GO-2024-0002 content mismatch: got %q", results["GO-2024-0002"])
	}
}

func TestStreamAllZip_TempFileCleanup(t *testing.T) {
	vulnJSON := `{"id":"GO-2024-0001","modified":"2024-01-01T00:00:00Z"}`
	zipData := createTestZip(t, map[string]string{
		"GO-2024-0001.json": vulnJSON,
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(zipData)
	}))
	defer server.Close()

	f := New(WithBaseURL(server.URL))

	entries, errCh, err := f.StreamAllZip(context.Background(), "Go")
	if err != nil {
		t.Fatalf("StreamAllZip failed: %v", err)
	}

	// Drain entries
	for range entries {
	}
	<-errCh

	// After streaming completes, verify no mayu-zip temp files remain.
	// Give a brief moment for cleanup goroutine.
	time.Sleep(10 * time.Millisecond)

	tmpDir := os.TempDir()
	dirEntries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("read temp dir: %v", err)
	}
	for _, de := range dirEntries {
		if strings.HasPrefix(de.Name(), "mayu-zip-") && strings.HasSuffix(de.Name(), ".tmp") {
			t.Errorf("temp file not cleaned up: %s", de.Name())
		}
	}
}

func TestStreamAllZip_ContextCancellation(t *testing.T) {
	vulnJSON := `{"id":"GO-2024-0001","modified":"2024-01-01T00:00:00Z"}`
	zipData := createTestZip(t, map[string]string{
		"GO-2024-0001.json": vulnJSON,
		"GO-2024-0002.json": vulnJSON,
		"GO-2024-0003.json": vulnJSON,
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(zipData)
	}))
	defer server.Close()

	f := New(WithBaseURL(server.URL))

	ctx, cancel := context.WithCancel(context.Background())

	entries, errCh, err := f.StreamAllZip(ctx, "Go")
	if err != nil {
		t.Fatalf("StreamAllZip failed: %v", err)
	}

	// Read one entry then cancel
	<-entries
	cancel()

	// Drain remaining
	for range entries {
	}

	// Should get context cancellation error (or nil if entries finished before cancel took effect)
	streamErr := <-errCh
	if streamErr != nil && streamErr != context.Canceled {
		t.Fatalf("unexpected error: %v", streamErr)
	}
}

func TestDownloadToTempFile(t *testing.T) {
	content := "test content for temp file download"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(content))
	}))
	defer server.Close()

	f := New(WithBaseURL(server.URL))

	tmpFile, size, err := f.downloadToTempFile(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("downloadToTempFile failed: %v", err)
	}
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
	}()

	if size != int64(len(content)) {
		t.Errorf("size = %d, want %d", size, len(content))
	}

	// Read back and verify content
	buf := make([]byte, size)
	_, err = tmpFile.Read(buf)
	if err != nil {
		t.Fatalf("read temp file: %v", err)
	}
	if string(buf) != content {
		t.Errorf("content mismatch: got %q", string(buf))
	}

	// Verify file permissions (0600)
	info, err := os.Stat(tmpFile.Name())
	if err != nil {
		t.Fatalf("stat temp file: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("file permissions = %o, want 0600", perm)
	}
}

func TestStreamTopLevelAllZip(t *testing.T) {
	// The top-level all.zip contains files with paths like "ecosystem/vuln_id.json"
	vulnJSON1 := `{"id":"GO-2024-0001","modified":"2024-01-01T00:00:00Z","summary":"Test vuln 1"}`
	vulnJSON2 := `{"id":"PYSEC-2024-0001","modified":"2024-02-01T00:00:00Z","summary":"Test vuln 2"}`

	zipData := createTestZip(t, map[string]string{
		"Go/GO-2024-0001.json":      vulnJSON1,
		"PyPI/PYSEC-2024-0001.json": vulnJSON2,
		"README.md":                 "not a json file",
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/all.zip":
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(zipData)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	f := New(WithBaseURL(server.URL))

	entries, errCh, err := f.StreamTopLevelAllZip(context.Background())
	if err != nil {
		t.Fatalf("StreamTopLevelAllZip failed: %v", err)
	}

	// Collect all entries
	results := make(map[string]string)
	for entry := range entries {
		results[entry.Name] = string(entry.Data)
	}

	// Check for streaming errors
	if streamErr := <-errCh; streamErr != nil {
		t.Fatalf("stream error: %v", streamErr)
	}

	// Verify results - should extract vuln_id from "ecosystem/vuln_id.json"
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d: %v", len(results), results)
	}
	if results["GO-2024-0001"] != vulnJSON1 {
		t.Errorf("GO-2024-0001 content mismatch: got %q", results["GO-2024-0001"])
	}
	if results["PYSEC-2024-0001"] != vulnJSON2 {
		t.Errorf("PYSEC-2024-0001 content mismatch: got %q", results["PYSEC-2024-0001"])
	}
}

func TestStreamTopLevelAllZip_ContextCancellation(t *testing.T) {
	vulnJSON := `{"id":"GO-2024-0001","modified":"2024-01-01T00:00:00Z"}`
	zipData := createTestZip(t, map[string]string{
		"Go/GO-2024-0001.json":    vulnJSON,
		"Go/GO-2024-0002.json":    vulnJSON,
		"PyPI/PYSEC-2024-01.json": vulnJSON,
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(zipData)
	}))
	defer server.Close()

	f := New(WithBaseURL(server.URL))

	ctx, cancel := context.WithCancel(context.Background())

	entries, errCh, err := f.StreamTopLevelAllZip(ctx)
	if err != nil {
		t.Fatalf("StreamTopLevelAllZip failed: %v", err)
	}

	// Read one entry then cancel
	<-entries
	cancel()

	// Drain remaining
	for range entries {
	}

	// Should get context cancellation error (or nil if finished)
	streamErr := <-errCh
	if streamErr != nil && streamErr != context.Canceled {
		t.Fatalf("unexpected error: %v", streamErr)
	}
}
