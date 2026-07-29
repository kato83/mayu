package reachability

import (
	"context"
	"encoding/json"
	"path/filepath"
	"runtime"
	"testing"
)

func testdataDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "..", "testdata", "reachability")
}

func TestGoAnalyzer_Reachable(t *testing.T) {
	analyzer := NewGoAnalyzer()
	dir := filepath.Join(testdataDir(), "reachable")

	symbols := []VulnSymbol{
		{VulnID: "GO-2024-2687", Package: "net/http", Symbol: "Get"},
	}

	results, err := analyzer.Analyze(context.Background(), dir, symbols)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := results[0]
	if !r.Reachable {
		t.Error("expected Reachable=true for project using http.Get")
	}
	if r.VulnID != "GO-2024-2687" {
		t.Errorf("VulnID = %q, want %q", r.VulnID, "GO-2024-2687")
	}
	if r.Package != "net/http" {
		t.Errorf("Package = %q, want %q", r.Package, "net/http")
	}
	if len(r.Evidence) == 0 {
		t.Fatal("expected at least one Evidence entry")
	}

	ev := r.Evidence[0]
	if ev.Symbol != "net/http.Get" {
		t.Errorf("Evidence.Symbol = %q, want %q", ev.Symbol, "net/http.Get")
	}
	if ev.File != "main.go" {
		t.Errorf("Evidence.File = %q, want %q", ev.File, "main.go")
	}
	if ev.Line == 0 {
		t.Error("Evidence.Line should not be 0")
	}
}

func TestGoAnalyzer_Unreachable(t *testing.T) {
	analyzer := NewGoAnalyzer()
	dir := filepath.Join(testdataDir(), "unreachable")

	symbols := []VulnSymbol{
		{VulnID: "GO-2024-2687", Package: "net/http", Symbol: "Get"},
		{VulnID: "GO-2024-2687", Package: "net/http", Symbol: "ListenAndServe"},
	}

	results, err := analyzer.Analyze(context.Background(), dir, symbols)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	// All results should be for the same (vulnID, pkg), so 1 result.
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := results[0]
	if r.Reachable {
		t.Error("expected Reachable=false for project importing net/http but not using vulnerable symbols")
	}
	if len(r.Evidence) != 0 {
		t.Errorf("expected no Evidence, got %d entries", len(r.Evidence))
	}
}

func TestGoAnalyzer_NoImport(t *testing.T) {
	analyzer := NewGoAnalyzer()
	dir := filepath.Join(testdataDir(), "no_import")

	symbols := []VulnSymbol{
		{VulnID: "GO-2024-2687", Package: "net/http", Symbol: "Get"},
	}

	results, err := analyzer.Analyze(context.Background(), dir, symbols)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := results[0]
	if r.Reachable {
		t.Error("expected Reachable=false for project not importing net/http")
	}
	if len(r.Evidence) != 0 {
		t.Errorf("expected no Evidence, got %d entries", len(r.Evidence))
	}
}

func TestGoAnalyzer_AliasImport(t *testing.T) {
	analyzer := NewGoAnalyzer()
	dir := filepath.Join(testdataDir(), "alias_import")

	symbols := []VulnSymbol{
		{VulnID: "GO-2024-2687", Package: "net/http", Symbol: "Get"},
	}

	results, err := analyzer.Analyze(context.Background(), dir, symbols)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := results[0]
	if !r.Reachable {
		t.Error("expected Reachable=true for project using aliased import (nethttp.Get)")
	}
	if len(r.Evidence) == 0 {
		t.Fatal("expected at least one Evidence entry")
	}
}

func TestGoAnalyzer_MethodOnType(t *testing.T) {
	analyzer := NewGoAnalyzer()
	dir := filepath.Join(testdataDir(), "method_on_type")

	symbols := []VulnSymbol{
		{VulnID: "GO-2024-2687", Package: "net/http", Symbol: "Client.Do"},
	}

	results, err := analyzer.Analyze(context.Background(), dir, symbols)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := results[0]
	if !r.Reachable {
		t.Error("expected Reachable=true for project using http.Client (vulnerable symbol Client.Do)")
	}
	if len(r.Evidence) == 0 {
		t.Fatal("expected at least one Evidence entry for Client.Do")
	}
}

func TestGoAnalyzer_EmptySymbols(t *testing.T) {
	analyzer := NewGoAnalyzer()
	dir := filepath.Join(testdataDir(), "reachable")

	results, err := analyzer.Analyze(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if results != nil {
		t.Errorf("expected nil results for empty symbols, got %d", len(results))
	}
}

func TestGoAnalyzer_MultipleVulns(t *testing.T) {
	analyzer := NewGoAnalyzer()
	dir := filepath.Join(testdataDir(), "reachable")

	symbols := []VulnSymbol{
		{VulnID: "GO-2024-2687", Package: "net/http", Symbol: "Get"},
		{VulnID: "GO-2024-9999", Package: "crypto/tls", Symbol: "Dial"},
	}

	results, err := analyzer.Analyze(context.Background(), dir, symbols)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	// Find each result by VulnID.
	var httpResult, tlsResult *Result
	for i := range results {
		switch results[i].VulnID {
		case "GO-2024-2687":
			httpResult = &results[i]
		case "GO-2024-9999":
			tlsResult = &results[i]
		}
	}

	if httpResult == nil {
		t.Fatal("missing result for GO-2024-2687")
	}
	if !httpResult.Reachable {
		t.Error("expected http result to be reachable")
	}

	if tlsResult == nil {
		t.Fatal("missing result for GO-2024-9999")
	}
	if tlsResult.Reachable {
		t.Error("expected tls result to be unreachable")
	}
}

func TestGoAnalyzer_ContextCancellation(t *testing.T) {
	analyzer := NewGoAnalyzer()
	dir := filepath.Join(testdataDir(), "reachable")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	symbols := []VulnSymbol{
		{VulnID: "GO-2024-2687", Package: "net/http", Symbol: "Get"},
	}

	_, err := analyzer.Analyze(ctx, dir, symbols)
	if err == nil {
		// It's acceptable to not error if the analysis completed before
		// the context check. But if it does error, it should be context.Canceled.
		return
	}
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestExtractVulnSymbols(t *testing.T) {
	tests := []struct {
		name    string
		vulnID  string
		input   string
		wantLen int
		wantPkg string
		wantSym string
	}{
		{
			name:   "valid Go ecosystem_specific",
			vulnID: "GO-2024-2687",
			input: `{
				"imports": [
					{
						"path": "net/http",
						"symbols": ["Get", "Client.Do"]
					}
				]
			}`,
			wantLen: 2,
			wantPkg: "net/http",
			wantSym: "Get",
		},
		{
			name:   "multiple imports",
			vulnID: "GO-2024-0001",
			input: `{
				"imports": [
					{"path": "net/http", "symbols": ["Get"]},
					{"path": "net/http/httputil", "symbols": ["ReverseProxy.ServeHTTP"]}
				]
			}`,
			wantLen: 2,
			wantPkg: "net/http",
			wantSym: "Get",
		},
		{
			name:    "nil input",
			vulnID:  "GO-2024-0001",
			input:   "",
			wantLen: 0,
		},
		{
			name:    "no symbols field",
			vulnID:  "GO-2024-0001",
			input:   `{"imports": [{"path": "net/http"}]}`,
			wantLen: 0,
		},
		{
			name:    "empty imports",
			vulnID:  "GO-2024-0001",
			input:   `{"imports": []}`,
			wantLen: 0,
		},
		{
			name:    "invalid JSON",
			vulnID:  "GO-2024-0001",
			input:   `not json`,
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var raw json.RawMessage
			if tt.input != "" {
				raw = json.RawMessage(tt.input)
			}

			got := ExtractVulnSymbols(tt.vulnID, raw)
			if len(got) != tt.wantLen {
				t.Fatalf("ExtractVulnSymbols() returned %d symbols, want %d", len(got), tt.wantLen)
			}

			if tt.wantLen > 0 {
				if got[0].VulnID != tt.vulnID {
					t.Errorf("VulnID = %q, want %q", got[0].VulnID, tt.vulnID)
				}
				if got[0].Package != tt.wantPkg {
					t.Errorf("Package = %q, want %q", got[0].Package, tt.wantPkg)
				}
				if got[0].Symbol != tt.wantSym {
					t.Errorf("Symbol = %q, want %q", got[0].Symbol, tt.wantSym)
				}
			}
		})
	}
}
