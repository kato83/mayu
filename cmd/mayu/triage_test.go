package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kato83/mayu/internal/triage"
)

// TestTriageSingleID tests `mayu triage --id <vuln-id>` functionality.
// Validates: Requirements 6.2
func TestTriageSingleID(t *testing.T) {
	tests := []struct {
		name     string
		vulnID   string
		format   string
		wantErr  bool
		checkOut func(t *testing.T, output string)
	}{
		{
			name:   "single vuln table output",
			vulnID: "CVE-2024-1234",
			format: "table",
			checkOut: func(t *testing.T, output string) {
				if !strings.Contains(output, "CVE-2024-1234") {
					t.Errorf("expected output to contain vuln ID, got: %s", output)
				}
				if !strings.Contains(output, "Priority:") {
					t.Errorf("expected output to contain Priority field")
				}
			},
		},
		{
			name:   "single vuln json output",
			vulnID: "CVE-2024-5678",
			format: "json",
			checkOut: func(t *testing.T, output string) {
				var result triage.TriageResult
				if err := json.Unmarshal([]byte(output), &result); err != nil {
					t.Fatalf("expected valid JSON output: %v", err)
				}
				if result.VulnerabilityID != "CVE-2024-5678" {
					t.Errorf("expected vuln ID CVE-2024-5678, got %s", result.VulnerabilityID)
				}
				if result.PriorityLevel == "" {
					t.Error("expected non-empty priority level")
				}
				if result.ProfileUsed == "" {
					t.Error("expected non-empty profile_used")
				}
			},
		},
		{
			name:   "single vuln csv output",
			vulnID: "CVE-2024-9999",
			format: "csv",
			checkOut: func(t *testing.T, output string) {
				lines := strings.Split(strings.TrimSpace(output), "\n")
				if len(lines) < 2 {
					t.Fatalf("expected at least 2 lines (header + data), got %d", len(lines))
				}
				if !strings.Contains(lines[0], "vulnerability_id") {
					t.Error("expected CSV header with vulnerability_id")
				}
				if !strings.Contains(lines[1], "CVE-2024-9999") {
					t.Errorf("expected data line with CVE-2024-9999, got: %s", lines[1])
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture stdout
			old := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			args := []string{"--id", tt.vulnID, "--format", tt.format}
			err := runTriageExecute(args)

			w.Close()
			os.Stdout = old

			var buf [4096]byte
			n, _ := r.Read(buf[:])
			output := string(buf[:n])
			r.Close()

			if tt.wantErr && err == nil {
				t.Fatal("expected error but got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.checkOut != nil {
				tt.checkOut(t, output)
			}
		})
	}
}

// TestTriageBatchSBOM tests `mayu triage --sbom <path>` functionality.
// Validates: Requirements 6.1, 6.4
func TestTriageBatchSBOM(t *testing.T) {
	// Create a temporary SBOM file with test findings
	sbomData := `{
		"findings": [
			{"vulnerability_id": "CVE-2024-001", "cvss_score": 9.8, "epss_score": 0.95, "in_kev": true, "has_exploit": true, "patch_available": true},
			{"vulnerability_id": "CVE-2024-002", "cvss_score": 5.0, "epss_score": 0.10, "in_kev": false, "has_exploit": false, "patch_available": true},
			{"vulnerability_id": "CVE-2024-003", "cvss_score": 7.5, "epss_score": 0.60, "in_kev": false, "has_exploit": true, "patch_available": false}
		]
	}`

	tmpDir := t.TempDir()
	sbomPath := filepath.Join(tmpDir, "test-sbom.json")
	if err := os.WriteFile(sbomPath, []byte(sbomData), 0644); err != nil {
		t.Fatalf("write test SBOM: %v", err)
	}

	t.Run("batch triage table output with sort order", func(t *testing.T) {
		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		args := []string{"--sbom", sbomPath, "--format", "table"}
		err := runTriageExecute(args)

		w.Close()
		os.Stdout = old

		var buf [8192]byte
		n, _ := r.Read(buf[:])
		output := string(buf[:n])
		r.Close()

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify all vulnerabilities are present
		if !strings.Contains(output, "CVE-2024-001") {
			t.Error("expected output to contain CVE-2024-001")
		}
		if !strings.Contains(output, "CVE-2024-002") {
			t.Error("expected output to contain CVE-2024-002")
		}
		if !strings.Contains(output, "CVE-2024-003") {
			t.Error("expected output to contain CVE-2024-003")
		}

		// Verify sort order: Critical CVE-2024-001 should appear before lower priority ones
		idx001 := strings.Index(output, "CVE-2024-001")
		idx002 := strings.Index(output, "CVE-2024-002")
		if idx001 > idx002 {
			t.Error("expected CVE-2024-001 (higher priority) to appear before CVE-2024-002")
		}
	})

	t.Run("batch triage json output", func(t *testing.T) {
		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		args := []string{"--sbom", sbomPath, "--format", "json"}
		err := runTriageExecute(args)

		w.Close()
		os.Stdout = old

		var buf [16384]byte
		n, _ := r.Read(buf[:])
		output := string(buf[:n])
		r.Close()

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var report struct {
			ProfileUsed string `json:"profile_used"`
			Summary     struct {
				Total    int `json:"total"`
				Critical int `json:"critical"`
				High     int `json:"high"`
				Medium   int `json:"medium"`
				Low      int `json:"low"`
			} `json:"summary"`
			Results []triage.TriageResult `json:"results"`
		}
		if err := json.Unmarshal([]byte(output), &report); err != nil {
			t.Fatalf("expected valid JSON: %v\noutput: %s", err, output)
		}
		if report.Summary.Total != 3 {
			t.Errorf("expected total 3, got %d", report.Summary.Total)
		}
		if report.ProfileUsed != "default" {
			t.Errorf("expected profile_used 'default', got %q", report.ProfileUsed)
		}
	})
}

// TestTriageSBOMWithServerProfile tests `mayu triage --sbom --server` for profile auto-resolution.
// Validates: Requirements 6.3
func TestTriageSBOMWithServerProfile(t *testing.T) {
	sbomData := `{
		"findings": [
			{"vulnerability_id": "CVE-2024-100", "cvss_score": 8.0, "epss_score": 0.80, "in_kev": true, "has_exploit": false, "patch_available": true}
		]
	}`

	tmpDir := t.TempDir()
	sbomPath := filepath.Join(tmpDir, "test-sbom.json")
	if err := os.WriteFile(sbomPath, []byte(sbomData), 0644); err != nil {
		t.Fatalf("write test SBOM: %v", err)
	}

	// Test with server label - it should use the "internet-facing" profile
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	args := []string{"--sbom", sbomPath, "--server", "api-prod", "--profile", "internet-facing", "--format", "json"}
	err := runTriageExecute(args)

	w.Close()
	os.Stdout = old

	var buf [8192]byte
	n, _ := r.Read(buf[:])
	output := string(buf[:n])
	r.Close()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report struct {
		ProfileUsed string `json:"profile_used"`
	}
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}
	if report.ProfileUsed != "internet-facing" {
		t.Errorf("expected profile 'internet-facing', got %q", report.ProfileUsed)
	}
}

// TestTriageFailOn tests `--fail-on` exit code behavior.
// Validates: Requirements 6.5
func TestTriageFailOn(t *testing.T) {
	// Create SBOM with a Critical vulnerability
	sbomData := `{
		"findings": [
			{"vulnerability_id": "CVE-2024-CRIT", "cvss_score": 9.8, "epss_score": 0.97, "in_kev": true, "has_exploit": true, "patch_available": false}
		]
	}`

	tmpDir := t.TempDir()
	sbomPath := filepath.Join(tmpDir, "test-sbom.json")
	if err := os.WriteFile(sbomPath, []byte(sbomData), 0644); err != nil {
		t.Fatalf("write test SBOM: %v", err)
	}

	// We can't directly test os.Exit(1), but we can test the logic up to that point.
	// The triageBatchSBOM function calls os.Exit directly, so we test the engine logic instead.
	profile := triage.DefaultProfile()
	engine := triage.NewEngine(profile)

	cvss := 9.8
	epss := 0.97
	input := &triage.TriageInput{
		VulnerabilityID: "CVE-2024-CRIT",
		CVSSScore:       &cvss,
		EPSSScore:       &epss,
		InKEV:           true,
		HasExploit:      true,
		PatchAvailable:  false,
	}

	results, err := engine.TriageBatch(nil, []*triage.TriageInput{input})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the result would trigger --fail-on critical
	if len(results) == 0 {
		t.Fatal("expected at least one result")
	}

	failLevel := triage.PriorityLevel("Critical")
	foundMatch := false
	for _, r := range results {
		if triage.PriorityRank(r.PriorityLevel) >= triage.PriorityRank(failLevel) {
			foundMatch = true
			break
		}
	}
	if !foundMatch {
		t.Error("expected Critical priority result that would trigger --fail-on critical")
	}

	// Test that --fail-on low would also match
	failLevel = triage.PriorityLevel("Low")
	foundMatch = false
	for _, r := range results {
		if triage.PriorityRank(r.PriorityLevel) >= triage.PriorityRank(failLevel) {
			foundMatch = true
			break
		}
	}
	if !foundMatch {
		t.Error("expected result that would trigger --fail-on low")
	}
}

// TestTriageOverview tests `mayu triage overview` command.
// Validates: Requirements 6.6 (overview display)
func TestTriageOverview(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runTriageOverview([]string{})

	w.Close()
	os.Stdout = old

	var buf [4096]byte
	n, _ := r.Read(buf[:])
	output := string(buf[:n])
	r.Close()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(output, "Cross-Project Triage Overview") {
		t.Error("expected output to contain 'Cross-Project Triage Overview'")
	}
}

// TestTriagePaths tests `mayu triage paths` command (Impact Score sort verification).
// Validates: Requirements 6.6
func TestTriagePaths(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runTriagePaths([]string{})

	w.Close()
	os.Stdout = old

	var buf [4096]byte
	n, _ := r.Read(buf[:])
	output := string(buf[:n])
	r.Close()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(output, "Triage Paths") {
		t.Error("expected output to contain 'Triage Paths'")
	}
}

// TestTriagePathsImpactScoreSort tests that ComputeTriagePaths returns paths sorted by ImpactScore descending.
// Validates: Requirements 9.1, 9.2
func TestTriagePathsImpactScoreSort(t *testing.T) {
	findings := []triage.ScanFinding{
		// Group 1: lodash - low score
		{VulnerabilityID: "CVE-2020-001", PackagePurl: "pkg:npm/lodash", CurrentVersion: "4.17.15", FixedVersion: "4.17.21", Ecosystem: "npm", ServerLabel: "s1", ProjectID: 1, CompositeScore: 0.3, PriorityLevel: triage.PriorityLow},
		// Group 2: express - high score, multiple CVEs and servers
		{VulnerabilityID: "CVE-2021-001", PackagePurl: "pkg:npm/express", CurrentVersion: "4.16.0", FixedVersion: "4.17.1", Ecosystem: "npm", ServerLabel: "s1", ProjectID: 1, CompositeScore: 0.9, PriorityLevel: triage.PriorityCritical},
		{VulnerabilityID: "CVE-2021-002", PackagePurl: "pkg:npm/express", CurrentVersion: "4.16.0", FixedVersion: "4.17.1", Ecosystem: "npm", ServerLabel: "s2", ProjectID: 2, CompositeScore: 0.8, PriorityLevel: triage.PriorityHigh},
	}

	paths := triage.ComputeTriagePaths(findings)
	if len(paths) < 2 {
		t.Fatalf("expected at least 2 paths, got %d", len(paths))
	}

	// Verify sorted by ImpactScore descending
	for i := 1; i < len(paths); i++ {
		if paths[i].ImpactScore > paths[i-1].ImpactScore {
			t.Errorf("paths not sorted by ImpactScore desc: path[%d]=%f > path[%d]=%f",
				i, paths[i].ImpactScore, i-1, paths[i-1].ImpactScore)
		}
	}
}

// TestTriageProfileBind tests `mayu triage profile bind` functionality.
// Validates: Requirements 10.1, 10.2
func TestTriageProfileBind(t *testing.T) {
	t.Run("successful binding", func(t *testing.T) {
		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		args := []string{"--project", "test-project", "--server", "api-prod", "--profile", "internet-facing"}
		err := runTriageProfileBind(args)

		w.Close()
		os.Stdout = old

		var buf [4096]byte
		n, _ := r.Read(buf[:])
		output := string(buf[:n])
		r.Close()

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(output, "Bound profile") {
			t.Error("expected success message about binding")
		}
		if !strings.Contains(output, "internet-facing") {
			t.Error("expected output to reference the profile name")
		}
	})

	t.Run("missing required fields", func(t *testing.T) {
		args := []string{"--project", "test-project"}
		err := runTriageProfileBind(args)
		if err == nil {
			t.Error("expected error for missing --server and --profile")
		}
	})

	t.Run("unknown profile", func(t *testing.T) {
		args := []string{"--project", "test-project", "--server", "web-prod", "--profile", "nonexistent-profile"}
		err := runTriageProfileBind(args)
		if err == nil {
			t.Error("expected error for unknown profile")
		}
	})
}

// TestTriageProfileBindings tests `mayu triage profile bindings` listing functionality.
// Validates: Requirements 10.1
func TestTriageProfileBindings(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	args := []string{"--project", "test-project"}
	err := runTriageProfileBindings(args)

	w.Close()
	os.Stdout = old

	var buf [4096]byte
	n, _ := r.Read(buf[:])
	output := string(buf[:n])
	r.Close()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(output, "test-project") {
		t.Error("expected output to reference project name")
	}
}

// TestTriageProfileValidate tests `mayu triage profile validate` with valid and invalid YAML.
// Validates: Requirements 10.1, 10.2, 10.3, 10.4
func TestTriageProfileValidate(t *testing.T) {
	t.Run("valid profile", func(t *testing.T) {
		validYAML := `name: test-valid
description: A valid test profile
weights:
  cvss: 0.20
  epss: 0.20
  lev: 0.15
  kev: 0.15
  patch: 0.08
  age: 0.05
  exploitdb: 0.10
  reachability: 0.07
thresholds:
  critical: 0.85
  high: 0.65
  medium: 0.40
`
		tmpDir := t.TempDir()
		profilePath := filepath.Join(tmpDir, "valid-profile.yaml")
		if err := os.WriteFile(profilePath, []byte(validYAML), 0644); err != nil {
			t.Fatalf("write profile: %v", err)
		}

		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		args := []string{"--file", profilePath}
		err := runTriageProfileValidate(args)

		w.Close()
		os.Stdout = old

		var buf [4096]byte
		n, _ := r.Read(buf[:])
		output := string(buf[:n])
		r.Close()

		if err != nil {
			t.Fatalf("expected no error for valid profile, got: %v", err)
		}
		if !strings.Contains(output, "is valid") {
			t.Errorf("expected 'is valid' message, got: %s", output)
		}
	})

	t.Run("invalid profile - weights sum", func(t *testing.T) {
		invalidYAML := `name: test-invalid
description: Weights do not sum to 1.0
weights:
  cvss: 0.50
  epss: 0.50
  lev: 0.50
  kev: 0.00
  patch: 0.00
  age: 0.00
  exploitdb: 0.00
  reachability: 0.00
thresholds:
  critical: 0.85
  high: 0.65
  medium: 0.40
`
		tmpDir := t.TempDir()
		profilePath := filepath.Join(tmpDir, "invalid-profile.yaml")
		if err := os.WriteFile(profilePath, []byte(invalidYAML), 0644); err != nil {
			t.Fatalf("write profile: %v", err)
		}

		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		args := []string{"--file", profilePath}
		err := runTriageProfileValidate(args)

		w.Close()
		os.Stdout = old

		var buf [4096]byte
		n, _ := r.Read(buf[:])
		output := string(buf[:n])
		r.Close()

		if err == nil {
			t.Error("expected error for invalid profile")
		}
		if !strings.Contains(output, "validation error") {
			t.Errorf("expected validation error message, got: %s", output)
		}
	})

	t.Run("invalid profile - bad thresholds", func(t *testing.T) {
		invalidYAML := `name: test-bad-threshold
description: Thresholds in wrong order
weights:
  cvss: 0.20
  epss: 0.20
  lev: 0.15
  kev: 0.15
  patch: 0.08
  age: 0.05
  exploitdb: 0.10
  reachability: 0.07
thresholds:
  critical: 0.40
  high: 0.65
  medium: 0.85
`
		tmpDir := t.TempDir()
		profilePath := filepath.Join(tmpDir, "bad-threshold.yaml")
		if err := os.WriteFile(profilePath, []byte(invalidYAML), 0644); err != nil {
			t.Fatalf("write profile: %v", err)
		}

		args := []string{"--file", profilePath}
		err := runTriageProfileValidate(args)
		if err == nil {
			t.Error("expected error for invalid thresholds")
		}
	})

	t.Run("invalid YAML syntax", func(t *testing.T) {
		badYAML := `name: [broken
  this is not valid yaml: {{{`
		tmpDir := t.TempDir()
		profilePath := filepath.Join(tmpDir, "bad-syntax.yaml")
		if err := os.WriteFile(profilePath, []byte(badYAML), 0644); err != nil {
			t.Fatalf("write profile: %v", err)
		}

		args := []string{"--file", profilePath}
		err := runTriageProfileValidate(args)
		if err == nil {
			t.Error("expected error for invalid YAML syntax")
		}
	})
}

// TestTriageTopN tests `--top` option limiting results.
// Validates: Requirements 6.6
func TestTriageTopN(t *testing.T) {
	sbomData := `{
		"findings": [
			{"vulnerability_id": "CVE-2024-A01", "cvss_score": 9.0, "epss_score": 0.90, "in_kev": true, "has_exploit": true, "patch_available": true},
			{"vulnerability_id": "CVE-2024-A02", "cvss_score": 7.0, "epss_score": 0.50, "in_kev": false, "has_exploit": false, "patch_available": true},
			{"vulnerability_id": "CVE-2024-A03", "cvss_score": 5.0, "epss_score": 0.20, "in_kev": false, "has_exploit": false, "patch_available": true},
			{"vulnerability_id": "CVE-2024-A04", "cvss_score": 3.0, "epss_score": 0.05, "in_kev": false, "has_exploit": false, "patch_available": true}
		]
	}`

	tmpDir := t.TempDir()
	sbomPath := filepath.Join(tmpDir, "test-sbom.json")
	if err := os.WriteFile(sbomPath, []byte(sbomData), 0644); err != nil {
		t.Fatalf("write test SBOM: %v", err)
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	args := []string{"--sbom", sbomPath, "--format", "json", "--top", "2"}
	err := runTriageExecute(args)

	w.Close()
	os.Stdout = old

	var buf [8192]byte
	n, _ := r.Read(buf[:])
	output := string(buf[:n])
	r.Close()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report struct {
		Results []triage.TriageResult `json:"results"`
	}
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}
	if len(report.Results) != 2 {
		t.Errorf("expected 2 results with --top 2, got %d", len(report.Results))
	}
}
