package lockfile

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

const testdataDir = "../../testdata/lockfiles"

func TestDetect(t *testing.T) {
	tests := []struct {
		path    string
		wantErr bool
	}{
		{"go.sum", false},
		{"package-lock.json", false},
		{"yarn.lock", false},
		{"pnpm-lock.yaml", false},
		{"Pipfile.lock", false},
		{"poetry.lock", false},
		{"Gemfile.lock", false},
		{"Cargo.lock", false},
		{"requirements.txt", false},
		{"composer.lock", false},
		{"unknown.txt", true},
		{"package.json", true},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			_, err := Detect(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("Detect(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestGoSumParser(t *testing.T) {
	f, err := os.Open(filepath.Join(testdataDir, "go.sum"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	p := &GoSumParser{}
	components, err := p.Parse("go.sum", f)
	if err != nil {
		t.Fatal(err)
	}

	if len(components) != 3 {
		t.Fatalf("expected 3 components, got %d", len(components))
	}

	// Sort for deterministic testing
	sort.Slice(components, func(i, j int) bool {
		return components[i].Name < components[j].Name
	})

	// Check github.com/google/uuid
	found := false
	for _, c := range components {
		if c.Name == "github.com/google/uuid" {
			found = true
			if c.Version != "1.6.0" {
				t.Errorf("uuid version = %q, want %q", c.Version, "1.6.0")
			}
			if c.Ecosystem != "Go" {
				t.Errorf("uuid ecosystem = %q, want %q", c.Ecosystem, "Go")
			}
			if c.Purl != "pkg:golang/github.com/google/uuid@1.6.0" {
				t.Errorf("uuid purl = %q, want %q", c.Purl, "pkg:golang/github.com/google/uuid@1.6.0")
			}
		}
	}
	if !found {
		t.Error("expected to find github.com/google/uuid")
	}
}

func TestNPMLockParser(t *testing.T) {
	f, err := os.Open(filepath.Join(testdataDir, "package-lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	p := &NPMLockParser{}
	components, err := p.Parse("package-lock.json", f)
	if err != nil {
		t.Fatal(err)
	}

	if len(components) != 3 {
		t.Fatalf("expected 3 components, got %d", len(components))
	}

	// Check for lodash
	var lodash, angular, jest bool
	for _, c := range components {
		switch c.Name {
		case "lodash":
			lodash = true
			if c.Version != "4.17.21" {
				t.Errorf("lodash version = %q, want %q", c.Version, "4.17.21")
			}
			if c.Ecosystem != "npm" {
				t.Errorf("lodash ecosystem = %q, want %q", c.Ecosystem, "npm")
			}
			if c.IsDev {
				t.Error("lodash should not be dev")
			}
		case "@angular/core":
			angular = true
			if c.Version != "17.0.0" {
				t.Errorf("@angular/core version = %q, want %q", c.Version, "17.0.0")
			}
		case "jest":
			jest = true
			if !c.IsDev {
				t.Error("jest should be dev")
			}
		}
	}
	if !lodash {
		t.Error("expected to find lodash")
	}
	if !angular {
		t.Error("expected to find @angular/core")
	}
	if !jest {
		t.Error("expected to find jest")
	}
}

func TestYarnLockParser(t *testing.T) {
	f, err := os.Open(filepath.Join(testdataDir, "yarn.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	p := &YarnLockParser{}
	components, err := p.Parse("yarn.lock", f)
	if err != nil {
		t.Fatal(err)
	}

	if len(components) != 3 {
		t.Fatalf("expected 3 components, got %d", len(components))
	}

	found := make(map[string]string)
	for _, c := range components {
		found[c.Name] = c.Version
		if c.Ecosystem != "npm" {
			t.Errorf("%s ecosystem = %q, want %q", c.Name, c.Ecosystem, "npm")
		}
	}

	if v, ok := found["lodash"]; !ok || v != "4.17.21" {
		t.Errorf("lodash = %q, want %q", v, "4.17.21")
	}
	if v, ok := found["@angular/core"]; !ok || v != "17.0.0" {
		t.Errorf("@angular/core = %q, want %q", v, "17.0.0")
	}
	if v, ok := found["express"]; !ok || v != "4.18.2" {
		t.Errorf("express = %q, want %q", v, "4.18.2")
	}
}

func TestPnpmLockParser(t *testing.T) {
	f, err := os.Open(filepath.Join(testdataDir, "pnpm-lock.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	p := &PnpmLockParser{}
	components, err := p.Parse("pnpm-lock.yaml", f)
	if err != nil {
		t.Fatal(err)
	}

	if len(components) != 3 {
		t.Fatalf("expected 3 components, got %d", len(components))
	}

	found := make(map[string]bool)
	for _, c := range components {
		found[c.Name] = true
		if c.Ecosystem != "npm" {
			t.Errorf("%s ecosystem = %q, want %q", c.Name, c.Ecosystem, "npm")
		}
		if c.Name == "typescript" && !c.IsDev {
			t.Error("typescript should be dev")
		}
	}

	if !found["lodash"] {
		t.Error("expected to find lodash")
	}
	if !found["@angular/core"] {
		t.Error("expected to find @angular/core")
	}
	if !found["typescript"] {
		t.Error("expected to find typescript")
	}
}

func TestPipfileLockParser(t *testing.T) {
	f, err := os.Open(filepath.Join(testdataDir, "Pipfile.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	p := &PipfileLockParser{}
	components, err := p.Parse("Pipfile.lock", f)
	if err != nil {
		t.Fatal(err)
	}

	if len(components) != 3 {
		t.Fatalf("expected 3 components, got %d", len(components))
	}

	found := make(map[string]bool)
	for _, c := range components {
		found[c.Name] = true
		if c.Ecosystem != "PyPI" {
			t.Errorf("%s ecosystem = %q, want %q", c.Name, c.Ecosystem, "PyPI")
		}
		if c.Name == "pytest" && !c.IsDev {
			t.Error("pytest should be dev")
		}
		if c.Name == "requests" && c.Version != "2.31.0" {
			t.Errorf("requests version = %q, want %q", c.Version, "2.31.0")
		}
	}

	if !found["requests"] {
		t.Error("expected to find requests")
	}
	if !found["flask"] {
		t.Error("expected to find flask")
	}
	if !found["pytest"] {
		t.Error("expected to find pytest")
	}
}

func TestPoetryLockParser(t *testing.T) {
	f, err := os.Open(filepath.Join(testdataDir, "poetry.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	p := &PoetryLockParser{}
	components, err := p.Parse("poetry.lock", f)
	if err != nil {
		t.Fatal(err)
	}

	if len(components) != 2 {
		t.Fatalf("expected 2 components, got %d", len(components))
	}

	found := make(map[string]string)
	for _, c := range components {
		found[c.Name] = c.Version
		if c.Ecosystem != "PyPI" {
			t.Errorf("%s ecosystem = %q, want %q", c.Name, c.Ecosystem, "PyPI")
		}
	}

	if v, ok := found["requests"]; !ok || v != "2.31.0" {
		t.Errorf("requests = %q, want %q", v, "2.31.0")
	}
	if v, ok := found["flask"]; !ok || v != "3.0.0" {
		t.Errorf("flask = %q, want %q", v, "3.0.0")
	}
}

func TestGemfileLockParser(t *testing.T) {
	f, err := os.Open(filepath.Join(testdataDir, "Gemfile.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	p := &GemfileLockParser{}
	components, err := p.Parse("Gemfile.lock", f)
	if err != nil {
		t.Fatal(err)
	}

	if len(components) != 3 {
		t.Fatalf("expected 3 components, got %d", len(components))
	}

	found := make(map[string]string)
	for _, c := range components {
		found[c.Name] = c.Version
		if c.Ecosystem != "RubyGems" {
			t.Errorf("%s ecosystem = %q, want %q", c.Name, c.Ecosystem, "RubyGems")
		}
	}

	if v, ok := found["actionpack"]; !ok || v != "7.1.0" {
		t.Errorf("actionpack = %q, want %q", v, "7.1.0")
	}
	if v, ok := found["rack"]; !ok || v != "2.2.8" {
		t.Errorf("rack = %q, want %q", v, "2.2.8")
	}
}

func TestCargoLockParser(t *testing.T) {
	f, err := os.Open(filepath.Join(testdataDir, "Cargo.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	p := &CargoLockParser{}
	components, err := p.Parse("Cargo.lock", f)
	if err != nil {
		t.Fatal(err)
	}

	if len(components) != 3 {
		t.Fatalf("expected 3 components, got %d", len(components))
	}

	found := make(map[string]string)
	for _, c := range components {
		found[c.Name] = c.Version
		if c.Ecosystem != "crates.io" {
			t.Errorf("%s ecosystem = %q, want %q", c.Name, c.Ecosystem, "crates.io")
		}
	}

	if v, ok := found["serde"]; !ok || v != "1.0.193" {
		t.Errorf("serde = %q, want %q", v, "1.0.193")
	}
	if v, ok := found["tokio"]; !ok || v != "1.35.0" {
		t.Errorf("tokio = %q, want %q", v, "1.35.0")
	}
}

func TestRequirementsTxtParser(t *testing.T) {
	f, err := os.Open(filepath.Join(testdataDir, "requirements.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	p := &RequirementsTxtParser{}
	components, err := p.Parse("requirements.txt", f)
	if err != nil {
		t.Fatal(err)
	}

	if len(components) != 4 {
		t.Fatalf("expected 4 components, got %d", len(components))
	}

	found := make(map[string]string)
	for _, c := range components {
		found[c.Name] = c.Version
		if c.Ecosystem != "PyPI" {
			t.Errorf("%s ecosystem = %q, want %q", c.Name, c.Ecosystem, "PyPI")
		}
	}

	if v, ok := found["requests"]; !ok || v != "2.31.0" {
		t.Errorf("requests = %q, want %q", v, "2.31.0")
	}
	if v, ok := found["flask"]; !ok || v != "3.0.0" {
		t.Errorf("flask = %q, want %q", v, "3.0.0")
	}
	if v, ok := found["numpy"]; !ok || v != "1.26.2" {
		t.Errorf("numpy = %q, want %q", v, "1.26.2")
	}
	if v, ok := found["Django"]; !ok || v != "4.2.8" {
		t.Errorf("Django = %q, want %q", v, "4.2.8")
	}
}

func TestComposerLockParser(t *testing.T) {
	f, err := os.Open(filepath.Join(testdataDir, "composer.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	p := &ComposerLockParser{}
	components, err := p.Parse("composer.lock", f)
	if err != nil {
		t.Fatal(err)
	}

	if len(components) != 3 {
		t.Fatalf("expected 3 components, got %d", len(components))
	}

	found := make(map[string]bool)
	for _, c := range components {
		found[c.Name] = true
		if c.Ecosystem != "Packagist" {
			t.Errorf("%s ecosystem = %q, want %q", c.Name, c.Ecosystem, "Packagist")
		}
		if c.Name == "phpunit/phpunit" {
			if !c.IsDev {
				t.Error("phpunit should be dev")
			}
			if c.Version != "10.5.0" {
				t.Errorf("phpunit version = %q, want %q", c.Version, "10.5.0")
			}
		}
		if c.Name == "symfony/console" {
			if c.Version != "6.4.0" {
				t.Errorf("symfony/console version = %q, want %q", c.Version, "6.4.0")
			}
		}
	}

	if !found["symfony/console"] {
		t.Error("expected to find symfony/console")
	}
	if !found["monolog/monolog"] {
		t.Error("expected to find monolog/monolog")
	}
	if !found["phpunit/phpunit"] {
		t.Error("expected to find phpunit/phpunit")
	}
}

func TestFindLockfiles(t *testing.T) {
	files, err := FindLockfiles(testdataDir)
	if err != nil {
		t.Fatal(err)
	}

	if len(files) == 0 {
		t.Error("expected to find at least one lockfile in testdata dir")
	}

	// Verify all returned paths exist
	for _, f := range files {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("returned path does not exist: %s", f)
		}
	}
}
