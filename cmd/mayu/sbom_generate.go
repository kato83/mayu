package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/kato83/mayu/internal/config"
	"github.com/kato83/mayu/internal/lockfile"
	"github.com/kato83/mayu/internal/sbom"
)

func runSBOMGenerate(args []string, _ *config.Config) error {
	fs := flag.NewFlagSet("sbom generate", flag.ContinueOnError)

	lockfilePath := fs.String("lockfile", "", "Path to lockfile (e.g., go.sum, package-lock.json)")
	dir := fs.String("dir", "", "Directory to scan for lockfiles (alternative to --lockfile)")
	format := fs.String("format", "cyclonedx", "Output format: cyclonedx or spdx")
	name := fs.String("name", "", "Project/component name")
	version := fs.String("version", "", "Project version")
	output := fs.String("output", "", "Output file path (default: stdout)")

	fs.Usage = func() {
		fmt.Println("Usage: mayu sbom generate [options]")
		fmt.Println()
		fmt.Println("Generate an SBOM from lockfiles in CycloneDX or SPDX format.")
		fmt.Println("No authentication required (local operation only).")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Supported lockfiles:")
		fmt.Println("  go.sum, package-lock.json, yarn.lock, pnpm-lock.yaml,")
		fmt.Println("  Pipfile.lock, poetry.lock, Gemfile.lock, Cargo.lock,")
		fmt.Println("  requirements.txt, composer.lock")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  mayu sbom generate --lockfile ./go.sum --format cyclonedx --name my-app --version 1.0.0")
		fmt.Println("  mayu sbom generate --dir . --format spdx --name my-app")
		fmt.Println("  mayu sbom generate --lockfile ./package-lock.json --output sbom.cdx.json")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Validate inputs
	if *lockfilePath == "" && *dir == "" {
		return fmt.Errorf("either --lockfile or --dir is required")
	}
	if *lockfilePath != "" && *dir != "" {
		return fmt.Errorf("--lockfile and --dir are mutually exclusive")
	}

	formatLower := strings.ToLower(*format)
	if formatLower != "cyclonedx" && formatLower != "spdx" {
		return fmt.Errorf("unsupported format: %q (use 'cyclonedx' or 'spdx')", *format)
	}

	// Collect lockfile paths
	var lockfiles []string
	if *lockfilePath != "" {
		lockfiles = []string{*lockfilePath}
	} else {
		found, err := lockfile.FindLockfiles(*dir)
		if err != nil {
			return fmt.Errorf("scan directory: %w", err)
		}
		if len(found) == 0 {
			return fmt.Errorf("no recognized lockfiles found in %q", *dir)
		}
		lockfiles = found
	}

	// Parse all lockfiles and collect components
	var components []sbom.Component
	for _, lf := range lockfiles {
		parser, err := lockfile.Detect(lf)
		if err != nil {
			return fmt.Errorf("detect lockfile %q: %w", lf, err)
		}

		f, err := os.Open(lf)
		if err != nil {
			return fmt.Errorf("open lockfile %q: %w", lf, err)
		}

		comps, err := parser.Parse(lf, f)
		_ = f.Close()
		if err != nil {
			return fmt.Errorf("parse lockfile %q: %w", lf, err)
		}

		components = append(components, comps...)
	}

	// Deduplicate components by purl
	components = deduplicateComponents(components)

	// Build metadata
	meta := sbom.GenerateMetadata{
		Name:      *name,
		Version:   *version,
		Timestamp: time.Now().UTC(),
	}

	// Generate SBOM
	var data []byte
	var err error
	switch formatLower {
	case "cyclonedx":
		data, err = sbom.GenerateCycloneDX(components, meta)
	case "spdx":
		data, err = sbom.GenerateSPDX(components, meta)
	}
	if err != nil {
		return fmt.Errorf("generate SBOM: %w", err)
	}

	// Output
	if *output != "" {
		if err := os.WriteFile(*output, data, 0644); err != nil {
			return fmt.Errorf("write output file: %w", err)
		}
		fmt.Fprintf(os.Stderr, "SBOM generated: %s (%d components, format: %s)\n", *output, len(components), formatLower)
	} else {
		_, err := os.Stdout.Write(data)
		if err != nil {
			return fmt.Errorf("write stdout: %w", err)
		}
		// Add trailing newline for terminal readability
		fmt.Println()
	}

	return nil
}

// deduplicateComponents removes duplicate components based on purl.
// If purl is empty, the component is always kept.
func deduplicateComponents(components []sbom.Component) []sbom.Component {
	seen := make(map[string]struct{}, len(components))
	result := make([]sbom.Component, 0, len(components))
	for _, c := range components {
		if c.Purl == "" {
			result = append(result, c)
			continue
		}
		if _, ok := seen[c.Purl]; ok {
			continue
		}
		seen[c.Purl] = struct{}{}
		result = append(result, c)
	}
	return result
}
