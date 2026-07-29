package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"

	"github.com/kato83/mayu/internal/config"
	"github.com/kato83/mayu/internal/sbommon"
	"github.com/kato83/mayu/internal/vex"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func runVEX(args []string, cfg *config.Config) error {
	if len(args) == 0 {
		printVEXUsage()
		return fmt.Errorf("no subcommand specified (use 'export' or 'import')")
	}

	switch args[0] {
	case "export":
		return runVEXExport(args[1:], cfg)
	case "import":
		return runVEXImport(args[1:], cfg)
	case "help", "-h", "--help":
		printVEXUsage()
		return nil
	default:
		printVEXUsage()
		return fmt.Errorf("unknown vex subcommand: %q (use 'export' or 'import')", args[0])
	}
}

func runVEXExport(args []string, cfg *config.Config) error {
	fs := flag.NewFlagSet("vex export", flag.ContinueOnError)

	project := fs.String("project", "", "Project name (required)")
	version := fs.String("version", "", "Version (default: latest)")
	author := fs.String("author", "", "Document author (default: mayu)")
	docID := fs.String("id", "", "Document ID (default: auto-generated)")

	fs.Usage = func() {
		fmt.Println("Usage: mayu vex export [options]")
		fmt.Println()
		fmt.Println("Export finding statuses as an OpenVEX document.")
		fmt.Println()
		fmt.Println("Authentication:")
		fmt.Println("  Set MAYU_API_KEY environment variable or run 'mayu login'.")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  export MAYU_API_KEY=your-api-key")
		fmt.Println("  mayu vex export --project my-app --version 1.0.0")
		fmt.Println("  mayu vex export --project my-app --author security-team@example.com")
		fmt.Println("  mayu vex export --project my-app > product.vex.json")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *project == "" {
		return fmt.Errorf("--project is required")
	}

	// Connect to database
	databaseURL := resolveDatabaseURL(cfg)
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}

	// Authenticate user
	user, err := resolveAuthUserWithDB(ctx, cfg, db)
	if err != nil {
		return err
	}
	userID := user.ID

	// Initialize store
	sbomStore := sbommon.NewPostgresSBOMStore(db)

	// Find project
	proj, err := sbomStore.GetProjectByName(ctx, *project, userID)
	if err != nil {
		return fmt.Errorf("get project: %w", err)
	}
	if proj == nil {
		return fmt.Errorf("project %q not found", *project)
	}

	// Find version
	var ver *sbommon.SBOMVersion
	if *version != "" {
		versions, err := sbomStore.ListVersions(ctx, proj.ID)
		if err != nil {
			return fmt.Errorf("list versions: %w", err)
		}
		for _, v := range versions {
			if v.Version == *version {
				ver, err = sbomStore.GetVersion(ctx, v.ID)
				if err != nil {
					return fmt.Errorf("get version: %w", err)
				}
				break
			}
		}
		if ver == nil {
			return fmt.Errorf("version %q not found in project %q", *version, *project)
		}
	} else {
		ver, err = sbomStore.GetLatestVersion(ctx, proj.ID)
		if err != nil {
			return fmt.Errorf("get latest version: %w", err)
		}
		if ver == nil {
			return fmt.Errorf("no versions found for project %q", *project)
		}
	}

	// Get all finding statuses for this version
	statuses, err := sbomStore.ListFindingStatuses(ctx, ver.ID, nil)
	if err != nil {
		return fmt.Errorf("list finding statuses: %w", err)
	}

	if len(statuses) == 0 {
		return fmt.Errorf("no finding statuses for project %q version %q", *project, ver.Version)
	}

	// Export as OpenVEX
	data, err := vex.ExportJSON(statuses, vex.ExportOptions{
		Author:     *author,
		DocumentID: *docID,
	})
	if err != nil {
		return fmt.Errorf("export VEX: %w", err)
	}

	fmt.Println(string(data))
	return nil
}

func runVEXImport(args []string, cfg *config.Config) error {
	fs := flag.NewFlagSet("vex import", flag.ContinueOnError)

	project := fs.String("project", "", "Project name (required)")
	version := fs.String("version", "", "Version (default: latest)")
	filePath := fs.String("file", "", "Path to OpenVEX file (required)")

	fs.Usage = func() {
		fmt.Println("Usage: mayu vex import [options]")
		fmt.Println()
		fmt.Println("Import an OpenVEX document and apply finding statuses.")
		fmt.Println()
		fmt.Println("Authentication:")
		fmt.Println("  Set MAYU_API_KEY environment variable or run 'mayu login'.")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  export MAYU_API_KEY=your-api-key")
		fmt.Println("  mayu vex import --project my-app --version 1.0.0 --file product.vex.json")
		fmt.Println("  mayu vex import --project my-app --file product.vex.json")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *project == "" {
		return fmt.Errorf("--project is required")
	}
	if *filePath == "" {
		return fmt.Errorf("--file is required")
	}

	// Parse VEX file
	result, err := vex.ImportFile(*filePath)
	if err != nil {
		return fmt.Errorf("import VEX: %w", err)
	}

	// Connect to database
	databaseURL := resolveDatabaseURL(cfg)
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}

	// Authenticate user
	user, err := resolveAuthUserWithDB(ctx, cfg, db)
	if err != nil {
		return err
	}
	userID := user.ID

	// Initialize store
	sbomStore := sbommon.NewPostgresSBOMStore(db)

	// Find project
	proj, err := sbomStore.GetProjectByName(ctx, *project, userID)
	if err != nil {
		return fmt.Errorf("get project: %w", err)
	}
	if proj == nil {
		return fmt.Errorf("project %q not found", *project)
	}

	// Find version
	var ver *sbommon.SBOMVersion
	if *version != "" {
		versions, err := sbomStore.ListVersions(ctx, proj.ID)
		if err != nil {
			return fmt.Errorf("list versions: %w", err)
		}
		for _, v := range versions {
			if v.Version == *version {
				ver, err = sbomStore.GetVersion(ctx, v.ID)
				if err != nil {
					return fmt.Errorf("get version: %w", err)
				}
				break
			}
		}
		if ver == nil {
			return fmt.Errorf("version %q not found in project %q", *version, *project)
		}
	} else {
		ver, err = sbomStore.GetLatestVersion(ctx, proj.ID)
		if err != nil {
			return fmt.Errorf("get latest version: %w", err)
		}
		if ver == nil {
			return fmt.Errorf("no versions found for project %q", *project)
		}
	}

	// Apply each status from the VEX document
	applied := 0
	for _, fs := range result.Statuses {
		fs.VersionID = ver.ID
		fs.UpdatedBy = userID
		_, err := sbomStore.UpsertFindingStatus(ctx, &fs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to apply status for %s (%s): %v\n", fs.VulnID, fs.Purl, err)
			continue
		}
		applied++
	}

	fmt.Printf("VEX import complete:\n")
	fmt.Printf("  File:       %s\n", *filePath)
	fmt.Printf("  Project:    %s\n", proj.Name)
	fmt.Printf("  Version:    %s\n", ver.Version)
	fmt.Printf("  Statements: %d\n", result.TotalStatements)
	fmt.Printf("  Applied:    %d\n", applied)

	return nil
}

func printVEXUsage() {
	fmt.Println("Usage: mayu vex <subcommand> [options]")
	fmt.Println()
	fmt.Println("Manage VEX (Vulnerability Exploitability eXchange) documents.")
	fmt.Println()
	fmt.Println("Authentication:")
	fmt.Println("  All subcommands require the MAYU_API_KEY environment variable to be set.")
	fmt.Println()
	fmt.Println("Subcommands:")
	fmt.Println("  export    Export finding statuses as an OpenVEX document")
	fmt.Println("  import    Import an OpenVEX document and apply finding statuses")
	fmt.Println()
	fmt.Println("Run 'mayu vex <subcommand> --help' for more information.")
}
