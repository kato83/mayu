package main

import (
	"flag"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"

	"github.com/kato83/mayu/internal/config"
	migrations "github.com/kato83/mayu/migrations"
)

func runMigrate(args []string, cfg *config.Config) error {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)

	steps := fs.Int("steps", 0, "Number of migrations to apply (0 = all). Negative to roll back.")

	fs.Usage = func() {
		fmt.Println("Usage: mayu migrate [up|down|status] [options]")
		fmt.Println()
		fmt.Println("Run database migrations.")
		fmt.Println()
		fmt.Println("Subcommands:")
		fmt.Println("  up       Apply all pending migrations (default)")
		fmt.Println("  down     Roll back one migration (or --steps N)")
		fmt.Println("  status   Show current migration version")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  mayu migrate                 # Apply all pending migrations")
		fmt.Println("  mayu migrate up")
		fmt.Println("  mayu migrate down")
		fmt.Println("  mayu migrate down --steps 3  # Roll back 3 migrations")
		fmt.Println("  mayu migrate status")
	}

	// Parse subcommand before flags
	action := "up"
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		action = args[0]
		args = args[1:]
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	databaseURL := resolveDatabaseURL(cfg)

	// Create migrate instance using embedded migrations
	source, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return fmt.Errorf("create migration source: %w", err)
	}

	m, err := migrate.NewWithSourceInstance("iofs", source, databaseURL)
	if err != nil {
		return fmt.Errorf("create migrator: %w", err)
	}
	defer func() { _, _ = m.Close() }()

	switch action {
	case "up":
		if *steps > 0 {
			err = m.Steps(*steps)
		} else {
			err = m.Up()
		}
		if err == migrate.ErrNoChange {
			fmt.Println("No pending migrations.")
			return nil
		}
		if err != nil {
			return fmt.Errorf("migrate up: %w", err)
		}
		v, dirty, _ := m.Version()
		fmt.Printf("Migrations applied successfully. Current version: %d (dirty: %v)\n", v, dirty)

	case "down":
		n := 1
		if *steps != 0 {
			if *steps > 0 {
				n = *steps
			} else {
				n = -*steps
			}
		}
		err = m.Steps(-n)
		if err == migrate.ErrNoChange {
			fmt.Println("No migrations to roll back.")
			return nil
		}
		if err != nil {
			return fmt.Errorf("migrate down: %w", err)
		}
		v, dirty, verr := m.Version()
		if verr != nil {
			fmt.Println("Rolled back to clean state (no migrations applied).")
		} else {
			fmt.Printf("Rolled back successfully. Current version: %d (dirty: %v)\n", v, dirty)
		}

	case "status":
		v, dirty, err := m.Version()
		if err == migrate.ErrNilVersion {
			fmt.Println("No migrations have been applied yet.")
			return nil
		}
		if err != nil {
			return fmt.Errorf("get version: %w", err)
		}
		fmt.Printf("Current version: %d (dirty: %v)\n", v, dirty)

	default:
		return fmt.Errorf("unknown migrate action: %q (use up, down, or status)", action)
	}

	return nil
}
