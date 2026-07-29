package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"

	"github.com/kato83/mayu/internal/auth"
	"github.com/kato83/mayu/internal/config"
	"github.com/kato83/mayu/internal/credentials"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func runLogout(args []string, cfg *config.Config) error {
	fs := flag.NewFlagSet("logout", flag.ContinueOnError)

	fs.Usage = func() {
		fmt.Println("Usage: mayu logout")
		fmt.Println()
		fmt.Println("Log out by deleting stored session credentials.")
		fmt.Println("Optionally invalidates the session on the server (best-effort).")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	creds, err := credentials.Load()
	if err != nil {
		// Can't load credentials, just try to delete the file
		_ = credentials.Delete()
		fmt.Println("Logged out.")
		return nil
	}

	if creds == nil {
		fmt.Println("Not logged in.")
		return nil
	}

	// Best-effort: try to invalidate the session on the server
	if creds.SessionToken != "" {
		invalidateSession(cfg, creds.SessionToken)
	}

	// Delete local credentials
	if err := credentials.Delete(); err != nil {
		return fmt.Errorf("delete credentials: %w", err)
	}

	fmt.Println("Logged out successfully.")
	return nil
}

// invalidateSession attempts to delete the session from the database.
// This is best-effort and does not return errors.
func invalidateSession(cfg *config.Config, sessionToken string) {
	databaseURL := resolveDatabaseURL(cfg)
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		return
	}

	authStore := auth.NewPostgresAuthStore(db)
	authProvider := auth.NewLocalAuthProvider(authStore, authStore, authStore, 0)
	_ = authProvider.DeleteSession(ctx, sessionToken)
}
