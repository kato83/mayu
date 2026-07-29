package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"time"

	"github.com/kato83/mayu/internal/auth"
	"github.com/kato83/mayu/internal/config"
	"github.com/kato83/mayu/internal/credentials"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// resolveAuthUser authenticates the user using the following priority:
// 1. MAYU_API_KEY environment variable
// 2. Stored session token from credentials.json
// 3. Returns an error with a helpful message
//
// It opens a database connection internally. Use resolveAuthUserWithDB if you
// already have a *sql.DB open.
func resolveAuthUser(ctx context.Context, cfg *config.Config) (*auth.User, *sql.DB, error) {
	apiKey := os.Getenv("MAYU_API_KEY")

	// Priority 1: API key from environment
	if apiKey != "" {
		databaseURL := resolveDatabaseURL(cfg)
		db, err := sql.Open("pgx", databaseURL)
		if err != nil {
			return nil, nil, fmt.Errorf("open database: %w", err)
		}
		if err := db.PingContext(ctx); err != nil {
			_ = db.Close()
			return nil, nil, fmt.Errorf("connect to database: %w", err)
		}

		authStore := auth.NewPostgresAuthStore(db)
		authProvider := auth.NewLocalAuthProvider(authStore, authStore, authStore, cfg.Auth.SessionMaxAge)
		user, err := authProvider.ValidateAPIKey(ctx, apiKey)
		if err != nil {
			_ = db.Close()
			return nil, nil, fmt.Errorf("authenticate: %w", err)
		}
		return user, db, nil
	}

	// Priority 2: Stored session token
	creds, err := credentials.Load()
	if err == nil && creds != nil && creds.SessionToken != "" {
		if time.Now().Before(creds.ExpiresAt) {
			databaseURL := resolveDatabaseURL(cfg)
			db, err := sql.Open("pgx", databaseURL)
			if err != nil {
				return nil, nil, fmt.Errorf("open database: %w", err)
			}
			if err := db.PingContext(ctx); err != nil {
				_ = db.Close()
				return nil, nil, fmt.Errorf("connect to database: %w", err)
			}

			authStore := auth.NewPostgresAuthStore(db)
			authProvider := auth.NewLocalAuthProvider(authStore, authStore, authStore, cfg.Auth.SessionMaxAge)
			user, err := authProvider.ValidateSession(ctx, creds.SessionToken)
			if err != nil {
				_ = db.Close()
				return nil, nil, fmt.Errorf("session validation failed (try 'mayu login' to re-authenticate): %w", err)
			}
			return user, db, nil
		}
		// Session is expired
		return nil, nil, fmt.Errorf("session expired: run 'mayu login' to re-authenticate")
	}

	// Priority 3: No auth available
	return nil, nil, fmt.Errorf("authentication required: set MAYU_API_KEY environment variable or run 'mayu login'")
}

// resolveAuthUserWithDB authenticates the user using the following priority:
// 1. MAYU_API_KEY environment variable
// 2. Stored session token from credentials.json
// 3. Returns an error with a helpful message
//
// It uses the provided *sql.DB connection.
func resolveAuthUserWithDB(ctx context.Context, cfg *config.Config, db *sql.DB) (*auth.User, error) {
	apiKey := os.Getenv("MAYU_API_KEY")

	// Priority 1: API key from environment
	if apiKey != "" {
		authStore := auth.NewPostgresAuthStore(db)
		authProvider := auth.NewLocalAuthProvider(authStore, authStore, authStore, cfg.Auth.SessionMaxAge)
		user, err := authProvider.ValidateAPIKey(ctx, apiKey)
		if err != nil {
			return nil, fmt.Errorf("authenticate: %w", err)
		}
		return user, nil
	}

	// Priority 2: Stored session token
	creds, err := credentials.Load()
	if err == nil && creds != nil && creds.SessionToken != "" {
		if time.Now().Before(creds.ExpiresAt) {
			authStore := auth.NewPostgresAuthStore(db)
			authProvider := auth.NewLocalAuthProvider(authStore, authStore, authStore, cfg.Auth.SessionMaxAge)
			user, err := authProvider.ValidateSession(ctx, creds.SessionToken)
			if err != nil {
				return nil, fmt.Errorf("session validation failed (try 'mayu login' to re-authenticate): %w", err)
			}
			return user, nil
		}
		// Session is expired
		return nil, fmt.Errorf("session expired: run 'mayu login' to re-authenticate")
	}

	// Priority 3: No auth available
	return nil, fmt.Errorf("authentication required: set MAYU_API_KEY environment variable or run 'mayu login'")
}
