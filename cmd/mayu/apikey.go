package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/kato83/mayu/internal/auth"
	"github.com/kato83/mayu/internal/config"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func runAPIKey(args []string, cfg *config.Config) error {
	if len(args) == 0 {
		printAPIKeyUsage()
		return fmt.Errorf("no subcommand specified (use 'create')")
	}

	switch args[0] {
	case "create":
		return runAPIKeyCreate(args[1:], cfg)
	case "help", "-h", "--help":
		printAPIKeyUsage()
		return nil
	default:
		printAPIKeyUsage()
		return fmt.Errorf("unknown apikey subcommand: %q (use 'create')", args[0])
	}
}

func runAPIKeyCreate(args []string, cfg *config.Config) error {
	fs := flag.NewFlagSet("apikey create", flag.ContinueOnError)

	userEmail := fs.String("user-email", "", "Email of the user to associate the key with (required)")
	name := fs.String("name", "", "Description/name for the API key")
	expires := fs.String("expires", "", "Expiration duration (e.g., '90d', '1y', '24h')")

	fs.Usage = func() {
		fmt.Println("Usage: mayu apikey create [options]")
		fmt.Println()
		fmt.Println("Create a new API key for a user.")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  mayu apikey create --user-email admin@example.com --name 'CI Pipeline'")
		fmt.Println("  mayu apikey create --user-email admin@example.com --name 'Temp Key' --expires 90d")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Validate required fields
	if *userEmail == "" {
		return fmt.Errorf("--user-email is required")
	}

	// Parse expiration duration
	var expiresAt *time.Time
	if *expires != "" {
		duration, err := parseDuration(*expires)
		if err != nil {
			return fmt.Errorf("invalid --expires value %q: %w", *expires, err)
		}
		t := time.Now().Add(duration)
		expiresAt = &t
	}

	// Generate random 32-byte API key
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return fmt.Errorf("generate random key: %w", err)
	}
	rawKey := "mayu_" + hex.EncodeToString(keyBytes)

	// Compute hash and prefix
	keyHash := auth.HashAPIKey(rawKey)
	keyPrefix := auth.APIKeyPrefix(rawKey)

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

	// Lookup user by email
	store := auth.NewPostgresAuthStore(db)
	user, err := store.GetUserByEmail(ctx, *userEmail)
	if err != nil {
		return fmt.Errorf("lookup user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("user not found with email: %s", *userEmail)
	}

	// Create API key record
	apiKey, err := store.CreateAPIKey(ctx, user.ID, *name, keyHash, keyPrefix, expiresAt)
	if err != nil {
		return fmt.Errorf("create api key: %w", err)
	}

	fmt.Println("API key created successfully:")
	fmt.Printf("  ID:      %d\n", apiKey.ID)
	fmt.Printf("  User:    %s\n", *userEmail)
	if apiKey.Name != "" {
		fmt.Printf("  Name:    %s\n", apiKey.Name)
	}
	fmt.Printf("  Prefix:  %s\n", apiKey.KeyPrefix)
	if apiKey.ExpiresAt != nil {
		fmt.Printf("  Expires: %s\n", apiKey.ExpiresAt.Format(time.RFC3339))
	}
	fmt.Println()
	fmt.Println("  API Key: " + rawKey)
	fmt.Println()
	fmt.Println("  WARNING: This is the only time the full API key will be displayed.")
	fmt.Println("  Store it securely. It cannot be recovered.")

	return nil
}

// parseDuration parses duration strings like "90d", "1y", "24h", "30m".
func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}

	// Try standard Go duration first (handles h, m, s)
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}

	// Handle custom suffixes: d (days), y (years)
	suffix := s[len(s)-1]
	numStr := s[:len(s)-1]
	num, err := strconv.Atoi(numStr)
	if err != nil {
		return 0, fmt.Errorf("invalid duration format: %s", s)
	}
	if num <= 0 {
		return 0, fmt.Errorf("duration must be positive: %s", s)
	}

	switch suffix {
	case 'd':
		return time.Duration(num) * 24 * time.Hour, nil
	case 'y':
		return time.Duration(num) * 365 * 24 * time.Hour, nil
	default:
		return 0, fmt.Errorf("unknown duration suffix %q in %q (use h, d, or y)", string(suffix), s)
	}
}

func printAPIKeyUsage() {
	fmt.Println("Usage: mayu apikey <subcommand> [options]")
	fmt.Println()
	fmt.Println("Manage API keys.")
	fmt.Println()
	fmt.Println("Subcommands:")
	fmt.Println("  create    Create a new API key")
	fmt.Println()
	fmt.Println("Run 'mayu apikey <subcommand> --help' for more information.")
}
