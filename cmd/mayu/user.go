package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/kato83/mayu/internal/auth"
	"github.com/kato83/mayu/internal/config"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func runUser(args []string, cfg *config.Config) error {
	if len(args) == 0 {
		printUserUsage()
		return fmt.Errorf("no subcommand specified (use 'create', 'list', or 'update')")
	}

	switch args[0] {
	case "create":
		return runUserCreate(args[1:], cfg)
	case "list":
		return runUserList(args[1:], cfg)
	case "update":
		return runUserUpdate(args[1:], cfg)
	case "help", "-h", "--help":
		printUserUsage()
		return nil
	default:
		printUserUsage()
		return fmt.Errorf("unknown user subcommand: %q (use 'create', 'list', or 'update')", args[0])
	}
}

func runUserCreate(args []string, cfg *config.Config) error {
	fs := flag.NewFlagSet("user create", flag.ContinueOnError)

	email := fs.String("email", "", "User email address (required)")
	name := fs.String("name", "", "User display name")
	role := fs.String("role", "viewer", "User role: admin or viewer")
	password := fs.String("password", "", "User password (required for local auth mode)")

	fs.Usage = func() {
		fmt.Println("Usage: mayu user create [options]")
		fmt.Println()
		fmt.Println("Create a new user account.")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  mayu user create --email admin@example.com --name Admin --role admin --password secret")
		fmt.Println("  mayu user create --email viewer@example.com --role viewer --password mypass")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Validate required fields
	if *email == "" {
		return fmt.Errorf("--email is required")
	}

	// Validate role
	*role = strings.ToLower(*role)
	if *role != auth.RoleAdmin && *role != auth.RoleViewer {
		return fmt.Errorf("invalid role %q: must be 'admin' or 'viewer'", *role)
	}

	// Password is required for local auth mode
	if *password == "" {
		return fmt.Errorf("--password is required")
	}

	// Hash the password
	passwordHash, err := auth.HashPassword(*password)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
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

	// Create user
	store := auth.NewPostgresAuthStore(db)
	user, err := store.CreateUser(ctx, *email, *name, *role, passwordHash)
	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}

	fmt.Println("User created successfully:")
	fmt.Printf("  ID:    %d\n", user.ID)
	fmt.Printf("  Email: %s\n", user.Email)
	fmt.Printf("  Name:  %s\n", user.Name)
	fmt.Printf("  Role:  %s\n", user.Role)

	return nil
}

func runUserList(args []string, cfg *config.Config) error {
	fs := flag.NewFlagSet("user list", flag.ContinueOnError)

	fs.Usage = func() {
		fmt.Println("Usage: mayu user list")
		fmt.Println()
		fmt.Println("List all users.")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
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

	// List users
	store := auth.NewPostgresAuthStore(db)
	users, err := store.ListUsers(ctx)
	if err != nil {
		return fmt.Errorf("list users: %w", err)
	}

	if len(users) == 0 {
		fmt.Println("No users found.")
		return nil
	}

	// Print table
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintf(w, "ID\tEMAIL\tNAME\tROLE\n")
	for _, u := range users {
		_, _ = fmt.Fprintf(w, "%d\t%s\t%s\t%s\n", u.ID, u.Email, u.Name, u.Role)
	}
	return w.Flush()
}

func printUserUsage() {
	fmt.Println("Usage: mayu user <subcommand> [options]")
	fmt.Println()
	fmt.Println("Manage user accounts.")
	fmt.Println()
	fmt.Println("Subcommands:")
	fmt.Println("  create    Create a new user")
	fmt.Println("  list      List all users")
	fmt.Println("  update    Update an existing user")
	fmt.Println()
	fmt.Println("Run 'mayu user <subcommand> --help' for more information.")
}

func runUserUpdate(args []string, cfg *config.Config) error {
	fs := flag.NewFlagSet("user update", flag.ContinueOnError)

	email := fs.String("email", "", "User email address to update (required)")
	role := fs.String("role", "", "New role: admin or viewer (required)")

	fs.Usage = func() {
		fmt.Println("Usage: mayu user update [options]")
		fmt.Println()
		fmt.Println("Update an existing user's role.")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  mayu user update --email user@example.com --role admin")
		fmt.Println("  mayu user update --email user@example.com --role viewer")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Validate required fields
	if *email == "" {
		return fmt.Errorf("--email is required")
	}
	if *role == "" {
		return fmt.Errorf("--role is required")
	}

	// Validate role
	*role = strings.ToLower(*role)
	if *role != auth.RoleAdmin && *role != auth.RoleViewer {
		return fmt.Errorf("invalid role %q: must be 'admin' or 'viewer'", *role)
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

	// Update user role
	store := auth.NewPostgresAuthStore(db)
	user, err := store.UpdateUserRole(ctx, *email, *role)
	if err != nil {
		return fmt.Errorf("update user: %w", err)
	}

	fmt.Println("User updated successfully:")
	fmt.Printf("  ID:    %d\n", user.ID)
	fmt.Printf("  Email: %s\n", user.Email)
	fmt.Printf("  Name:  %s\n", user.Name)
	fmt.Printf("  Role:  %s\n", user.Role)

	return nil
}
