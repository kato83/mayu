package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"text/tabwriter"

	"github.com/kato83/mayu/internal/auth"
	"github.com/kato83/mayu/internal/config"
	"github.com/kato83/mayu/internal/team"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func runTeam(args []string, cfg *config.Config) error {
	if len(args) == 0 {
		printTeamUsage()
		return fmt.Errorf("no subcommand specified (use 'create', 'list', 'add-member', 'remove-member')")
	}

	switch args[0] {
	case "create":
		return runTeamCreate(args[1:], cfg)
	case "list":
		return runTeamList(args[1:], cfg)
	case "add-member":
		return runTeamAddMember(args[1:], cfg)
	case "remove-member":
		return runTeamRemoveMember(args[1:], cfg)
	case "members":
		return runTeamListMembers(args[1:], cfg)
	case "help", "-h", "--help":
		printTeamUsage()
		return nil
	default:
		printTeamUsage()
		return fmt.Errorf("unknown team subcommand: %q", args[0])
	}
}

func runTeamCreate(args []string, cfg *config.Config) error {
	fs := flag.NewFlagSet("team create", flag.ContinueOnError)

	name := fs.String("name", "", "Team name (required)")
	description := fs.String("description", "", "Team description")

	fs.Usage = func() {
		fmt.Println("Usage: mayu team create [options]")
		fmt.Println()
		fmt.Println("Create a new team.")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  mayu team create --name \"platform-team\"")
		fmt.Println("  mayu team create --name \"frontend\" --description \"Frontend engineering team\"")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *name == "" {
		return fmt.Errorf("--name is required")
	}

	db, err := openDB(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	store := team.NewPostgresTeamStore(db)

	t := &team.Team{
		Name:        *name,
		Description: *description,
	}

	id, err := store.CreateTeam(ctx, t)
	if err != nil {
		return fmt.Errorf("create team: %w", err)
	}

	fmt.Println("Team created successfully:")
	fmt.Printf("  ID:          %d\n", id)
	fmt.Printf("  Name:        %s\n", *name)
	if *description != "" {
		fmt.Printf("  Description: %s\n", *description)
	}

	return nil
}

func runTeamList(args []string, cfg *config.Config) error {
	fs := flag.NewFlagSet("team list", flag.ContinueOnError)

	fs.Usage = func() {
		fmt.Println("Usage: mayu team list")
		fmt.Println()
		fmt.Println("List all teams.")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	db, err := openDB(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	store := team.NewPostgresTeamStore(db)

	teams, err := store.ListTeams(ctx)
	if err != nil {
		return fmt.Errorf("list teams: %w", err)
	}

	if len(teams) == 0 {
		fmt.Println("No teams found.")
		return nil
	}

	tw := tabwriter.NewWriter(writerFunc(func(p []byte) (int, error) {
		fmt.Print(string(p))
		return len(p), nil
	}), 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tName\tDescription\tCreated At")
	_, _ = fmt.Fprintln(tw, "--\t----\t-----------\t----------")
	for _, t := range teams {
		_, _ = fmt.Fprintf(tw, "%d\t%s\t%s\t%s\n", t.ID, t.Name, t.Description, t.CreatedAt.Format("2006-01-02"))
	}
	_ = tw.Flush()

	return nil
}

func runTeamAddMember(args []string, cfg *config.Config) error {
	fs := flag.NewFlagSet("team add-member", flag.ContinueOnError)

	teamName := fs.String("team", "", "Team name (required)")
	email := fs.String("email", "", "User email to add (required)")
	role := fs.String("role", "member", "Member role: owner or member")

	fs.Usage = func() {
		fmt.Println("Usage: mayu team add-member [options]")
		fmt.Println()
		fmt.Println("Add a user to a team.")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  mayu team add-member --team platform-team --email user@example.com --role member")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *teamName == "" {
		return fmt.Errorf("--team is required")
	}
	if *email == "" {
		return fmt.Errorf("--email is required")
	}
	if *role != team.RoleOwner && *role != team.RoleMember {
		return fmt.Errorf("invalid role %q: must be 'owner' or 'member'", *role)
	}

	db, err := openDB(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	teamStore := team.NewPostgresTeamStore(db)
	authStore := auth.NewPostgresAuthStore(db)

	// Lookup team by name
	t, err := teamStore.GetTeamByName(ctx, *teamName)
	if err != nil {
		return fmt.Errorf("lookup team: %w", err)
	}
	if t == nil {
		return fmt.Errorf("team %q not found", *teamName)
	}

	// Lookup user by email
	user, err := authStore.GetUserByEmail(ctx, *email)
	if err != nil {
		return fmt.Errorf("lookup user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("user %q not found", *email)
	}

	if err := teamStore.AddMember(ctx, t.ID, user.ID, *role); err != nil {
		return fmt.Errorf("add member: %w", err)
	}

	fmt.Printf("Added %s to team %q as %s.\n", *email, *teamName, *role)
	return nil
}

func runTeamRemoveMember(args []string, cfg *config.Config) error {
	fs := flag.NewFlagSet("team remove-member", flag.ContinueOnError)

	teamName := fs.String("team", "", "Team name (required)")
	email := fs.String("email", "", "User email to remove (required)")

	fs.Usage = func() {
		fmt.Println("Usage: mayu team remove-member [options]")
		fmt.Println()
		fmt.Println("Remove a user from a team.")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *teamName == "" {
		return fmt.Errorf("--team is required")
	}
	if *email == "" {
		return fmt.Errorf("--email is required")
	}

	db, err := openDB(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	teamStore := team.NewPostgresTeamStore(db)
	authStore := auth.NewPostgresAuthStore(db)

	// Lookup team by name
	t, err := teamStore.GetTeamByName(ctx, *teamName)
	if err != nil {
		return fmt.Errorf("lookup team: %w", err)
	}
	if t == nil {
		return fmt.Errorf("team %q not found", *teamName)
	}

	// Lookup user by email
	user, err := authStore.GetUserByEmail(ctx, *email)
	if err != nil {
		return fmt.Errorf("lookup user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("user %q not found", *email)
	}

	if err := teamStore.RemoveMember(ctx, t.ID, user.ID); err != nil {
		return fmt.Errorf("remove member: %w", err)
	}

	fmt.Printf("Removed %s from team %q.\n", *email, *teamName)
	return nil
}

func runTeamListMembers(args []string, cfg *config.Config) error {
	fs := flag.NewFlagSet("team members", flag.ContinueOnError)

	teamName := fs.String("team", "", "Team name (required)")

	fs.Usage = func() {
		fmt.Println("Usage: mayu team members [options]")
		fmt.Println()
		fmt.Println("List members of a team.")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *teamName == "" {
		return fmt.Errorf("--team is required")
	}

	db, err := openDB(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	teamStore := team.NewPostgresTeamStore(db)

	// Lookup team by name
	t, err := teamStore.GetTeamByName(ctx, *teamName)
	if err != nil {
		return fmt.Errorf("lookup team: %w", err)
	}
	if t == nil {
		return fmt.Errorf("team %q not found", *teamName)
	}

	members, err := teamStore.ListMembers(ctx, t.ID)
	if err != nil {
		return fmt.Errorf("list members: %w", err)
	}

	if len(members) == 0 {
		fmt.Printf("Team %q has no members.\n", *teamName)
		return nil
	}

	tw := tabwriter.NewWriter(writerFunc(func(p []byte) (int, error) {
		fmt.Print(string(p))
		return len(p), nil
	}), 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "User ID\tEmail\tName\tRole")
	_, _ = fmt.Fprintln(tw, "-------\t-----\t----\t----")
	for _, m := range members {
		_, _ = fmt.Fprintf(tw, "%d\t%s\t%s\t%s\n", m.UserID, m.Email, m.Name, m.Role)
	}
	_ = tw.Flush()

	return nil
}

// writerFunc adapts a function to the io.Writer interface.
type writerFunc func(p []byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) {
	return f(p)
}

func openDB(cfg *config.Config) (*sql.DB, error) {
	databaseURL := resolveDatabaseURL(cfg)
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("connect to database: %w", err)
	}
	return db, nil
}

func printTeamUsage() {
	fmt.Println("Usage: mayu team <subcommand> [options]")
	fmt.Println()
	fmt.Println("Manage teams and team membership.")
	fmt.Println()
	fmt.Println("Subcommands:")
	fmt.Println("  create         Create a new team")
	fmt.Println("  list           List all teams")
	fmt.Println("  add-member     Add a user to a team")
	fmt.Println("  remove-member  Remove a user from a team")
	fmt.Println("  members        List members of a team")
	fmt.Println()
	fmt.Println("Run 'mayu team <subcommand> --help' for more information.")
}
