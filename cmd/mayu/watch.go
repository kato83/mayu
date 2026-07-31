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
	"github.com/kato83/mayu/internal/watchlist"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// triagePriorityMinFlag holds the parsed --triage-priority-min value for watchlist filtering.
// When set, only vulnerabilities with triage priority at or above this level will trigger notifications.
var triagePriorityMinFlag string

func runWatch(args []string, cfg *config.Config) error {
	if len(args) == 0 {
		printWatchUsage()
		return fmt.Errorf("no subcommand specified (use 'add', 'list', 'remove', or 'check')")
	}

	switch args[0] {
	case "add":
		return runWatchAdd(args[1:], cfg)
	case "list":
		return runWatchList(args[1:], cfg)
	case "remove":
		return runWatchRemove(args[1:], cfg)
	case "check":
		return runWatchCheck(args[1:], cfg)
	case "help", "-h", "--help":
		printWatchUsage()
		return nil
	default:
		printWatchUsage()
		return fmt.Errorf("unknown watch subcommand: %q (use 'add', 'list', 'remove', or 'check')", args[0])
	}
}

func runWatchAdd(args []string, cfg *config.Config) error {
	fs := flag.NewFlagSet("watch add", flag.ContinueOnError)

	name := fs.String("name", "", "Watchlist entry name (required)")
	matchType := fs.String("type", "", "Match type: package, purl, cpe, ecosystem (required)")
	ecosystem := fs.String("ecosystem", "", "Ecosystem name (required for package/ecosystem types)")
	packageName := fs.String("package", "", "Package name (required for package type)")
	purlPattern := fs.String("purl", "", "Purl pattern for prefix matching (required for purl type)")
	cpePattern := fs.String("cpe", "", "CPE pattern for prefix matching (required for cpe type)")
	severityMin := fs.String("severity-min", "", "Minimum severity: critical, high, medium, low, none")
	epssThreshold := fs.Float64("epss-threshold", 0, "Minimum EPSS score threshold (0.0-1.0)")
	triagePriorityMin := fs.String("triage-priority-min", "", "Minimum triage priority level for notification (critical, high, medium, low)")
	userEmail := fs.String("user-email", "", "Email of the user who owns this watchlist (required)")

	fs.Usage = func() {
		fmt.Println("Usage: mayu watch add [options]")
		fmt.Println()
		fmt.Println("Add a new watchlist entry.")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  mayu watch add --name 'Go crypto' --type package --ecosystem Go --package golang.org/x/crypto --user-email admin@example.com")
		fmt.Println("  mayu watch add --name 'Express' --type purl --purl pkg:npm/express --user-email admin@example.com")
		fmt.Println("  mayu watch add --name 'Apache HTTPD' --type cpe --cpe 'cpe:2.3:a:apache:http_server' --user-email admin@example.com")
		fmt.Println("  mayu watch add --name 'Go Critical' --type ecosystem --ecosystem Go --severity-min critical --user-email admin@example.com")
		fmt.Println("  mayu watch add --name 'KEV Criticals' --type ecosystem --ecosystem Go --triage-priority-min critical --user-email admin@example.com")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Validate required fields
	if *name == "" {
		return fmt.Errorf("--name is required")
	}
	if *matchType == "" {
		return fmt.Errorf("--type is required")
	}
	if *userEmail == "" {
		return fmt.Errorf("--user-email is required")
	}

	// Validate match type
	*matchType = strings.ToLower(*matchType)
	validTypes := map[string]bool{
		watchlist.MatchTypePackage:   true,
		watchlist.MatchTypePurl:      true,
		watchlist.MatchTypeCPE:       true,
		watchlist.MatchTypeEcosystem: true,
	}
	if !validTypes[*matchType] {
		return fmt.Errorf("invalid --type %q: must be one of package, purl, cpe, ecosystem", *matchType)
	}

	// Validate type-specific required fields
	switch *matchType {
	case watchlist.MatchTypePackage:
		if *ecosystem == "" {
			return fmt.Errorf("--ecosystem is required for type 'package'")
		}
		if *packageName == "" {
			return fmt.Errorf("--package is required for type 'package'")
		}
	case watchlist.MatchTypePurl:
		if *purlPattern == "" {
			return fmt.Errorf("--purl is required for type 'purl'")
		}
	case watchlist.MatchTypeCPE:
		if *cpePattern == "" {
			return fmt.Errorf("--cpe is required for type 'cpe'")
		}
	case watchlist.MatchTypeEcosystem:
		if *ecosystem == "" {
			return fmt.Errorf("--ecosystem is required for type 'ecosystem'")
		}
	}

	// Parse severity
	var sevMin *int16
	if *severityMin != "" {
		sev, err := parseSeverityLabel(*severityMin)
		if err != nil {
			return err
		}
		sevMin = &sev
	}

	// Parse EPSS threshold
	var epssThreshPtr *float64
	if *epssThreshold > 0 {
		if *epssThreshold < 0.0 || *epssThreshold > 1.0 {
			return fmt.Errorf("--epss-threshold must be between 0.0 and 1.0")
		}
		epssThreshPtr = epssThreshold
	}

	// Validate triage-priority-min if specified
	if *triagePriorityMin != "" {
		if _, err := watchlist.ParseTriagePriorityMin(*triagePriorityMin); err != nil {
			return err
		}
		triagePriorityMinFlag = *triagePriorityMin
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

	// Lookup user by email
	authStore := auth.NewPostgresAuthStore(db)
	user, err := authStore.GetUserByEmail(ctx, *userEmail)
	if err != nil {
		return fmt.Errorf("lookup user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("user not found with email: %s", *userEmail)
	}

	// Build watchlist entry
	wl := &watchlist.Watchlist{
		UserID:    user.ID,
		Name:      *name,
		MatchType: *matchType,
		Enabled:   true,
	}

	if *ecosystem != "" {
		wl.Ecosystem = ecosystem
	}
	if *packageName != "" {
		wl.PackageName = packageName
	}
	if *purlPattern != "" {
		wl.PurlPattern = purlPattern
	}
	if *cpePattern != "" {
		wl.CpePattern = cpePattern
	}
	if sevMin != nil {
		wl.SeverityMin = sevMin
	}
	if epssThreshPtr != nil {
		wl.EpssThreshold = epssThreshPtr
	}

	// Create watchlist
	store := watchlist.NewPostgresWatchlistStore(db)
	id, err := store.CreateWatchlist(ctx, wl)
	if err != nil {
		return fmt.Errorf("create watchlist: %w", err)
	}

	fmt.Println("Watchlist entry created:")
	fmt.Printf("  ID:   %d\n", id)
	fmt.Printf("  Name: %s\n", *name)
	fmt.Printf("  Type: %s\n", *matchType)
	fmt.Printf("  User: %s\n", *userEmail)

	return nil
}

func runWatchList(args []string, cfg *config.Config) error {
	fs := flag.NewFlagSet("watch list", flag.ContinueOnError)

	userEmail := fs.String("user-email", "", "Email of the user whose watchlists to list (required)")

	fs.Usage = func() {
		fmt.Println("Usage: mayu watch list [options]")
		fmt.Println()
		fmt.Println("List watchlist entries for a user.")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *userEmail == "" {
		return fmt.Errorf("--user-email is required")
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

	// Lookup user by email
	authStore := auth.NewPostgresAuthStore(db)
	user, err := authStore.GetUserByEmail(ctx, *userEmail)
	if err != nil {
		return fmt.Errorf("lookup user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("user not found with email: %s", *userEmail)
	}

	// List watchlists
	store := watchlist.NewPostgresWatchlistStore(db)
	watchlists, err := store.ListWatchlists(ctx, user.ID)
	if err != nil {
		return fmt.Errorf("list watchlists: %w", err)
	}

	if len(watchlists) == 0 {
		fmt.Println("No watchlist entries found.")
		return nil
	}

	// Print table
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintf(w, "ID\tNAME\tTYPE\tENABLED\tCRITERIA\n")
	for _, wl := range watchlists {
		criteria := formatCriteria(wl)
		enabled := "yes"
		if !wl.Enabled {
			enabled = "no"
		}
		_, _ = fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n", wl.ID, wl.Name, wl.MatchType, enabled, criteria)
	}
	return w.Flush()
}

func runWatchRemove(args []string, cfg *config.Config) error {
	fs := flag.NewFlagSet("watch remove", flag.ContinueOnError)

	id := fs.Int64("id", 0, "Watchlist entry ID to remove (required)")
	userEmail := fs.String("user-email", "", "Email of the user who owns the watchlist (required)")

	fs.Usage = func() {
		fmt.Println("Usage: mayu watch remove [options]")
		fmt.Println()
		fmt.Println("Remove a watchlist entry.")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *id == 0 {
		return fmt.Errorf("--id is required")
	}
	if *userEmail == "" {
		return fmt.Errorf("--user-email is required")
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

	// Lookup user by email
	authStore := auth.NewPostgresAuthStore(db)
	user, err := authStore.GetUserByEmail(ctx, *userEmail)
	if err != nil {
		return fmt.Errorf("lookup user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("user not found with email: %s", *userEmail)
	}

	// Delete watchlist
	store := watchlist.NewPostgresWatchlistStore(db)
	if err := store.DeleteWatchlist(ctx, *id, user.ID); err != nil {
		return fmt.Errorf("delete watchlist: %w", err)
	}

	fmt.Printf("Watchlist entry %d removed.\n", *id)
	return nil
}

func runWatchCheck(args []string, cfg *config.Config) error {
	fs := flag.NewFlagSet("watch check", flag.ContinueOnError)

	dryRun := fs.Bool("dry-run", false, "Show matches without recording or notifying")

	fs.Usage = func() {
		fmt.Println("Usage: mayu watch check [options]")
		fmt.Println()
		fmt.Println("Check all active watchlists against the vulnerability database.")
		fmt.Println("Finds new matches that haven't been recorded yet (e.g., EPSS score")
		fmt.Println("crossed threshold since last check). Designed for cron/periodic execution.")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  mayu watch check                # Run full check, record & notify")
		fmt.Println("  mayu watch check --dry-run      # Preview matches without recording")
		fmt.Println()
		fmt.Println("Cron example (check every hour):")
		fmt.Println("  0 * * * * /usr/local/bin/mayu watch check")
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

	// Create watchlist store and matcher
	wlStore := watchlist.NewPostgresWatchlistStore(db)

	if *dryRun {
		return runWatchCheckDryRun(ctx, wlStore)
	}

	// Create matcher with the full store (supports FindMatchingVulnerabilities)
	vulnDataProvider := watchlist.NewPostgresVulnDataProvider(db)
	matcher := watchlist.NewMatcher(wlStore, vulnDataProvider)

	// TODO: wire webhook NotifyFunc if configured

	results, err := matcher.CheckAll(ctx)
	if err != nil {
		return fmt.Errorf("watch check: %w", err)
	}

	if len(results) == 0 {
		fmt.Println("No new matches found.")
		return nil
	}

	// Print results
	totalMatches := 0
	for _, r := range results {
		totalMatches += len(r.NewMatches)
		fmt.Printf("  [%s] %d new match(es)\n", r.WatchlistName, len(r.NewMatches))
		for _, id := range r.NewMatches {
			if len(r.NewMatches) <= 10 {
				fmt.Printf("    - %s\n", id)
			}
		}
		if len(r.NewMatches) > 10 {
			fmt.Printf("    ... and %d more\n", len(r.NewMatches)-10)
		}
	}
	fmt.Printf("\nTotal: %d new match(es) across %d watchlist(s).\n", totalMatches, len(results))

	return nil
}

func runWatchCheckDryRun(ctx context.Context, wlStore *watchlist.PostgresWatchlistStore) error {
	// Get all active watchlists
	watchlists, err := wlStore.GetActiveWatchlists(ctx)
	if err != nil {
		return fmt.Errorf("get active watchlists: %w", err)
	}

	if len(watchlists) == 0 {
		fmt.Println("No active watchlists found.")
		return nil
	}

	fmt.Printf("Checking %d active watchlist(s) (dry-run)...\n\n", len(watchlists))

	totalMatches := 0
	for _, wl := range watchlists {
		vulnIDs, err := wlStore.FindMatchingVulnerabilities(ctx, wl)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ [%s] error: %v\n", wl.Name, err)
			continue
		}

		if len(vulnIDs) == 0 {
			fmt.Printf("  [%s] no new matches\n", wl.Name)
			continue
		}

		totalMatches += len(vulnIDs)
		fmt.Printf("  [%s] %d new match(es) (would be recorded)\n", wl.Name, len(vulnIDs))
		limit := 10
		if len(vulnIDs) < limit {
			limit = len(vulnIDs)
		}
		for _, id := range vulnIDs[:limit] {
			fmt.Printf("    - %s\n", id)
		}
		if len(vulnIDs) > 10 {
			fmt.Printf("    ... and %d more\n", len(vulnIDs)-10)
		}
	}

	fmt.Printf("\nTotal: %d new match(es) would be recorded (dry-run, no changes made).\n", totalMatches)
	return nil
}

// parseSeverityLabel converts severity label strings to the 1-5 numeric scale.
func parseSeverityLabel(label string) (int16, error) {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "critical":
		return 5, nil
	case "high":
		return 4, nil
	case "medium":
		return 3, nil
	case "low":
		return 2, nil
	case "none":
		return 1, nil
	default:
		return 0, fmt.Errorf("invalid --severity-min %q: must be one of critical, high, medium, low, none", label)
	}
}

// formatCriteria formats the matching criteria for display.
func formatCriteria(wl *watchlist.Watchlist) string {
	var parts []string
	switch wl.MatchType {
	case watchlist.MatchTypePackage:
		if wl.Ecosystem != nil && wl.PackageName != nil {
			parts = append(parts, *wl.Ecosystem+"/"+*wl.PackageName)
		}
	case watchlist.MatchTypePurl:
		if wl.PurlPattern != nil {
			parts = append(parts, *wl.PurlPattern)
		}
	case watchlist.MatchTypeCPE:
		if wl.CpePattern != nil {
			parts = append(parts, *wl.CpePattern)
		}
	case watchlist.MatchTypeEcosystem:
		if wl.Ecosystem != nil {
			parts = append(parts, *wl.Ecosystem)
		}
	}

	if wl.SeverityMin != nil {
		parts = append(parts, fmt.Sprintf("severity>=%s", severityLabel(*wl.SeverityMin)))
	}
	if wl.EpssThreshold != nil {
		parts = append(parts, fmt.Sprintf("epss>=%.2f", *wl.EpssThreshold))
	}

	return strings.Join(parts, ", ")
}

// severityLabel converts a numeric severity level to its label.
func severityLabel(level int16) string {
	switch level {
	case 5:
		return "critical"
	case 4:
		return "high"
	case 3:
		return "medium"
	case 2:
		return "low"
	case 1:
		return "none"
	default:
		return "unknown"
	}
}

func printWatchUsage() {
	fmt.Println("Usage: mayu watch <subcommand> [options]")
	fmt.Println()
	fmt.Println("Manage watchlist entries for vulnerability monitoring.")
	fmt.Println()
	fmt.Println("Subcommands:")
	fmt.Println("  add       Add a new watchlist entry")
	fmt.Println("  list      List watchlist entries for a user")
	fmt.Println("  remove    Remove a watchlist entry")
	fmt.Println("  check     Check all active watchlists against the database (cron-friendly)")
	fmt.Println()
	fmt.Println("Run 'mayu watch <subcommand> --help' for more information.")
}
