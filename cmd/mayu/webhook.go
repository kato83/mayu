package main

import (
	"bytes"
	"context"
	"database/sql"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/cbroglie/mustache"
	"github.com/kato83/mayu/internal/auth"
	"github.com/kato83/mayu/internal/config"
	"github.com/kato83/mayu/internal/model"
	"github.com/kato83/mayu/internal/webhook"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func runWebhook(args []string, cfg *config.Config) error {
	if len(args) == 0 {
		printWebhookUsage()
		return fmt.Errorf("no subcommand specified (use 'create', 'list', or 'test')")
	}

	switch args[0] {
	case "create":
		return runWebhookCreate(args[1:], cfg)
	case "list":
		return runWebhookList(args[1:], cfg)
	case "test":
		return runWebhookTest(args[1:], cfg)
	case "help", "-h", "--help":
		printWebhookUsage()
		return nil
	default:
		printWebhookUsage()
		return fmt.Errorf("unknown webhook subcommand: %q (use 'create', 'list', or 'test')", args[0])
	}
}

// authenticateWebhookUser validates the MAYU_API_KEY environment variable and
// returns the authenticated user's ID, the database connection, and the webhook store.
func authenticateWebhookUser(ctx context.Context, cfg *config.Config) (int64, *sql.DB, *webhook.PostgresWebhookStore, error) {
	apiKey := os.Getenv("MAYU_API_KEY")
	if apiKey == "" {
		return 0, nil, nil, fmt.Errorf("MAYU_API_KEY environment variable is required for authentication")
	}

	databaseURL := resolveDatabaseURL(cfg)
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("open database: %w", err)
	}

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return 0, nil, nil, fmt.Errorf("connect to database: %w", err)
	}

	// Validate API key and resolve user
	authStore := auth.NewPostgresAuthStore(db)
	authProvider := auth.NewLocalAuthProvider(authStore, authStore, authStore, 0)
	user, err := authProvider.ValidateAPIKey(ctx, apiKey)
	if err != nil {
		_ = db.Close()
		return 0, nil, nil, fmt.Errorf("authenticate: %w", err)
	}

	store := webhook.NewPostgresWebhookStore(db)
	return user.ID, db, store, nil
}

func runWebhookCreate(args []string, cfg *config.Config) error {
	fs := flag.NewFlagSet("webhook create", flag.ContinueOnError)

	name := fs.String("name", "", "Webhook name (required)")
	url := fs.String("url", "", "Webhook URL (required)")
	events := fs.String("events", "", "Comma-separated list of events (required, e.g., 'new_critical,new_high' or '*')")
	contentType := fs.String("content-type", "application/json", "Content-Type header for the webhook request")
	bodyTemplate := fs.String("body-template", "", "Mustache template for the request body")
	secret := fs.String("secret", "", "HMAC secret for webhook signature verification")
	enabled := fs.Bool("enabled", true, "Whether the webhook is enabled")

	fs.Usage = func() {
		fmt.Println("Usage: mayu webhook create [options]")
		fmt.Println()
		fmt.Println("Create a new webhook.")
		fmt.Println()
		fmt.Println("Requires the MAYU_API_KEY environment variable to be set with a valid API key.")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  export MAYU_API_KEY=your-api-key")
		fmt.Println("  mayu webhook create --name 'Slack Alert' --url 'https://hooks.slack.com/...' --events 'new_critical,new_high' --body-template '{\"text\": \"{{ID}} ({{Severity}})\"}'")
		fmt.Println("  mayu webhook create --name 'All Events' --url 'https://example.com/webhook' --events '*'")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Validate required fields
	if *name == "" {
		return fmt.Errorf("--name is required")
	}
	if *url == "" {
		return fmt.Errorf("--url is required")
	}
	if *events == "" {
		return fmt.Errorf("--events is required")
	}

	eventList := strings.Split(*events, ",")
	for i, e := range eventList {
		eventList[i] = strings.TrimSpace(e)
	}

	ctx := context.Background()

	// Authenticate user
	userID, db, store, err := authenticateWebhookUser(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	wh := &model.Webhook{
		UserID:       &userID,
		Name:         *name,
		URL:          *url,
		Events:       eventList,
		ContentType:  *contentType,
		BodyTemplate: *bodyTemplate,
		Secret:       *secret,
		Enabled:      *enabled,
	}

	created, err := store.CreateWebhook(ctx, wh)
	if err != nil {
		return fmt.Errorf("create webhook: %w", err)
	}

	fmt.Println("Webhook created successfully:")
	fmt.Printf("  ID:           %d\n", created.ID)
	fmt.Printf("  Name:         %s\n", created.Name)
	fmt.Printf("  URL:          %s\n", created.URL)
	fmt.Printf("  Events:       %s\n", strings.Join(created.Events, ", "))
	fmt.Printf("  Content-Type: %s\n", created.ContentType)
	fmt.Printf("  Enabled:      %t\n", created.Enabled)

	return nil
}

func runWebhookList(args []string, cfg *config.Config) error {
	fs := flag.NewFlagSet("webhook list", flag.ContinueOnError)

	fs.Usage = func() {
		fmt.Println("Usage: mayu webhook list")
		fmt.Println()
		fmt.Println("List webhooks for the authenticated user.")
		fmt.Println()
		fmt.Println("Requires the MAYU_API_KEY environment variable to be set with a valid API key.")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx := context.Background()

	// Authenticate user
	userID, db, store, err := authenticateWebhookUser(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	webhooks, err := store.ListWebhooksByUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("list webhooks: %w", err)
	}

	if len(webhooks) == 0 {
		fmt.Println("No webhooks found.")
		return nil
	}

	// Print table
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintf(w, "ID\tNAME\tURL\tEVENTS\tENABLED\n")
	for _, wh := range webhooks {
		_, _ = fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%t\n",
			wh.ID, wh.Name, wh.URL, strings.Join(wh.Events, ","), wh.Enabled)
	}
	return w.Flush()
}

func runWebhookTest(args []string, cfg *config.Config) error {
	fs := flag.NewFlagSet("webhook test", flag.ContinueOnError)

	id := fs.Int64("id", 0, "Webhook ID to test (required)")

	fs.Usage = func() {
		fmt.Println("Usage: mayu webhook test --id <webhook-id>")
		fmt.Println()
		fmt.Println("Send a test payload to a webhook.")
		fmt.Println()
		fmt.Println("Requires the MAYU_API_KEY environment variable to be set with a valid API key.")
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

	ctx := context.Background()

	// Authenticate user
	userID, db, store, err := authenticateWebhookUser(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	wh, err := store.GetWebhook(ctx, *id)
	if err != nil {
		return fmt.Errorf("get webhook: %w", err)
	}
	if wh == nil {
		return fmt.Errorf("webhook not found: id=%d", *id)
	}

	// Verify ownership: user can only test their own webhooks
	if wh.UserID == nil || *wh.UserID != userID {
		return fmt.Errorf("webhook not found: id=%d", *id)
	}

	// Render template with sample data
	sampleEvent := webhook.WebhookEvent{
		Event:    "test",
		ID:       "CVE-0000-0000",
		Severity: "MEDIUM",
		EPSS:     0.5,
		LEV:      0.3,
		Summary:  "Test webhook delivery",
	}

	rendered, err := mustache.Render(wh.BodyTemplate, sampleEvent)
	if err != nil {
		return fmt.Errorf("render body template: %w", err)
	}

	body := bytes.NewBufferString(rendered)

	fmt.Printf("Testing webhook %q (ID: %d)...\n", wh.Name, wh.ID)
	fmt.Printf("  URL: %s\n", wh.URL)
	fmt.Printf("  Payload:\n    %s\n", strings.ReplaceAll(body.String(), "\n", "\n    "))
	fmt.Println()

	// Send the HTTP request
	contentType := wh.ContentType
	if contentType == "" {
		contentType = "application/json"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, wh.URL, bytes.NewReader(body.Bytes()))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)

	client := &http.Client{Timeout: 10 * time.Second}
	start := time.Now()
	resp, err := client.Do(req)
	duration := time.Since(start)

	if err != nil {
		fmt.Printf("  Result: FAILED\n")
		fmt.Printf("  Error:  %v\n", err)
		fmt.Printf("  Duration: %s\n", duration.Round(time.Millisecond))
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	fmt.Printf("  Result: %s\n", resp.Status)
	fmt.Printf("  Duration: %s\n", duration.Round(time.Millisecond))

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		fmt.Println("  Webhook test successful!")
	} else {
		fmt.Println("  Webhook test completed with non-success status.")
	}

	return nil
}

func printWebhookUsage() {
	fmt.Println("Usage: mayu webhook <subcommand> [options]")
	fmt.Println()
	fmt.Println("Manage webhooks.")
	fmt.Println()
	fmt.Println("All subcommands require the MAYU_API_KEY environment variable to be set.")
	fmt.Println()
	fmt.Println("Subcommands:")
	fmt.Println("  create    Create a new webhook")
	fmt.Println("  list      List all webhooks")
	fmt.Println("  test      Send a test payload to a webhook")
	fmt.Println()
	fmt.Println("Run 'mayu webhook <subcommand> --help' for more information.")
}
