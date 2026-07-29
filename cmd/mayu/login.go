package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/kato83/mayu/internal/auth"
	"github.com/kato83/mayu/internal/config"
	"github.com/kato83/mayu/internal/credentials"

	_ "github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/term"
)

func runLogin(args []string, cfg *config.Config) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)

	oidcFlag := fs.Bool("oidc", false, "Use OIDC browser-based login")
	server := fs.String("server", "", "Server URL (default: http://localhost:8080)")

	fs.Usage = func() {
		fmt.Println("Usage: mayu login [options]")
		fmt.Println()
		fmt.Println("Authenticate with a mayu server and store session credentials locally.")
		fmt.Println()
		fmt.Println("Modes:")
		fmt.Println("  Interactive (default): Prompt for email and password")
		fmt.Println("  OIDC (--oidc):         Open browser for OIDC authentication")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  mayu login")
		fmt.Println("  mayu login --server http://localhost:8080")
		fmt.Println("  mayu login --oidc")
		fmt.Println("  mayu login --oidc --server http://localhost:8080")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	serverURL := *server
	if serverURL == "" {
		serverURL = "http://localhost:8080"
	}

	if *oidcFlag {
		return runLoginOIDC(cfg, serverURL)
	}
	return runLoginInteractive(cfg, serverURL)
}

// runLoginInteractive performs email/password login by prompting the user.
func runLoginInteractive(cfg *config.Config, serverURL string) error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Email: ")
	email, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read email: %w", err)
	}
	email = strings.TrimSpace(email)
	if email == "" {
		return fmt.Errorf("email is required")
	}

	fmt.Print("Password: ")
	passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println() // print newline after hidden input
	if err != nil {
		return fmt.Errorf("read password: %w", err)
	}
	password := strings.TrimSpace(string(passwordBytes))
	if password == "" {
		return fmt.Errorf("password is required")
	}

	// Connect to database and authenticate
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

	authStore := auth.NewPostgresAuthStore(db)
	authProvider := auth.NewLocalAuthProvider(authStore, authStore, authStore, cfg.Auth.SessionMaxAge)

	user, err := authProvider.Authenticate(ctx, email, password)
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}

	// Create session
	sessionID, err := authProvider.CreateSession(ctx, user.ID)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}

	// Calculate expiry
	maxAge := time.Duration(cfg.Auth.SessionMaxAge) * time.Second
	if maxAge <= 0 {
		maxAge = 24 * time.Hour
	}
	expiresAt := time.Now().Add(maxAge)

	// Save credentials
	creds := &credentials.Credentials{
		ServerURL:    serverURL,
		SessionToken: sessionID,
		ExpiresAt:    expiresAt,
	}
	if err := credentials.Save(creds); err != nil {
		return fmt.Errorf("save credentials: %w", err)
	}

	fmt.Printf("Login successful!\n")
	fmt.Printf("  User:    %s\n", user.Email)
	fmt.Printf("  Expires: %s\n", expiresAt.Format(time.RFC3339))
	return nil
}

// runLoginOIDC performs OIDC browser-based login using a temporary local HTTP server.
func runLoginOIDC(cfg *config.Config, serverURL string) error {
	if cfg.Auth.Mode != "oidc" {
		return fmt.Errorf("OIDC login requires auth.mode to be 'oidc' in config")
	}

	oidcCfg := cfg.Auth.OIDC
	if oidcCfg.Issuer == "" {
		return fmt.Errorf("OIDC issuer is not configured (set auth.oidc.issuer in config)")
	}
	if oidcCfg.ClientID == "" {
		return fmt.Errorf("OIDC client_id is not configured (set auth.oidc.client_id in config)")
	}

	// Start temporary HTTP server on a random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("start callback server: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	callbackURL := fmt.Sprintf("http://localhost:%d/callback", port)

	// Override the redirect URL for this CLI flow
	oidcCfg.RedirectURL = callbackURL

	// Connect to database
	databaseURL := resolveDatabaseURL(cfg)
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		_ = listener.Close()
		return fmt.Errorf("open database: %w", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		_ = listener.Close()
		return fmt.Errorf("connect to database: %w", err)
	}

	authStore := auth.NewPostgresAuthStore(db)
	oidcProvider := auth.NewOIDCProvider(oidcCfg, authStore, authStore, authStore, cfg.Auth.SessionMaxAge)

	// Generate cryptographically random state to prevent CSRF
	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		_ = listener.Close()
		return fmt.Errorf("generate state token: %w", err)
	}
	state := "cli-" + hex.EncodeToString(stateBytes)
	authURL, err := oidcProvider.AuthorizationURL(state)
	if err != nil {
		_ = listener.Close()
		return fmt.Errorf("build authorization URL: %w", err)
	}

	// Channel to receive the result
	type callbackResult struct {
		code string
		err  error
	}
	resultCh := make(chan callbackResult, 1)

	// Set up HTTP handler for the callback
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		// Validate state
		if r.URL.Query().Get("state") != state {
			http.Error(w, "Invalid state parameter", http.StatusBadRequest)
			resultCh <- callbackResult{err: fmt.Errorf("invalid state parameter in callback")}
			return
		}

		// Check for error from provider
		if errParam := r.URL.Query().Get("error"); errParam != "" {
			desc := r.URL.Query().Get("error_description")
			if desc == "" {
				desc = errParam
			}
			http.Error(w, "Authentication failed: "+desc, http.StatusBadRequest)
			resultCh <- callbackResult{err: fmt.Errorf("OIDC error: %s", desc)}
			return
		}

		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "Missing authorization code", http.StatusBadRequest)
			resultCh <- callbackResult{err: fmt.Errorf("missing authorization code in callback")}
			return
		}

		// Send success response to browser
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, `<html><body><h1>Login successful!</h1><p>You can close this window and return to the terminal.</p></body></html>`)
		resultCh <- callbackResult{code: code}
	})

	srv := &http.Server{Handler: mux}

	// Start the server
	go func() {
		if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			resultCh <- callbackResult{err: fmt.Errorf("callback server: %w", err)}
		}
	}()

	// Open browser
	fmt.Printf("Opening browser for OIDC login...\n")
	fmt.Printf("If the browser doesn't open automatically, visit:\n  %s\n\n", authURL)
	_ = openBrowser(authURL)

	// Wait for callback (with timeout)
	var result callbackResult
	select {
	case result = <-resultCh:
	case <-time.After(5 * time.Minute):
		result = callbackResult{err: fmt.Errorf("login timed out (5 minutes)")}
	}

	// Shut down the server
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)

	if result.err != nil {
		return result.err
	}

	// Exchange code for user
	user, err := oidcProvider.HandleCallback(ctx, result.code)
	if err != nil {
		return fmt.Errorf("OIDC authentication failed: %w", err)
	}

	// Create session
	sessionID, err := oidcProvider.CreateSession(ctx, user.ID)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}

	// Calculate expiry
	maxAge := time.Duration(cfg.Auth.SessionMaxAge) * time.Second
	if maxAge <= 0 {
		maxAge = 24 * time.Hour
	}
	expiresAt := time.Now().Add(maxAge)

	// Save credentials
	creds := &credentials.Credentials{
		ServerURL:    serverURL,
		SessionToken: sessionID,
		ExpiresAt:    expiresAt,
	}
	if err := credentials.Save(creds); err != nil {
		return fmt.Errorf("save credentials: %w", err)
	}

	fmt.Printf("Login successful!\n")
	fmt.Printf("  User:    %s\n", user.Email)
	fmt.Printf("  Expires: %s\n", expiresAt.Format(time.RFC3339))
	return nil
}

// openBrowser opens the given URL in the user's default browser.
func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
	return cmd.Start()
}
