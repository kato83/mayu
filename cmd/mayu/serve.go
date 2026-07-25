package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/kato83/mayu/internal/auth"
	"github.com/kato83/mayu/internal/config"
	"github.com/kato83/mayu/internal/fetcher"
	"github.com/kato83/mayu/internal/server"
	"github.com/kato83/mayu/internal/store"
	"github.com/kato83/mayu/internal/uiassets"
	"github.com/kato83/mayu/internal/watchlist"
	"github.com/kato83/mayu/internal/webhook"
)

func runServe(args []string, cfg *config.Config) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)

	addr := fs.String("addr", ":8080", "Address to listen on (host:port)")
	uiDir := fs.String("ui-dir", "", "Path to SPA static files directory (e.g., ./ui/dist/mayu/browser)")

	fs.Usage = func() {
		fmt.Println("Usage: mayu serve [options]")
		fmt.Println()
		fmt.Println("Start the Mayu API server.")
		fmt.Println()
		fmt.Println("The server exposes REST API endpoints for vulnerability search,")
		fmt.Println("matching the functionality of the 'mayu search' command.")
		fmt.Println()
		fmt.Println("Endpoints:")
		fmt.Println("  GET /api/v1/vulnerabilities       Search vulnerabilities")
		fmt.Println("  GET /api/v1/vulnerabilities/{id}  Get vulnerability by ID")
		fmt.Println("  GET /healthz                      Health check")
		fmt.Println("  GET /openapi.yaml                 OpenAPI specification")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  mayu serve")
		fmt.Println("  mayu serve --addr :3000")
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Resolve database URL
	databaseURL := resolveDatabaseURL(cfg)

	// Setup context with signal handling
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Connect to database
	s, err := store.NewPostgresStore(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer func() { _ = s.Close() }()

	// Initialize auth provider based on config
	var authProvider auth.AuthProvider
	var apiKeyStore auth.APIKeyStore
	var sessionCleanupStore auth.SessionStore
	switch cfg.Auth.Mode {
	case "local":
		authStore := auth.NewPostgresAuthStore(s.DB())
		maxAge := cfg.Auth.SessionMaxAge
		if maxAge <= 0 {
			maxAge = 86400
		}
		authProvider = auth.NewLocalAuthProvider(authStore, authStore, authStore, maxAge)
		apiKeyStore = authStore
		sessionCleanupStore = authStore
	case "oidc":
		oidcCfg := cfg.Auth.OIDC
		if oidcCfg.Issuer == "" || oidcCfg.ClientID == "" || oidcCfg.ClientSecret == "" || oidcCfg.RedirectURL == "" {
			return fmt.Errorf("oidc auth mode requires issuer, client_id, client_secret, and redirect_url to be configured")
		}
		authStore := auth.NewPostgresAuthStore(s.DB())
		maxAge := cfg.Auth.SessionMaxAge
		if maxAge <= 0 {
			maxAge = 86400
		}
		authProvider = auth.NewOIDCProvider(oidcCfg, authStore, authStore, authStore, maxAge)
		apiKeyStore = authStore
		sessionCleanupStore = authStore
	default:
		// "none" or empty
		authProvider = auth.NewNoAuthProvider()
		if !isLocalhostAddr(*addr) {
			slog.Warn("authentication is disabled and the server is bound to a non-localhost address; all requests will have unrestricted admin access",
				"addr", *addr,
				"hint", "set auth.mode in config.yaml to 'local' or 'oidc' for production use")
		} else {
			slog.Info("authentication disabled (auth.mode is not set); all requests have admin access",
				"hint", "set auth.mode in config.yaml to 'local' or 'oidc' for production use")
		}
	}

	// Initialize webhook system
	webhookStore := webhook.NewPostgresWebhookStore(s.DB())
	webhookEngine := webhook.NewEngine(webhookStore)

	// Create and start server
	srv := server.New(server.Config{
		Addr:           *addr,
		Store:          s,
		Version:        version,
		UIDir:          *uiDir,
		EmbedFS:        uiassets.FS(),
		Fetcher:        fetcher.New(),
		AuthProvider:   authProvider,
		APIKeyStore:    apiKeyStore,
		WebhookStore:   webhookStore,
		WebhookEngine:  webhookEngine,
		WatchlistStore: watchlist.NewPostgresWatchlistStore(s.DB()),
	})

	// Start periodic session cleanup if auth is enabled
	if sessionCleanupStore != nil {
		go func() {
			ticker := time.NewTicker(1 * time.Hour)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if err := sessionCleanupStore.DeleteExpiredSessions(context.Background()); err != nil {
						slog.Error("failed to cleanup expired sessions", "error", err)
					}
				}
			}
		}()
	}

	// Start server in goroutine.
	// errCh is buffered (cap 1) so the goroutine never blocks on send.
	// On graceful shutdown (ErrServerClosed), the channel is closed without
	// sending an error, causing the select below to receive nil.
	errCh := make(chan error, 1)
	go func() {
		fmt.Printf("Mayu API server starting on %s\n", *addr)
		fmt.Printf("  API:     http://localhost%s/api/v1/vulnerabilities\n", *addr)
		fmt.Printf("  OpenAPI: http://localhost%s/openapi.yaml\n", *addr)
		fmt.Printf("  Health:  http://localhost%s/healthz\n", *addr)
		if *uiDir != "" {
			fmt.Printf("  UI:      http://localhost%s/\n", *addr)
			fmt.Printf("  UI Dir:  %s\n", *uiDir)
		} else if uiassets.FS() != nil {
			fmt.Printf("  UI:      http://localhost%s/ (embedded)\n", *addr)
		}
		fmt.Println()
		fmt.Println("Press Ctrl+C to stop.")

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	// Wait for interrupt or error
	select {
	case <-ctx.Done():
		fmt.Println("\nShutting down server...")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("server shutdown: %w", err)
		}
		fmt.Println("Server stopped.")
		return nil
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("server error: %w", err)
		}
		return nil
	}
}

// isLocalhostAddr returns true if the given address binds only to localhost.
// Addresses like ":8080", "0.0.0.0:8080", or "[::]:8080" are considered non-localhost.
func isLocalhostAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	// Empty host means "all interfaces" (equivalent to 0.0.0.0)
	if host == "" {
		return false
	}
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
