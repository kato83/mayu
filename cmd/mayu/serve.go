package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/kato83/mayu/internal/config"
	"github.com/kato83/mayu/internal/fetcher"
	"github.com/kato83/mayu/internal/server"
	"github.com/kato83/mayu/internal/store"
	"github.com/kato83/mayu/internal/uiassets"
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

	// Create and start server
	srv := server.New(server.Config{
		Addr:    *addr,
		Store:   s,
		Version: version,
		UIDir:   *uiDir,
		EmbedFS: uiassets.FS(),
		Fetcher: fetcher.New(),
	})

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
