// Package testhelper provides shared test infrastructure for integration tests.
// It uses testcontainers-go to spin up an isolated PostgreSQL container per test,
// ensuring tests do not interfere with each other or with the development database.
package testhelper

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

const (
	testDBName = "mayu_test"
	testDBUser = "mayu_test"
	testDBPass = "mayu_test"
)

// PostgresContainer wraps a testcontainers PostgreSQL instance
// and provides the connection URL for tests.
type PostgresContainer struct {
	Container   *postgres.PostgresContainer
	DatabaseURL string
}

// SetupPostgres starts a PostgreSQL container and runs all migrations.
// The container is automatically terminated when the test completes.
// Returns the connection URL for the test database.
func SetupPostgres(t *testing.T) *PostgresContainer {
	t.Helper()
	ctx := context.Background()

	// Start PostgreSQL container
	pgContainer, err := postgres.Run(ctx,
		"postgres:17-alpine",
		postgres.WithDatabase(testDBName),
		postgres.WithUsername(testDBUser),
		postgres.WithPassword(testDBPass),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("failed to start postgres container: %v", err)
	}

	// Register cleanup
	t.Cleanup(func() {
		if err := pgContainer.Terminate(ctx); err != nil {
			t.Logf("warning: failed to terminate postgres container: %v", err)
		}
	})

	// Get connection string
	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("failed to get connection string: %v", err)
	}

	// Run migrations
	migrationsDir := migrationsPath()
	m, err := migrate.New(
		fmt.Sprintf("file://%s", migrationsDir),
		connStr,
	)
	if err != nil {
		t.Fatalf("failed to create migrator: %v", err)
	}
	defer m.Close()

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("failed to run migrations: %v", err)
	}

	return &PostgresContainer{
		Container:   pgContainer,
		DatabaseURL: connStr,
	}
}

// migrationsPath returns the absolute path to the migrations directory
// relative to this source file.
func migrationsPath() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "..", "migrations")
}
