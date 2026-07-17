# Mayu - Project Steering

## Project Overview

Mayu is a unified vulnerability intelligence tool that aggregates multiple sources (OSV, NVD, etc.) for cross-platform lookup via CLI, API, and Web UI.

- Repository: github.com/kato83/mayu
- Language: Go (backend), Angular (future frontend)
- Database: PostgreSQL 16

## Directory Structure

```
mayu/
├── cmd/
│   ├── mayu/              # CLI entrypoint
│   └── mayu-server/       # API server (future)
├── internal/
│   ├── fetcher/           # GCS data download
│   ├── parser/            # OSV JSON parsing
│   ├── store/             # PostgreSQL persistence (database/sql + pgx stdlib)
│   ├── model/             # OSV schema Go structs
│   ├── query/             # Search logic
│   └── ingest/            # Pipeline orchestrator
├── migrations/            # golang-migrate SQL files
├── testdata/              # Test fixtures
├── docs/                  # Documentation
├── docker-compose.yml     # Dev PostgreSQL
├── .tool-versions         # asdf: golang 1.26.5
├── go.mod
├── go.sum
└── Makefile
```

## Coding Conventions

### Go

- Follow Standard Go Project Layout (`cmd/`, `internal/`, `pkg/`)
- Use `database/sql` standard interface with pgx as the driver (stdlib mode)
- Minimize external dependencies; prefer Go standard library
- Error handling: return errors, don't panic in library code
- Use `context.Context` for cancellation and timeouts
- Naming: follow Go conventions (MixedCaps, not snake_case)
- Comments: exported functions must have doc comments
- Keep packages focused: one responsibility per package

### Testing

- TDD approach: write tests before or alongside implementation
- Unit tests: `*_test.go` in the same package
- Integration tests: use build tags (`//go:build integration`) for tests requiring PostgreSQL
- Test fixtures: place in `testdata/` directory
- Use `net/http/httptest` for HTTP mocking
- Use table-driven tests where applicable

### Database

- Migrations: use golang-migrate/migrate with sequential numbered files
- Migration naming: `{number}_{description}.up.sql` / `{number}_{description}.down.sql`
- Always provide both up and down migrations
- Use JSONB for flexible/raw data storage (e.g., `raw_json`, `database_specific`)
- Index frequently queried columns

### Dependencies

- Database driver: `github.com/jackc/pgx/v5/stdlib`
- Migration: `github.com/golang-migrate/migrate/v4`
- Keep `go.mod` lean; justify new dependencies

## Development Workflow

### Prerequisites

- Go 1.26.5 (managed via asdf, `.tool-versions`)
- Docker & Docker Compose (for PostgreSQL)
- make

### Common Commands

```bash
make docker-up       # Start PostgreSQL
make docker-down     # Stop PostgreSQL
make migrate-up      # Run migrations
make migrate-down    # Rollback migrations
make build           # Build binary
make test            # Run unit tests
make test-integration # Run integration tests
make lint            # Run golangci-lint
```

### Environment Variables

- `DATABASE_URL` - PostgreSQL connection string (default: `postgres://mayu:mayu@localhost:5432/mayu?sslmode=disable`)

## Architecture Principles

- **Data-first**: Build the data pipeline before interfaces
- **Reversibility**: Always store raw source data alongside normalized data
- **Standard interfaces**: Use Go's standard `database/sql` and `net/http` where possible
- **Testability**: Design for dependency injection; interfaces over concrete types
- **Incremental**: Start with Go ecosystem, expand to all ecosystems
- **Separation of concerns**: Fetcher → Parser → Store are independent, composable units

## Key Data Model

- Primary schema: OSV Schema v1.8.0
- `database_specific` and `ecosystem_specific` fields stored as `json.RawMessage` (preserves unknown fields)
- Each vulnerability stores its complete original JSON in `raw_json` JSONB column
- Sync state tracked per-ecosystem for efficient delta updates via `modified_id.csv`

## Current Phase

Phase 1: Data Pipeline (see docs/PLAN.md for full roadmap)
