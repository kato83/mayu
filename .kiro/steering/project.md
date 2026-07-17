# Mayu - Project Steering

## Project Overview

Mayu is a unified vulnerability intelligence tool that aggregates multiple sources (OSV, NVD, Debian, etc.) for cross-platform lookup via CLI, API, and Web UI.

- Repository: github.com/kato83/mayu
- Language: Go (backend), Angular (future frontend)
- Database: PostgreSQL 17

## Directory Structure

```
mayu/
├── cmd/
│   └── mayu/              # CLI entrypoint (ingest, search, version)
├── internal/
│   ├── fetcher/           # GCS data download (OSV zip, converted sources, streaming)
│   ├── parser/            # OSV JSON parsing
│   ├── store/             # PostgreSQL persistence (database/sql + pgx stdlib)
│   ├── model/             # OSV schema Go structs
│   ├── query/             # (empty — search logic is in store.Store interface)
│   └── ingest/            # Pipeline orchestrator (OSV ecosystems + converted sources)
├── migrations/            # golang-migrate SQL files (000001–000002)
├── testdata/              # Test fixtures (OSV JSON samples)
├── docs/                  # Documentation (PLAN.md)
├── .github/workflows/     # CI (lint, test, build)
├── compose.yml            # Dev PostgreSQL 17
├── lefthook.yml           # Pre-commit hooks (fmt, lint)
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
- When the DB schema changes, always update `.kiro/steering/erd.md` to reflect the new structure

### Dependencies

- Database driver: `github.com/jackc/pgx/v5` (v5.10.0, stdlib mode)
- Migration: `github.com/golang-migrate/migrate/v4`
- Keep `go.mod` lean; justify new dependencies
- No CLI framework — uses Go standard `flag` package

## Development Workflow

### Prerequisites

- Go 1.26.5 (managed via asdf, `.tool-versions`)
- Docker & Docker Compose (for PostgreSQL)
- make
- [lefthook](https://github.com/evilmartians/lefthook) (pre-commit hooks: fmt + lint)

### Common Commands

```bash
make docker-up        # Start PostgreSQL
make docker-down      # Stop PostgreSQL
make docker-clean     # Stop PostgreSQL and remove volumes
make migrate-up       # Run migrations
make migrate-down     # Rollback migrations
make migrate-create   # Create new migration (interactive)
make build            # Build binary → bin/mayu
make test             # Run unit tests
make test-integration # Run integration tests (requires PostgreSQL)
make lint             # Run golangci-lint
make fmt              # Format code
make clean            # Remove binary and clean cache
```

### Environment Variables

- `DATABASE_URL` - PostgreSQL connection string (default: `postgres://mayu:mayu@localhost:5432/mayu?sslmode=disable`)

### CI/CD

GitHub Actions workflow (`.github/workflows/ci.yml`) runs on push/PR to `main`:
- **Lint**: golangci-lint v2.12.2
- **Test**: unit + integration tests against PostgreSQL 17 service container
- **Build**: compile binary and verify `mayu version`

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
- Search interface: `store.Store.Search()` with `SearchQuery` struct (ID, Ecosystem, PackageName, Alias, Limit, Offset)

## Data Sources

| Source | Status | Implementation |
|--------|--------|----------------|
| OSV (all ecosystems) | ✅ Supported | GCS zip archives via `internal/fetcher` |
| NVD (OSV converted) | ✅ Supported | GCS XML listing → individual JSON download |
| Debian (OSV converted) | ✅ Supported | GCS XML listing → individual JSON download |
| KEV | 🔜 Planned | — |
| EPSS | 🔜 Planned | — |
| MITRE CVE | 🔜 Planned | — |

## Current Phase

Phases 1–3 complete (Data Pipeline, CLI, CI/CD). Next up: Phase 4 (API Server).

See [docs/PLAN.md](../docs/PLAN.md) for the full roadmap.

- [x] Phase 1: Data Pipeline (OSV ingestion)
- [x] Phase 2: CLI (ingest + search)
- [x] Phase 3: CI/CD (GitHub Actions)
- [ ] Phase 4: API Server (REST)
- [ ] Phase 5: Web UI (Angular)
- [ ] Phase 6: Additional Data Sources (KEV, EPSS, MITRE CVE)
