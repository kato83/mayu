# Contributing to Mayu

[日本語版 (Japanese)](CONTRIBUTING_ja.md)

Thank you for your interest in contributing to Mayu! This guide covers everything you need to set up a development environment, run tests, and submit changes.

## Prerequisites

- [Go 1.26+](https://go.dev/) (managed via [asdf](https://asdf-vm.com/) — see `.tool-versions`)
- [Docker](https://www.docker.com/) & Docker Compose
- [golang-migrate](https://github.com/golang-migrate/migrate) CLI
- [lefthook](https://github.com/evilmartians/lefthook) (pre-commit hooks)
- [golangci-lint](https://golangci-lint.run/) v2.12+

## Getting Started

```bash
# Clone the repository
git clone https://github.com/kato83/mayu.git
cd mayu

# Install Go via asdf
asdf install

# Start PostgreSQL
make docker-up

# Run database migrations
make migrate-up

# Build the CLI
make build

# Verify
./bin/mayu version
```

## Development Commands

| Command | Description |
|---------|-------------|
| `make build` | Build binary with debug symbols → `bin/mayu` |
| `make build-release` | Build release binary (stripped, ~30% smaller) |
| `make test` | Run unit tests |
| `make test-integration` | Run integration tests (requires PostgreSQL) |
| `make fmt` | Format code (`go fmt`) |
| `make lint` | Run golangci-lint |
| `make clean` | Remove binary and clean cache |
| `make docker-up` | Start PostgreSQL |
| `make docker-down` | Stop PostgreSQL |
| `make docker-clean` | Stop PostgreSQL and remove volumes |
| `make migrate-up` | Run database migrations |
| `make migrate-down` | Rollback database migrations |
| `make migrate-create` | Create a new migration file (interactive) |

## Project Structure

```
mayu/
├── cmd/mayu/              # CLI entrypoint (ingest, search, serve, version)
├── internal/
│   ├── fetcher/           # GCS data download (OSV zip, converted sources)
│   ├── parser/            # OSV JSON parsing
│   ├── store/             # PostgreSQL persistence (database/sql + pgx stdlib)
│   ├── model/             # OSV schema Go structs
│   ├── server/            # HTTP/REST API server (go-chi)
│   ├── ingest/            # Pipeline orchestrator
│   ├── cvss/              # CVSS score parsing utilities
│   ├── purl/              # Package URL parsing
│   └── validate/          # Input validation helpers
├── migrations/            # golang-migrate SQL files
├── testdata/              # Test fixtures (OSV JSON samples)
├── docs/                  # Documentation (PLAN.md)
├── .github/workflows/     # CI (lint, test, build)
├── compose.yml            # Dev PostgreSQL 17
├── lefthook.yml           # Pre-commit hooks (fmt, lint)
├── .tool-versions         # asdf: golang 1.26.5
├── go.mod / go.sum
└── Makefile
```

## Architecture

```mermaid
graph TD
    CLI["CLI (cmd/mayu)"]
    CLI --> Ingest[ingest]
    CLI --> Search[search]
    CLI --> Serve[serve]

    Ingest --> Fetcher["Fetcher (GCS)"]
    Ingest --> Parser["Parser (OSV)"]
    Ingest --> IngestPipeline["Ingest (Pipeline)"]
    Search --> Store["Store (PG)"]
    Serve --> Server["Server (HTTP/REST)"]
    Server --> Store
    IngestPipeline --> Store

    Store --> DB[(PostgreSQL)]
```

## Coding Conventions

### General

- Follow [Standard Go Project Layout](https://github.com/golang-standards/project-layout) (`cmd/`, `internal/`)
- Use `database/sql` standard interface with pgx as the driver (stdlib mode)
- Minimize external dependencies; prefer Go standard library
- No CLI framework — uses Go standard `flag` package
- Keep packages focused: one responsibility per package

### Style

- Naming: follow Go conventions (MixedCaps, not snake_case)
- Exported functions must have doc comments
- Error handling: return errors, don't panic in library code
- Use `context.Context` for cancellation and timeouts

### Testing

- Write tests alongside implementation (TDD encouraged)
- Unit tests: `*_test.go` in the same package
- Integration tests: use build tag `//go:build integration`
- Test fixtures: place in `testdata/` directory
- Use table-driven tests where applicable
- Use `net/http/httptest` for HTTP mocking

### Database

- Migrations use golang-migrate with sequential numbered files
- Always provide both up and down migrations
- Naming: `{number}_{description}.up.sql` / `{number}_{description}.down.sql`
- Use JSONB for flexible/raw data storage

## Running Tests

```bash
# Unit tests only (no external dependencies)
make test

# Integration tests (requires running PostgreSQL)
make docker-up
make migrate-up
make test-integration
```

## Pre-commit Hooks

This project uses [lefthook](https://github.com/evilmartians/lefthook) for pre-commit hooks that automatically run `make fmt` and `make lint` on staged `.go` files.

```bash
# Install lefthook (if not already installed)
go install github.com/evilmartians/lefthook@latest

# Install hooks
lefthook install
```

## CI Pipeline

GitHub Actions runs on every push/PR to `main`:

1. **Lint** — golangci-lint v2.12.2
2. **Test** — unit + integration tests against PostgreSQL 17
3. **Build** — compile binary and verify `mayu version`

Ensure all checks pass locally before submitting a PR.

## Submitting Changes

1. Fork the repository and create a branch from `main`
2. Branch naming: `{type}/{short-description}` (e.g., `feature/kev-source`, `fix/search-crash`)
3. Make your changes with clear, atomic commits
4. Add or update tests as appropriate
5. Run `make fmt && make lint && make test` before pushing
6. Open a Pull Request against `main`

## Configuration

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgres://mayu:mayu@localhost:5432/mayu?sslmode=disable` |

> [!WARNING]
> The default `DATABASE_URL` uses `sslmode=disable`, which is appropriate only
> for local development against the bundled Docker PostgreSQL. For remote or
> production databases, enforce TLS with `sslmode=require` or `verify-full`.

## Web UI (Angular)

### Prerequisites

- [Node.js 24+](https://nodejs.org/) (managed via asdf — see `.tool-versions`)
- [pnpm 11+](https://pnpm.io/)

### Development Commands

| Command | Description |
|---------|-------------|
| `make ui-dev` | Start dev server (proxies /api to :8080) |
| `make ui-build` | Production build |
| `make ui-test` | Run Vitest unit tests |
| `make ui-lint` | Run linter |

### Internationalization (i18n)

The Web UI uses [Angular's built-in i18n](https://angular.dev/guide/i18n) for all user-facing text.

**Rules:**

1. **All fixed text in templates must be marked with `i18n`** — No hardcoded user-facing strings without i18n attributes.
2. **Use custom IDs** — Always use `@@` syntax for stability: `i18n="@@component.purpose"`
3. **ID naming convention** — `{component}.{purpose}` in camelCase (e.g., `@@sidebar.appName`, `@@vulnList.clearFilters`)
4. **For attributes** — Use `i18n-{attr}` (e.g., `i18n-placeholder="@@vulnList.filterIdPlaceholder"`, `i18n-aria-label="@@header.openMenu"`)
5. **For TypeScript strings** — Use `$localize` tagged template: `` $localize`:@@id:text` ``
6. **After adding/changing text** — Run `make ui-i18n-extract` to regenerate the source XLF, then update `src/locale/messages.ja.xlf`
7. **Source locale is English** — The template text itself serves as the English version
8. **Proper nouns** — Brand names (Mayu, NVD, MITRE, CVSS) should still be marked with i18n but may remain untranslated

**Workflow for adding new translatable text:**

```bash
# 1. Add i18n attribute to template (or $localize in TS)
# 2. Extract messages
make ui-i18n-extract

# 3. Update Japanese translation file
#    Copy new <trans-unit> entries from src/locale/messages.xlf to src/locale/messages.ja.xlf
#    and add <target> elements with Japanese translations

# 4. Verify build
make ui-build
```

## Roadmap

See [docs/PLAN.md](docs/PLAN.md) for the full implementation plan.

- [x] Phase 1: Data Pipeline (OSV ingestion)
- [x] Phase 2: CLI (ingest + search)
- [x] Phase 3: CI/CD (GitHub Actions)
- [x] Phase 4: API Server (REST)
- [ ] Phase 5: Web UI (Angular)
- [ ] Phase 6: Additional Data Sources (KEV, EPSS, MITRE CVE)
