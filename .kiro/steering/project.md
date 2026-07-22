# Mayu - Project Steering

## Project Overview

Mayu is a unified vulnerability intelligence tool that aggregates multiple sources (OSV, NVD, Debian, etc.) for cross-platform lookup via CLI, API, and Web UI.

- Repository: github.com/kato83/mayu
- Language: Go (backend), Angular v22 (frontend)
- Database: PostgreSQL 17

## Directory Structure

```
mayu/
├── cmd/
│   └── mayu/              # CLI entrypoint (ingest, search, audit, serve, migrate, version)
├── internal/
│   ├── audit/             # SBOM audit logic (version matching, finding generation)
│   ├── config/            # YAML configuration file loading
│   ├── cvss/              # CVSS score parsing utilities
│   ├── fetcher/           # GCS data download (OSV zip, converted sources, streaming, GitHub API)
│   ├── ingest/            # Pipeline orchestrator (OSV ecosystems + converted sources)
│   ├── model/             # OSV schema Go structs
│   ├── parser/            # OSV JSON parsing
│   ├── purl/              # Package URL parsing
│   ├── sbom/              # SBOM parsers (CycloneDX 1.7, SPDX 2.3 JSON)
│   ├── server/            # HTTP/REST API server (go-chi)
│   ├── store/             # PostgreSQL persistence (database/sql + pgx stdlib)
│   └── validate/          # Input validation helpers
├── ui/                    # Angular v22 Web UI (TailwindCSS v4, pnpm)
├── migrations/            # golang-migrate SQL files (000001–000014)
├── testdata/              # Test fixtures (OSV JSON samples)
├── docs/                  # Documentation (PLAN.md, import-ghsa-json.md)
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

### Web UI (Angular)

- Framework: Angular v22 with standalone components
- Styling: TailwindCSS v4
- Testing: Vitest (run via `pnpm run test`, not `npx vitest` directly)
- Package manager: pnpm
- All user-facing text must be internationalized using Angular's built-in i18n
- Use custom IDs with `@@` syntax: `i18n="@@component.purpose"`
- Source locale: English (`en`), translations: Japanese (`ja`)
- Translation files: `ui/src/locale/messages.ja.xlf`
- After adding/modifying text, run `make ui-i18n-extract` and update translations
- Use `$localize` tagged template for strings in TypeScript code
- SPA hosting: `mayu serve --ui-dir ./ui/dist/mayu/browser` (dev/small deployments only)
- Production: serve Angular assets via Nginx/Apache or CDN (S3+CloudFront, GCS+Cloud CDN)
- i18n build output: `ui/dist/mayu/browser/{locale}/` (e.g., `en/`, `ja/`)
- The Go server handles locale routing via Accept-Language header with fallback to `en`

### Dependencies

- Database driver: `github.com/jackc/pgx/v5` (v5.10.0, stdlib mode)
- Migration: `github.com/golang-migrate/migrate/v4`
- Concurrency: `golang.org/x/sync` (errgroup)
- Config: `gopkg.in/yaml.v3` (YAML config file parsing)
- Keep `go.mod` lean; justify new dependencies
- No CLI framework — uses Go standard `flag` package

### Documentation

- When CLI commands, flags, or behavior change, update both `README.md` and `README_ja.md` to reflect the new usage
- Keep CLI Reference tables in READMEs in sync with actual flag definitions in code
- When adding new data sources or features, update the relevant sections (Data Sources, Overview, etc.)

## Development Workflow

### Parallel Development

This project supports parallel development using `git worktree`. See [worktree.md](worktree.md) for the full workflow, directory layout, and rules.

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
make build-release    # Build release binary (stripped, ~30% smaller)
make build-embed      # Build binary with embedded Web UI (pnpm install + build + go build -tags uiembed)
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
- Search interface: `store.Store.Search()` with `SearchQuery` struct (ID, Ecosystem, PackageName, Alias, Severity, Since, Version, Limit, Offset)
- Audit interface: `store.Store.SearchByPackages()` for batch package lookup; `internal/audit.Auditor` performs version-range matching (semver via `github.com/Masterminds/semver/v3`) and generates `Finding` results
- SBOM parsing: `internal/sbom.Parse()` auto-detects CycloneDX 1.7 / SPDX 2.3 JSON and extracts `Component` list (purl → ecosystem/name/version resolution via `internal/purl`)

## Data Sources

| Source | Status | Implementation |
|--------|--------|----------------|
| OSV (all ecosystems) | ✅ Supported | GCS zip archives via `internal/fetcher` |
| NVD (OSV converted) | ✅ Supported | GCS XML listing → parallel JSON download |
| Debian (OSV converted) | ✅ Supported | GCS XML listing → parallel JSON download |
| NVD CVE (native) | ✅ Supported | NVD JSON Feed 2.0 via `internal/fetcher/nvdfeed` |
| MITRE CVE (cvelistV5) | ✅ Supported | GitHub Releases zip via `internal/fetcher/mitre` |
| EPSS | ✅ Supported | FIRST bulk CSV via `internal/fetcher/epss` |
| KEV | ✅ Supported | CISA JSON catalog via `internal/fetcher/kev` |
| LEV | ✅ Supported | Computed from EPSS + KEV (NIST CSWP 41) |
| GitHub Security Advisories | ✅ Supported | GitHub REST API via `internal/fetcher/ghsa.go` |

## Current Phase

Phases 1–6 complete (Data Pipeline, CLI, CI/CD, API Server, Web UI, Additional Data Sources).

See [docs/PLAN.md](../docs/PLAN.md) for the full roadmap.

- [x] Phase 1: Data Pipeline (OSV ingestion)
- [x] Phase 2: CLI (ingest + search)
- [x] Phase 3: CI/CD (GitHub Actions)
- [x] Phase 4: API Server (REST)
- [x] Phase 5: Web UI (Angular)
- [x] Phase 6: Additional Data Sources (EPSS, KEV, LEV)
