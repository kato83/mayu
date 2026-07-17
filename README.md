# Mayu

[日本語版 (Japanese)](README_ja.md)

A unified vulnerability intelligence tool that aggregates multiple sources (OSV, NVD, etc.) for cross-platform lookup via CLI, API, and Web UI.

## Overview

Mayu ingests vulnerability data from the [OSV](https://osv.dev/) ecosystem into a local PostgreSQL database, enabling fast cross-platform search and triage of known vulnerabilities.

**Current capabilities:**
- Full and delta import of OSV vulnerability data from the GCS bucket
- CLI-based vulnerability search by ID, package name, ecosystem, or alias
- Supports all OSV ecosystems (Go, PyPI, npm, Maven, crates.io, etc.)
- Raw OSV JSON preserved for full data reversibility

## Quick Start

### Prerequisites

- [Go 1.26+](https://go.dev/) (managed via [asdf](https://asdf-vm.com/))
- [Docker](https://www.docker.com/) & Docker Compose
- [golang-migrate](https://github.com/golang-migrate/migrate) CLI

### Setup

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
```

### Import Vulnerability Data

```bash
# Import all Go ecosystem vulnerabilities (full sync)
./bin/mayu ingest --ecosystem Go

# Import with delta update (only new/modified since last sync)
./bin/mayu ingest --ecosystem Go --update

# Import all supported ecosystems
./bin/mayu ingest --all
```

### Search Vulnerabilities

```bash
# Search by vulnerability ID
./bin/mayu search --id GO-2024-2687

# Search by package name
./bin/mayu search --package golang.org/x/crypto

# Search by ecosystem
./bin/mayu search --ecosystem Go --limit 10

# Search by CVE alias
./bin/mayu search --alias CVE-2024-24790

# Positional argument (auto-detects ID vs alias)
./bin/mayu search CVE-2024-24790

# JSON output for scripting
./bin/mayu search --id GO-2024-2687 --format json
```

## CLI Reference

### `mayu ingest`

Import vulnerability data from OSV into the local database.

| Flag | Description | Default |
|------|-------------|---------|
| `--ecosystem` | Ecosystem to import (e.g., Go, PyPI, npm) | — |
| `--all` | Import all known ecosystems | `false` |
| `--update` | Perform delta update instead of full import | `false` |
| `--db-url` | PostgreSQL connection URL | `$DATABASE_URL` or `localhost` |
| `--batch-size` | Number of vulnerabilities per batch insert | `100` |

### `mayu search`

Search for vulnerabilities in the local database.

| Flag | Description | Default |
|------|-------------|---------|
| `--id` | Search by vulnerability ID | — |
| `--package` | Search by package name | — |
| `--ecosystem` | Filter by ecosystem | — |
| `--alias` | Search by alias (e.g., CVE ID) | — |
| `--format` | Output format: `table`, `json` | `table` |
| `--limit` | Maximum number of results | `20` |
| `--db-url` | PostgreSQL connection URL | `$DATABASE_URL` or `localhost` |

### `mayu version`

Print version information.

## Architecture

```
┌─────────────────────────────────────────────┐
│              CLI (cmd/mayu)                  │
├─────────────┬───────────────────────────────┤
│   ingest    │           search              │
└──────┬──────┴───────────────┬───────────────┘
       │                      │
┌──────┴──────────────────────┴───────────────┐
│            Core (internal/)                  │
├─────────┬──────────┬────────┬───────────────┤
│ Fetcher │  Parser  │ Store  │    Ingest     │
│  (GCS)  │  (OSV)   │  (PG)  │  (Pipeline)   │
└─────────┴──────────┴───┬────┴───────────────┘
                          │
                   ┌──────┴──────┐
                   │ PostgreSQL  │
                   └─────────────┘
```

## Data Sources

| Source | Status | Method |
|--------|--------|--------|
| [OSV](https://osv.dev/) | ✅ Supported | GCS bucket (`gs://osv-vulnerabilities/`) |
| NVD (via OSV) | ✅ Supported | Included in OSV data |
| [NVD CVE (converted)](https://storage.googleapis.com/cve-osv-conversion/index.html?prefix=osv-output/) | ✅ Supported | `mayu ingest --source nvd` |
| [Debian Security Advisories](https://storage.googleapis.com/debian-osv/index.html) | ✅ Supported | `mayu ingest --source debian` |

> **Note:** Converted sources (NVD, Debian) contain 50,000+ entries and are downloaded individually since no bulk archive is available. This may take significant time. Parallel download optimization is planned for a future release.

| Source | Status | Method |
|--------|--------|--------|
| KEV | 🔜 Planned | — |
| EPSS | 🔜 Planned | — |

## Development

```bash
# Run unit tests
make test

# Run integration tests (requires PostgreSQL)
make docker-up && make migrate-up
make test-integration

# Lint
make lint

# Stop PostgreSQL
make docker-down
```

## Configuration

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgres://mayu:mayu@localhost:5432/mayu?sslmode=disable` |

> [!WARNING]
> The default connection string uses `sslmode=disable`, which is
> appropriate only for local development against the bundled Docker PostgreSQL.
> For any remote or production database, **enforce TLS** by setting
> `sslmode=require` (or `verify-full` for certificate verification), e.g.
> `postgres://user:pass@db.example.com:5432/mayu?sslmode=verify-full`.
> Mayu prints a warning when it detects a connection to a non-local host without
> enforced TLS.

## License

TBD

## Roadmap

See [docs/PLAN.md](docs/PLAN.md) for the full implementation plan.

- [x] Phase 1: Data Pipeline (OSV ingestion)
- [x] Phase 2: CLI (ingest + search)
- [x] Phase 3: CI/CD (GitHub Actions)
- [ ] Phase 4: API Server (REST)
- [ ] Phase 5: Web UI (Angular)
- [ ] Phase 6: Additional Data Sources (KEV, EPSS, MITRE CVE)
