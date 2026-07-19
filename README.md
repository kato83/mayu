# Mayu

[![CI](https://github.com/kato83/mayu/actions/workflows/ci.yml/badge.svg)](https://github.com/kato83/mayu/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/kato83/mayu/branch/main/graph/badge.svg)](https://codecov.io/gh/kato83/mayu)
[![Go Report Card](https://goreportcard.com/badge/github.com/kato83/mayu)](https://goreportcard.com/report/github.com/kato83/mayu)
[![Go Reference](https://pkg.go.dev/badge/github.com/kato83/mayu.svg)](https://pkg.go.dev/github.com/kato83/mayu)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/github/go-mod/go-version/kato83/mayu)](https://github.com/kato83/mayu/blob/main/go.mod)

[日本語版 (Japanese)](README_ja.md)

A unified vulnerability intelligence tool that aggregates multiple sources (OSV, NVD, etc.) for cross-platform lookup via CLI, API, and Web UI.

## Overview

Mayu ingests vulnerability data from the [OSV](https://osv.dev/) ecosystem into a local PostgreSQL database, enabling fast cross-platform search and triage of known vulnerabilities.

**Current capabilities:**
- Full and delta import of OSV vulnerability data from the GCS bucket
- CLI-based vulnerability search by ID, package name, ecosystem, or alias
- REST API server with OpenAPI 3.1 specification
- Supports all OSV ecosystems (Go, PyPI, npm, Maven, crates.io, etc.)
- Raw OSV JSON preserved for full data reversibility

## Naming

**Mayu** comes from the Japanese word *繭 (mayu)*, meaning "cocoon" — the protective casing a silkworm spins around itself. The name reflects the tool's purpose: using vulnerability intelligence to wrap your environment in a gentle yet resilient layer of protection.

## Quick Start

### Prerequisites

- [Go 1.26+](https://go.dev/)
- PostgreSQL 17+

### Build from Source

```bash
git clone https://github.com/kato83/mayu.git
cd mayu
go build -o bin/mayu ./cmd/mayu
```

### Import Vulnerability Data

```bash
# Import all Go ecosystem vulnerabilities (full sync)
./bin/mayu ingest --ecosystem Go

# Import with delta update (only new/modified since last sync)
./bin/mayu ingest --ecosystem Go --update

# Import all supported ecosystems
./bin/mayu ingest --all

# Import all ecosystems with custom parallelism
./bin/mayu ingest --all --concurrency 5 --store-workers 8

# Bulk import from single top-level all.zip (~1.3GB, all ecosystems at once)
./bin/mayu ingest --all --bulk

# Import NVD CVE data directly from NVD JSON Feed 2.0
./bin/mayu ingest --source nvd --native

# Delta update from NVD modified feed
./bin/mayu ingest --source nvd --native --update

# Import MITRE CVE data from cvelistV5 GitHub Releases
./bin/mayu ingest --source mitre

# Delta update from hourly MITRE releases
./bin/mayu ingest --source mitre --update
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

# Search by Package URL (purl)
./bin/mayu search --purl pkg:npm/%40angular/core

# Positional argument (auto-detects ID vs alias)
./bin/mayu search CVE-2024-24790

# Filter by severity level
./bin/mayu search --severity critical --ecosystem Go

# Filter by date (modified since)
./bin/mayu search --since 2024-01-01 --ecosystem npm

# Filter by affected version
./bin/mayu search --package golang.org/x/crypto --version 0.17.0

# Pagination
./bin/mayu search --ecosystem Go --limit 10 --offset 20

# Count results only
./bin/mayu search --ecosystem Go --count

# Detailed view (all fields)
./bin/mayu search --id GO-2024-2687 --detail

# JSON output for scripting
./bin/mayu search --id GO-2024-2687 --format json

# CSV export
./bin/mayu search --ecosystem Go --format csv > vulns.csv
```

### Start API Server

```bash
# Start the API server (default port: 8080)
./bin/mayu serve

# Start on custom port
./bin/mayu serve --addr :3000

# OpenAPI spec available at http://localhost:8080/openapi.yaml
```

## CLI Reference

### `mayu ingest`

Import vulnerability data from OSV into the local database.

| Flag | Description | Default |
|------|-------------|---------|
| `--ecosystem` | Ecosystem to import (e.g., Go, PyPI, npm) | — |
| `--all` | Import all ecosystems (dynamically fetched from GCS) | `false` |
| `--bulk` | Use top-level all.zip for bulk import (with `--all`) | `false` |
| `--update` | Perform delta update instead of full import | `false` |
| `--source` | Import from source (nvd, debian, mitre) | — |
| `--native` | Use native data source feed (with `--source nvd`) | `false` |
| `--concurrency` | Number of ecosystems to import in parallel (with `--all`) | `3` |
| `--store-workers` | Number of parallel DB store workers per ecosystem | CPU cores - 1 |
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
| `--purl` | Search by Package URL (e.g., `pkg:npm/%40angular/core`) | — |
| `--severity` | Filter by CVSS severity level (critical, high, medium, low, none) | — |
| `--since` | Filter by modified date (YYYY-MM-DD or RFC3339) | — |
| `--version` | Filter by affected version | — |
| `--format` | Output format: `table`, `json`, `csv` | `table` |
| `--limit` | Maximum number of results | `20` |
| `--offset` | Offset for pagination | `0` |
| `--count` | Show only the result count | `false` |
| `--detail` | Show detailed information for each result | `false` |
| `--db-url` | PostgreSQL connection URL | `$DATABASE_URL` or `localhost` |

### `mayu serve`

Start the API server for programmatic access to vulnerability data.

| Flag | Description | Default |
|------|-------------|---------|
| `--addr` | Address to listen on (host:port) | `:8080` |
| `--db-url` | PostgreSQL connection URL | `$DATABASE_URL` or `localhost` |

**Endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/vulnerabilities` | Search vulnerabilities (same params as CLI search) |
| GET | `/api/v1/vulnerabilities/{id}` | Get a single vulnerability by OSV ID |
| GET | `/healthz` | Health check |
| GET | `/openapi.yaml` | OpenAPI 3.1 specification |

**Examples:**

```bash
curl "http://localhost:8080/api/v1/vulnerabilities?ecosystem=Go&limit=5"
curl "http://localhost:8080/api/v1/vulnerabilities/GO-2024-2687"
curl "http://localhost:8080/api/v1/vulnerabilities?package=golang.org/x/crypto"
curl "http://localhost:8080/api/v1/vulnerabilities?severity=critical"
curl "http://localhost:8080/api/v1/vulnerabilities?purl=pkg:golang/golang.org/x/crypto"
```

### `mayu version`

Print version information.

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

## Data Sources

| Source | Status | Method |
|--------|--------|--------|
| [OSV](https://osv.dev/) | ✅ Supported | GCS bucket (`gs://osv-vulnerabilities/`) |
| NVD (via OSV) | ✅ Supported | Included in OSV data |
| [NVD CVE (converted)](https://storage.googleapis.com/cve-osv-conversion/index.html?prefix=osv-output/) | ✅ Supported | `mayu ingest --source nvd` |
| [NVD CVE (native)](https://nvd.nist.gov/vuln/data-feeds) | ✅ Supported | `mayu ingest --source nvd --native` |
| [Debian Security Advisories](https://storage.googleapis.com/debian-osv/index.html) | ✅ Supported | `mayu ingest --source debian` |
| [MITRE CVE (cvelistV5)](https://github.com/CVEProject/cvelistV5) | ✅ Supported | `mayu ingest --source mitre` |

> **Note:** Converted sources (NVD, Debian) contain 50,000+ entries and are downloaded individually since no bulk archive is available. This may take significant time.

| Source | Status | Method |
|--------|--------|--------|
| KEV | 🔜 Planned | — |
| EPSS | 🔜 Planned | — |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding conventions, and how to submit changes.

## License

[MIT](LICENSE)

## Roadmap

See [docs/PLAN.md](docs/PLAN.md) for the full implementation plan.

- [x] Phase 1: Data Pipeline (OSV ingestion)
- [x] Phase 2: CLI (ingest + search)
- [x] Phase 3: CI/CD (GitHub Actions)
- [x] Phase 4: API Server (REST)
- [ ] Phase 5: Web UI (Angular)
- [ ] Phase 6: Additional Data Sources (KEV, EPSS)
