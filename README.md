# Mayu

[![CI](https://github.com/kato83/mayu/actions/workflows/ci.yml/badge.svg)](https://github.com/kato83/mayu/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/github/go-mod/go-version/kato83/mayu)](https://github.com/kato83/mayu/blob/main/go.mod)

[日本語版 (Japanese)](README_ja.md)

A unified vulnerability intelligence tool that aggregates multiple sources (OSV, NVD, etc.) for cross-platform lookup via CLI, API, and Web UI.

## Overview

Mayu ingests vulnerability data from the [OSV](https://osv.dev/) ecosystem into a local PostgreSQL database, enabling fast cross-platform search and triage of known vulnerabilities.

**Current capabilities:**
- Full and delta import of OSV vulnerability data from the GCS bucket
- Direct import of GitHub Security Advisories — even before they reach OSV, just `wget` the API response and feed it to mayu
- CLI-based vulnerability search by ID, package name, ecosystem, or alias
- REST API server with OpenAPI 3.1 specification
- Supports all OSV ecosystems (Go, PyPI, npm, Maven, crates.io, etc.)
- Raw OSV JSON preserved for full data reversibility

![](./docs/readme_pic01.jpg)

## Naming

**Mayu** comes from the Japanese word *繭 (mayu)*, meaning "cocoon" — the protective casing a silkworm spins around itself. The name reflects the tool's purpose: using vulnerability intelligence to wrap your environment in a gentle yet resilient layer of protection.

## Why Mayu?

There are several excellent vulnerability intelligence tools available. Mayu occupies a unique position by combining the following characteristics in a single, self-contained tool:

| | Cloud-based CVE CLIs | CVE Monitoring Platforms | **Mayu** |
|---|---|---|---|
| Data ownership | Cloud API dependent | Self-hosted or SaaS | **Fully local (PostgreSQL)** |
| Offline / air-gap | ❌ | Partial (self-hosted) | **✅ After initial sync** |
| REST API built-in | ❌ (client only) | ✅ | **✅** |
| Web UI built-in | ❌ | ✅ | **✅** |
| CLI | ✅ | Limited | **✅** |
| OSV ecosystem coverage | ❌ (CVE/CPE only) | ❌ (CVE/CPE only) | **✅ 46 ecosystems (package-level)** |
| Package-name search | ❌ | ❌ | **✅** |
| EPSS / KEV / LEV | EPSS + KEV | EPSS + KEV | **EPSS + KEV + LEV** |
| Custom data import | ❌ | ❌ | **✅ (local JSON files)** |
| Raw data preservation | ❌ | Partial | **✅ Full reversibility** |
| Account / API key required | ✅ | ✅ (SaaS) | **❌** |

**In short:**

- Unlike cloud-based CLI tools, mayu **owns all data locally** and provides a built-in REST API and Web UI — no external service dependency or API key required.
- Unlike CVE monitoring platforms focused on vendor/product (CPE) matching and alerting, mayu supports **package-level search across all OSV ecosystems** (Go, npm, PyPI, Maven, crates.io, etc.) and computes **LEV scores** for exploitation likelihood estimation.
- Mayu is designed as a **vulnerability intelligence backend** — a single binary that can serve as both a personal lookup tool and an organization-wide vulnerability data API.

## Installation

### Pre-built Binaries (Recommended)

Download the latest release from [GitHub Releases](https://github.com/kato83/mayu/releases).
Release binaries include the Web UI embedded — just run `mayu serve` and access the UI at `http://localhost:8080/`.

| Platform | Architecture | Download |
|----------|-------------|----------|
| Linux | x86_64 | `mayu_*_linux_amd64.tar.gz` |
| Linux | ARM64 | `mayu_*_linux_arm64.tar.gz` |
| macOS | x86_64 (Intel) | `mayu_*_darwin_amd64.tar.gz` |
| macOS | ARM64 (Apple Silicon) | `mayu_*_darwin_arm64.tar.gz` |
| Windows | x86_64 | `mayu_*_windows_amd64.zip` |
| Windows | ARM64 | `mayu_*_windows_arm64.zip` |

```bash
# Example: Linux x86_64
curl -LO https://github.com/kato83/mayu/releases/latest/download/mayu_0.0.1-alpha.1_linux_amd64.tar.gz
tar xzf mayu_0.0.1-alpha.1_linux_amd64.tar.gz
sudo mv mayu /usr/local/bin/

# Verify installation
mayu version
```

### Build from Source

Requires:
- [Go 1.26+](https://go.dev/)
- [Node.js 24+](https://nodejs.org/) (for Web UI build)
- [pnpm 11+](https://pnpm.io/) (for Web UI dependency management)

```bash
git clone https://github.com/kato83/mayu.git
cd mayu

# Build with embedded Web UI (recommended — same as release binaries)
make build-embed

# Run — UI is served automatically at /
./bin/mayu serve
```

> [!TIP]
> If you only need the CLI/API without the Web UI, you can build with Go alone:
> ```bash
> go build -o bin/mayu ./cmd/mayu
> ```
> In this case, use `--ui-dir` to serve the Web UI from a separately built directory.

## Quick Start

### Prerequisites

- PostgreSQL 17+

> [!TIP]
> If you only want to try mayu quickly, use Docker to run PostgreSQL:
> ```bash
> docker run -d --name mayu-pg -e POSTGRES_USER=mayu -e POSTGRES_PASSWORD=mayu -e POSTGRES_DB=mayu -p 5432:5432 postgres:17
> ```

### Setup

```bash
# Run database migrations
mayu migrate

# Import vulnerability data (e.g., Go ecosystem)
mayu ingest --ecosystem Go

# Search vulnerabilities
mayu search --package golang.org/x/crypto
```

### Import Vulnerability Data

```bash
# Import all Go ecosystem vulnerabilities (full sync)
mayu ingest --ecosystem Go

# Import with delta update (only new/modified since last sync)
mayu ingest --ecosystem Go --update

# Import all supported ecosystems
mayu ingest --all

# Import all ecosystems with custom parallelism
mayu ingest --all --concurrency 5 --store-workers 8

# Bulk import from single top-level all.zip (~1.3GB, all ecosystems at once)
mayu ingest --all --bulk

# Import NVD CVE data directly from NVD JSON Feed 2.0
mayu ingest --source nvd --native

# Import only a specific year's NVD data
mayu ingest --source nvd --native --year 2024

# Delta update from NVD modified feed
mayu ingest --source nvd --native --update

# Import MITRE CVE data from cvelistV5 GitHub Releases
mayu ingest --source mitre

# Delta update from hourly MITRE releases
mayu ingest --source mitre --update

# Import EPSS scores (Exploit Prediction Scoring System)
mayu ingest --source epss

# Update EPSS scores (daily refresh if outdated)
mayu ingest --source epss --update

# Backfill EPSS historical data (required for LEV computation)
mayu ingest --source epss --backfill

# Backfill EPSS for a specific date range
mayu ingest --source epss --backfill --from 2024-01-01 --to 2025-07-19

# Import CISA KEV catalog (Known Exploited Vulnerabilities)
mayu ingest --source kev

# Update KEV catalog (refresh if outdated)
mayu ingest --source kev --update

# Import local OSV JSON files (e.g., manually constructed GHSA advisories)
mayu ingest --file GHSA-xxxx-xxxx-xxxx.json GHSA-yyyy-yyyy-yyyy.json
```

### Search Vulnerabilities

```bash
# Search by vulnerability ID
mayu search --id GO-2024-2687

# Search by package name
mayu search --package golang.org/x/crypto

# Search by ecosystem
mayu search --ecosystem Go --limit 10

# Search by CVE alias
mayu search --id CVE-2024-24790

# Search by Package URL (purl)
mayu search --purl pkg:npm/%40angular/core

# Positional argument (shorthand for --id)
mayu search CVE-2024-24790

# Filter by severity level
mayu search --severity critical --ecosystem Go

# Filter by date (modified since)
mayu search --since 2024-01-01 --ecosystem npm

# Filter by affected version
mayu search --package golang.org/x/crypto --version 0.17.0

# Pagination
mayu search --ecosystem Go --limit 10 --offset 20

# Cursor-based pagination (use NextToken from previous output)
mayu search --ecosystem Go --limit 10 --starting-token <token>

# Count results only
mayu search --ecosystem Go --count

# Detailed view (all fields)
mayu search --id GO-2024-2687 --detail

# JSON output for scripting
mayu search --id GO-2024-2687 --format json

# CSV export
mayu search --ecosystem Go --format csv > vulns.csv
```

### Audit SBOM

```bash
# Audit CycloneDX SBOM for vulnerabilities
mayu audit --sbom ./sbom.cdx.json

# Audit SPDX SBOM
mayu audit --sbom ./sbom.spdx.json

# Include dev dependencies
mayu audit --sbom ./sbom.cdx.json --include-dev

# Skip version matching (show all vulnerabilities for matched packages)
mayu audit --sbom ./sbom.cdx.json --no-version-check

# JSON output
mayu audit --sbom ./sbom.cdx.json --format json

# CSV output
mayu audit --sbom ./sbom.cdx.json --format csv
```

### Start API Server

```bash
# Start the API server (default port: 8080)
mayu serve

# Start on custom port
mayu serve --addr :3000

# Serve with Web UI from external directory (only needed for non-embed builds)
mayu serve --ui-dir ./ui/dist/mayu/browser

# OpenAPI spec available at http://localhost:8080/openapi.yaml
```

> [!NOTE]
> Release binaries and `make build-embed` builds already include the Web UI — `mayu serve`
> serves the UI at `/` automatically without any extra options.
> The `--ui-dir` option is only needed when building without embed (plain `go build`)
> and is useful for development or serving a custom UI build.
> For production, we recommend serving the Angular static assets via a dedicated web server
> (Nginx, Apache) or a CDN-backed storage service (S3 + CloudFront, GCS + Cloud CDN, etc.)
> to benefit from proper caching, compression, access control, and horizontal scalability.

## CLI Reference

### `mayu ingest`

Import vulnerability data from OSV into the local database.

| Flag | Description | Default |
|------|-------------|---------|
| `--ecosystem` | Ecosystem to import (e.g., Go, PyPI, npm) | — |
| `--all` | Import all ecosystems (dynamically fetched from GCS) | `false` |
| `--bulk` | Use top-level all.zip for bulk import (with `--all`) | `false` |
| `--update` | Perform delta update instead of full import | `false` |
| `--backfill` | Backfill historical data (with `--source epss`) | `false` |
| `--from` | Start date for backfill (YYYY-MM-DD) | `2023-03-07` (EPSS v3) |
| `--to` | End date for backfill (YYYY-MM-DD) | today |
| `--source` | Import from source (nvd, debian, mitre, epss, kev) | — |
| `--native` | Use native data source feed (with `--source nvd`) | `false` |
| `--year` | Import only a specific year's NVD feed (with `--source nvd --native`) | — |
| `--file` | Import from local OSV JSON files (paths as positional args) | `false` |
| `--concurrency` | Number of ecosystems to import in parallel (with `--all`) | `3` |
| `--store-workers` | Number of parallel DB store workers per ecosystem | CPU cores - 1 |
| `--batch-size` | Number of vulnerabilities per batch insert | `100` |

### `mayu audit`

Audit an SBOM for known vulnerabilities.

| Flag | Description | Default |
|------|-------------|---------|
| `--sbom` | Path to SBOM file (CycloneDX 1.7 or SPDX 2.3 JSON) | (required) |
| `--format` | Output format: `table`, `json`, `csv` | `table` |
| `--include-dev` | Include development dependencies in audit | `false` |
| `--no-version-check` | Skip version matching, report all vulnerabilities for package name | `false` |

**Exit codes:**

| Code | Meaning |
|------|---------|
| 0 | No vulnerabilities found |
| 1 | One or more vulnerabilities found |
| 2 | Error (invalid input, database connection failure, etc.) |

**Supported SBOM formats:**
- CycloneDX 1.7 (JSON) — dev dependencies detected via `scope` and `cdx:npm:package:development` property
- SPDX 2.3 (JSON) — all packages treated as production (SPDX lacks dev/prod distinction)

### `mayu search`

Search for vulnerabilities in the local database.

| Flag | Description | Default |
|------|-------------|---------|
| `--id` | Search by vulnerability ID or alias (e.g., CVE-2024-1234, GO-2024-2687, GHSA-xxxx) | — |
| `--package` | Search by package name | — |
| `--ecosystem` | Filter by ecosystem | — |
| `--purl` | Search by Package URL (e.g., `pkg:npm/%40angular/core`) | — |
| `--severity` | Filter by CVSS severity level (critical, high, medium, low, none) | — |
| `--since` | Filter by modified date (YYYY-MM-DD or RFC3339) | — |
| `--version` | Filter by affected version | — |
| `--format` | Output format: `table`, `json`, `csv` | `table` |
| `--limit` | Maximum number of results | `20` |
| `--offset` | Offset for pagination (deprecated: use `--starting-token`) | `0` |
| `--starting-token` | Cursor token for pagination (from previous `NextToken` output) | — |
| `--count` | Show only the result count | `false` |
| `--detail` | Show detailed information for each result | `false` |

### `mayu serve`

Start the API server for programmatic access to vulnerability data.

| Flag | Description | Default |
|------|-------------|---------|
| `--addr` | Address to listen on (host:port) | `:8080` |
| `--ui-dir` | Path to SPA static files directory for Web UI hosting | — |

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

### `mayu migrate`

Run database migrations (embedded in the binary).

| Flag | Description | Default |
|------|-------------|---------|
| `--steps` | Number of migrations to apply (0 = all, negative to roll back) | `0` |

**Subcommands:**

| Subcommand | Description |
|------------|-------------|
| `up` | Apply all pending migrations (default) |
| `down` | Roll back one migration (or `--steps N`) |
| `status` | Show current migration version |

**Examples:**

```bash
mayu migrate              # Apply all pending migrations
mayu migrate up
mayu migrate down
mayu migrate down --steps 3
mayu migrate status
```

### `mayu version`

Print version information.

## Configuration

### Configuration File

Mayu supports a YAML configuration file. The default path is:

```
$HOME/.config/mayu/config.yaml
```

You can specify a custom path with the `--config` global option:

```bash
mayu --config /path/to/config.yaml search --id CVE-2024-1234
```

If the default config file does not exist, mayu silently falls back to environment variables and defaults. If `--config` is explicitly specified and the file does not exist, mayu reports an error.

**Example `config.yaml`:**

```yaml
database_url: postgres://mayu:mayu@localhost:5432/mayu?sslmode=disable
```

**Priority order** (highest to lowest):

1. Environment variables (`DATABASE_URL`)
2. Configuration file (`config.yaml` — specify path with `--config`)
3. Default values

### Environment Variables

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
| KEV | ✅ Supported | `mayu ingest --source kev` |
| EPSS | ✅ Supported | `mayu ingest --source epss` |
| LEV | ✅ Supported | Computed from EPSS + KEV (see below) |

## LEV (Likely Exploited Vulnerabilities)

Mayu computes [LEV](https://doi.org/10.6028/NIST.CSWP.41) scores — a probabilistic metric proposed by NIST (CSWP 41) that estimates the chance a CVE has **already been exploited in the wild**.

### How it works

LEV combines two data sources already in mayu:

| Data Source | Role | Time Perspective |
|-------------|------|-----------------|
| **EPSS** | Daily exploitation probability (P30) | Future (next 30 days) |
| **CISA KEV** | Confirmed exploitation | Past (known exploited) |
| **LEV** | Probability of past exploitation | Past (estimated) |

**Algorithm** (rigorous approach from NIST CSWP 41):

```
P1  = 1 - (1 - P30)^(1/30)       # Convert EPSS 30-day prob → daily prob
LEV = 1 - ∏(1 - P1_i)             # Compound across all historical days
```

If the CVE is in the CISA KEV catalog, LEV is automatically set to **1.0** (confirmed exploitation).

> **Note:** This implementation uses the rigorous P30→P1 conversion, not the `P30/30` approximation from the paper which is inaccurate for high EPSS scores.

### Setup for LEV

LEV requires historical daily EPSS data. Use the backfill command to build up the time-series:

```bash
# 1. Import CISA KEV catalog
mayu ingest --source kev

# 2. Backfill EPSS daily scores from EPSS v3 release (2023-03-07) to today
mayu ingest --source epss --backfill

# Or specify a custom date range
mayu ingest --source epss --backfill --from 2024-01-01 --to 2025-07-19

# 3. After initial backfill, keep EPSS up-to-date with daily updates
mayu ingest --source epss --update
```

> **Tip:** The backfill downloads ~5-7 MB per day (~200,000 CVE scores). A full backfill from 2023-03-07 covers ~860 days. Already-imported dates are automatically skipped on re-run.

### Viewing LEV scores

LEV is displayed automatically in the `--detail` view and the API `?detail=true` response:

```bash
mayu search --id CVE-2023-38831 --detail
```

Output includes EPSS, KEV, and LEV sections:

```
EPSS:
  Score:      0.94218 (94.2%)
  Percentile: 0.99923 (99.9%)
  Score Date: 2026-07-19
KEV (CISA Known Exploited Vulnerabilities):
  Vendor/Project: WinRAR
  Product:        WinRAR
  Vuln Name:      RARLAB WinRAR Code Execution Vulnerability
  Date Added:     2023-08-24
  Due Date:       2023-09-14
  Ransomware Use: Known
LEV (Likely Exploited Vulnerabilities - NIST CSWP 41):
  Score:       1.00000 (100.0%)
  In KEV:      true
  EPSS Days:   730
  First EPSS:  2023-03-07
  Last EPSS:   2025-07-19
```

API example:

```bash
curl "http://localhost:8080/api/v1/vulnerabilities/CVE-2023-38831?detail=true" | jq '.lev'
```

```json
{
  "lev": 1.0,
  "in_kev": true,
  "epss_score_count": 730,
  "first_epss_date": "2023-03-07",
  "last_epss_date": "2025-07-19",
  "computed_at": "2026-07-19T12:00:00Z"
}
```

### Interpreting LEV scores

| LEV Range | Interpretation |
|-----------|---------------|
| 0.95 – 1.0 | Almost certainly exploited (or confirmed via KEV) |
| 0.70 – 0.95 | Very likely exploited |
| 0.30 – 0.70 | Possibly exploited |
| 0.05 – 0.30 | Low probability of past exploitation |
| 0.00 – 0.05 | Unlikely to have been exploited |

> **Important:** LEV is a probabilistic estimate, not a confirmed fact. It should be used alongside other signals (KEV, EPSS, CVSS) for vulnerability prioritization.

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
- [x] Phase 5: Web UI (Angular)
- [x] Phase 6: Additional Data Sources (EPSS, KEV, LEV)

### Web UI

The Web UI is an Angular v22 application with TailwindCSS v4, located in `ui/`.

```bash
# Development server (proxies /api to mayu serve on :8080)
make ui-dev

# Production build
make ui-build

# Run tests
make ui-test
```

Features:
- Left sidebar admin-style layout
- Vulnerability list with full filter support (ecosystem, package, severity, date, etc.)
- Vulnerability detail page with OSV, NVD, and MITRE enrichment
- Dark mode (automatic via `prefers-color-scheme`)
- URL-synced filters and cursor-based pagination
