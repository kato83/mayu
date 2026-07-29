# Mayu Vulnerability Scan — GitHub Action

Official GitHub Action for scanning SBOM or lockfiles for known vulnerabilities using [mayu](https://github.com/kato83/mayu).

## Features

- 🔍 Scan CycloneDX or SPDX SBOMs for vulnerabilities
- 📊 SARIF output with automatic upload to GitHub Code Scanning
- 📋 Job Summary with scan results
- ⚙️ Configurable fail threshold (critical, high, medium, low)
- 📦 Multi-source ingestion (OSV, NVD, MITRE, EPSS, KEV)
- 🔧 Version pinning for reproducible builds

## Quick Start

```yaml
name: Vulnerability Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:17
        env:
          POSTGRES_USER: mayu
          POSTGRES_PASSWORD: mayu
          POSTGRES_DB: mayu
        ports:
          - 5432:5432
        options: >-
          --health-cmd "pg_isready -U mayu"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    steps:
      - uses: actions/checkout@v4

      - name: Mayu Scan
        uses: ./.github/actions/mayu-scan
        with:
          sbom: './bom.json'
          database-url: 'postgres://mayu:mayu@localhost:5432/mayu?sslmode=disable'
          ingest-ecosystems: 'Go,npm'
          fail-on: 'critical,high'
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `sbom` | Path to SBOM file (CycloneDX or SPDX JSON) | No* | `''` |
| `lockfile` | Path to lockfile to scan | No* | `''` |
| `scan-dir` | Directory to scan for lockfiles (auto-detect) | No* | `''` |
| `fail-on` | Fail threshold (comma-separated: `critical,high,medium,low,none`) | No | `''` |
| `ignore` | Path to ignore file (`.mayu-ignore` format) | No | `''` |
| `format` | Output format (`table`, `json`, `sarif`) | No | `sarif` |
| `mayu-version` | Mayu version to install (`latest` or specific tag) | No | `latest` |
| `database-url` | PostgreSQL connection string | **Yes** | — |
| `ingest-sources` | Comma-separated sources to ingest (`osv,nvd,mitre,epss,kev`). Use `none` to skip. | No | `osv` |
| `ingest-ecosystems` | Comma-separated ecosystems for OSV ingestion (e.g., `Go,npm,PyPI`). Use `all` for all. | No | `''` |
| `upload-sarif` | Upload SARIF results to GitHub Code Scanning | No | `true` |

> \* At least one of `sbom`, `lockfile`, or `scan-dir` must be specified.

## Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Total number of vulnerability findings |
| `sarif-file` | Path to the generated SARIF file (if `format=sarif`) |
| `exit-code` | Exit code from mayu audit (`0`=clean, `1`=findings above threshold, `2`=error) |

## Usage Examples

### Basic SBOM Scan

```yaml
- uses: ./.github/actions/mayu-scan
  with:
    sbom: './sbom.cdx.json'
    database-url: 'postgres://mayu:mayu@localhost:5432/mayu?sslmode=disable'
    ingest-ecosystems: 'Go'
```

### Scan with Multiple Ecosystems

```yaml
- uses: ./.github/actions/mayu-scan
  with:
    sbom: './bom.json'
    database-url: 'postgres://mayu:mayu@localhost:5432/mayu?sslmode=disable'
    ingest-ecosystems: 'Go,npm,PyPI'
    fail-on: 'critical,high'
```

### Full Source Ingestion (NVD + EPSS + KEV)

```yaml
- uses: ./.github/actions/mayu-scan
  with:
    sbom: './bom.json'
    database-url: 'postgres://mayu:mayu@localhost:5432/mayu?sslmode=disable'
    ingest-sources: 'osv,nvd,epss,kev'
    ingest-ecosystems: 'Go'
    fail-on: 'critical,high'
```

### Auto-detect SBOM in Directory

```yaml
- uses: ./.github/actions/mayu-scan
  with:
    scan-dir: '.'
    database-url: 'postgres://mayu:mayu@localhost:5432/mayu?sslmode=disable'
    ingest-ecosystems: 'npm'
```

### Skip SARIF Upload (Table Output Only)

```yaml
- uses: ./.github/actions/mayu-scan
  with:
    sbom: './bom.json'
    database-url: 'postgres://mayu:mayu@localhost:5432/mayu?sslmode=disable'
    ingest-ecosystems: 'Go'
    format: 'table'
    upload-sarif: 'false'
```

### Pin Mayu Version

```yaml
- uses: ./.github/actions/mayu-scan
  with:
    sbom: './bom.json'
    database-url: 'postgres://mayu:mayu@localhost:5432/mayu?sslmode=disable'
    ingest-ecosystems: 'Go'
    mayu-version: 'v0.0.1-alpha.1'
```

### With Ignore File

```yaml
- uses: ./.github/actions/mayu-scan
  with:
    sbom: './bom.json'
    database-url: 'postgres://mayu:mayu@localhost:5432/mayu?sslmode=disable'
    ingest-ecosystems: 'Go'
    fail-on: 'critical,high'
    ignore: '.mayu-ignore'
```

### Use Scan Results in Subsequent Steps

```yaml
- name: Mayu Scan
  id: scan
  uses: ./.github/actions/mayu-scan
  with:
    sbom: './bom.json'
    database-url: 'postgres://mayu:mayu@localhost:5432/mayu?sslmode=disable'
    ingest-ecosystems: 'Go'
  continue-on-error: true

- name: Process results
  run: |
    echo "Findings: ${{ steps.scan.outputs.findings-count }}"
    echo "Exit code: ${{ steps.scan.outputs.exit-code }}"
    if [ "${{ steps.scan.outputs.exit-code }}" = "1" ]; then
      echo "::warning::Vulnerabilities detected but continuing..."
    fi
```

## Full Workflow Example

See [`.github/workflows/mayu-scan-example.yml`](../../workflows/mayu-scan-example.yml) for a complete workflow with PostgreSQL service container.

## Prerequisites

### PostgreSQL Service Container

The action requires a PostgreSQL database. Define it as a service container in your workflow:

```yaml
services:
  postgres:
    image: postgres:17
    env:
      POSTGRES_USER: mayu
      POSTGRES_PASSWORD: mayu
      POSTGRES_DB: mayu
    ports:
      - 5432:5432
    options: >-
      --health-cmd "pg_isready -U mayu"
      --health-interval 10s
      --health-timeout 5s
      --health-retries 5
```

### GitHub Code Scanning (SARIF Upload)

To use the SARIF upload feature, your repository must have GitHub Code Scanning enabled (available for public repos and GitHub Advanced Security licensed repos).

## How It Works

1. **Install** — Downloads the mayu binary from GitHub Releases
2. **Migrate** — Applies database schema migrations
3. **Ingest** — Imports vulnerability data from configured sources
4. **Audit** — Scans the SBOM for known vulnerabilities
5. **Report** — Uploads SARIF and posts a Job Summary
6. **Gate** — Fails the workflow if findings exceed the threshold

## Ignore File Format

Create a `.mayu-ignore` file to suppress known accepted vulnerabilities:

```
# Accepted risks (one ID per line)
CVE-2024-1234    # reason: no impact on our usage
GHSA-xxxx-yyyy   # suppressed until 2025-03-01
```

## License

[MIT](../../../LICENSE)
