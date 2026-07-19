# KEV Integration

## Overview

[CISA KEV (Known Exploited Vulnerabilities)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) is CISA's authoritative catalog of vulnerabilities that have been confirmed to be actively exploited in the wild. Organizations subject to BOD 22-01 are required to remediate these vulnerabilities by the specified due date.

Mayu integrates KEV data by downloading the full catalog JSON from CISA and storing entries in the `kev_entries` table, linked to the unified `vulnerabilities` table via CVE ID.

## Data Source

| Property | Value |
|----------|-------|
| Provider | CISA (Cybersecurity and Infrastructure Security Agency) |
| URL | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| JSON Feed | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| Update Frequency | A few times per week (irregular) |
| Coverage | ~1,600+ CVEs confirmed exploited in the wild |
| Authentication | None required |
| Rate Limiting | None documented |
| Format | Single JSON file (~1-2 MB) |

## Usage

### Full Import (recommended for initial setup)

```bash
# Download and import all KEV entries (~1,600+ CVEs)
mayu ingest --source kev
```

### Periodic Update

```bash
# Skip if already synced within the last hour, otherwise re-download
mayu ingest --source kev --update
```

### Automation

For automated monitoring, schedule the update command periodically:

```bash
# crontab example: run every 6 hours
0 */6 * * * /path/to/mayu ingest --source kev --update
```

## Data Model

### Entry Fields

| Field | Type | Description |
|-------|------|-------------|
| `cve_id` | text | CVE identifier (e.g., CVE-2023-38831) |
| `vendor_project` | text | Vendor/project name (e.g., Microsoft, Fortinet) |
| `product` | text | Product name (e.g., SharePoint, FortiSandbox) |
| `vulnerability_name` | text | Human-readable vulnerability title |
| `date_added` | date | Date the CVE was added to the KEV catalog |
| `short_description` | text | Brief vulnerability description |
| `required_action` | text | Remediation action required by affected organizations |
| `due_date` | date | Deadline for remediation (per BOD 22-01) |
| `known_ransomware_campaign_use` | text | "Known" or "Unknown" |
| `notes` | text | Additional URLs and context |
| `cwes` | text[] | CWE classifications (e.g., CWE-502, CWE-78) |

### Interpretation

- **date_added**: When CISA confirmed active exploitation
- **due_date**: Federal agencies must remediate by this date (BOD 22-01)
- **known_ransomware_campaign_use = "Known"**: Vulnerability is associated with ransomware campaigns
- **cwes**: Weakness classifications for the vulnerability

### Database Schema

```sql
CREATE TABLE kev_entries (
    id                          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cve_id                      TEXT NOT NULL,
    vulnerability_id            TEXT NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    vendor_project              TEXT NOT NULL,
    product                     TEXT NOT NULL,
    vulnerability_name          TEXT NOT NULL,
    date_added                  DATE NOT NULL,
    short_description           TEXT NOT NULL,
    required_action             TEXT NOT NULL,
    due_date                    DATE NOT NULL,
    known_ransomware_campaign_use TEXT NOT NULL DEFAULT 'Unknown',
    notes                       TEXT,
    cwes                        TEXT[],
    raw_json                    JSONB NOT NULL,
    CONSTRAINT kev_entries_cve_id_unique UNIQUE (cve_id)
);
```

## Reversibility

Following the same pattern as NVD, MITRE, and EPSS data, the original catalog entry is preserved in the `raw_json` JSONB column. This ensures:

- No data loss during normalization
- Ability to re-derive any field from the original data
- Audit trail of exactly what was received from the source

## Architecture

```
CISA KEV JSON (periodic)
    │
    ▼
internal/fetcher/kev.go     ← Download full catalog JSON
    │
    ▼
internal/model/kev.go       ← Parse JSON → KEVRecord structs
    │
    ▼
internal/ingest/kev.go      ← Orchestrate batched import pipeline
    │
    ▼
internal/store/kev.go       ← Upsert into PostgreSQL (kev_entries table)
```

## Upsert Strategy

The KEV catalog is cumulative — entries are never removed, only added or occasionally updated. The upsert strategy:

1. **Vulnerabilities table**: `INSERT ... ON CONFLICT DO NOTHING` — KEV only creates the vulnerability row if it doesn't already exist. It never overwrites richer data from OSV/NVD/MITRE.
2. **KEV entries table**: `INSERT ... ON CONFLICT (cve_id) DO UPDATE` — all fields are updated with the latest catalog data on reimport.

## Delta Strategy

There is no delta mechanism for the KEV catalog. The full catalog is small (~1-2 MB) and downloading it is inexpensive. The `--update` flag implements a simple time-based throttle:

- If never synced: performs full import.
- If last sync was within 1 hour: skips (already up-to-date).
- Otherwise: re-downloads the full catalog.

## Use Cases

### Prioritization

KEV entries are valuable for vulnerability prioritization:

- **Presence in KEV = confirmed exploitation** — should be prioritized for immediate remediation
- Combined with EPSS scores, enables risk-based prioritization:
  - KEV + high EPSS → immediate action required
  - KEV + low EPSS → still requires action (confirmed exploitation overrides prediction)
  - Not in KEV + high EPSS → monitor closely
  - Not in KEV + low EPSS → standard patching cycle

### Compliance

Organizations subject to CISA BOD 22-01 must remediate KEV entries by their `due_date`. The `due_date` field enables compliance tracking and reporting.

### Ransomware Assessment

The `known_ransomware_campaign_use` field provides immediate visibility into vulnerabilities associated with ransomware campaigns, enabling targeted defensive measures.
