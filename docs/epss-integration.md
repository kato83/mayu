# EPSS Integration

## Overview

[EPSS (Exploit Prediction Scoring System)](https://www.first.org/epss/) is a data-driven model maintained by FIRST (Forum of Incident Response and Security Teams) that estimates the probability that a CVE will be exploited in the wild within the next 30 days.

Mayu integrates EPSS scores by downloading the daily bulk CSV from FIRST and storing them in the `epss_scores` table, linked to the unified `vulnerabilities` table via CVE ID.

## Data Source

| Property | Value |
|----------|-------|
| Provider | FIRST (Forum of Incident Response and Security Teams) |
| URL | https://www.first.org/epss/ |
| API Endpoint | https://api.first.org/data/v1/epss |
| Bulk CSV | https://epss.cyentia.com/epss_scores-current.csv.gz |
| Update Frequency | Daily (UTC 00:00+) |
| Coverage | All CVEs (~200,000+) |
| Authentication | None required |
| Rate Limiting | None documented |

## Usage

### Full Import (recommended for initial setup)

```bash
# Download and import all EPSS scores (~200,000+ CVEs)
mayu ingest --source epss
```

### Daily Update

```bash
# Skip if already synced today, otherwise download fresh scores
mayu ingest --source epss --update
```

### Automation

For daily automation, schedule the update command once per day after UTC 00:00:

```bash
# crontab example: run at 06:00 UTC daily
0 6 * * * /path/to/mayu ingest --source epss --update
```

## Data Model

### Score Fields

| Field | Type | Description |
|-------|------|-------------|
| `epss` | float (0.0-1.0) | Probability of exploitation in next 30 days |
| `percentile` | float (0.0-1.0) | Relative ranking among all scored CVEs |
| `score_date` | date | Date the score was calculated |

### Interpretation

- **epss = 0.94**: ~94% probability of exploitation in the next 30 days
- **percentile = 0.999**: In the top 0.1% most likely to be exploited

### Database Schema

```sql
CREATE TABLE epss_scores (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cve_id              TEXT NOT NULL,
    vulnerability_id    TEXT NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    epss                FLOAT8 NOT NULL,
    percentile          FLOAT8 NOT NULL,
    score_date          DATE NOT NULL,
    raw_json            JSONB NOT NULL,
    CONSTRAINT epss_scores_cve_id_date_unique UNIQUE (cve_id, score_date)
);
```

## Reversibility

Following the same pattern as NVD and MITRE data, the original API response entry is preserved in the `raw_json` JSONB column. This ensures:

- No data loss during normalization
- Ability to re-derive any field from the original data
- Audit trail of exactly what was received from the source

## Architecture

```
FIRST EPSS CSV (daily)
    │
    ▼
internal/fetcher/epss.go    ← Download + decompress gzipped CSV
    │
    ▼
internal/model/epss.go      ← Parse CSV lines → EPSSScore structs
    │
    ▼
internal/ingest/epss.go     ← Orchestrate batched import pipeline
    │
    ▼
internal/store/epss.go      ← Upsert into PostgreSQL (epss_scores table)
```

## Future: LEV (Likely Exploited Vulnerabilities)

The EPSS integration is designed with extensibility in mind for future scoring systems. In particular, [NIST CSWP 41 "Likely Exploited Vulnerabilities"](https://csrc.nist.gov/pubs/cswp/41/likely-exploited-vulnerabilities/final) (published May 2025) proposes a complementary metric. When LEV data becomes available as a feed, it can follow the same pattern:

- Dedicated `lev_scores` table (similar schema to `epss_scores`)
- Same reversibility pattern (raw_json JSONB)
- Same batch upsert store interface pattern
- Same CLI integration (`mayu ingest --source lev`)
