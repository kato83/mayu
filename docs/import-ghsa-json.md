# Importing GitHub Security Advisory JSON

How to import vulnerabilities into mayu when they exist only as repository-level GitHub Security Advisories and have not yet reached OSV.

## Background

GitHub Security Advisories (GHSAs) are published in two stages:

1. **Repository Security Advisory** — Created and published by maintainers within their repository (`/security/advisories/GHSA-xxxx`)
2. **GitHub Advisory Database** — Curated by GitHub's security team and reflected in the global advisory database

OSV automatically ingests from the GitHub Advisory Database. Advisories that are only at stage 1 are **not** present in OSV. This gap (typically days to weeks) can be bridged by manually constructing OSV-format JSON and importing via `mayu ingest --file`.

## Obtaining GHSA JSON

### Method 1: GitHub Advisory Database Repository (OSV Format — Recommended)

GitHub publishes all reviewed advisories as OSV-format JSON in the [`github/advisory-database`](https://github.com/github/advisory-database) repository.

- Directory structure: `advisories/{github-reviewed|unreviewed}/{year}/{month}/{GHSA-ID}/{GHSA-ID}.json`

```bash
# Fetch a specific GHSA directly
curl -sL -o GHSA-xxxx-xxxx-xxxx.json \
  https://raw.githubusercontent.com/github/advisory-database/main/advisories/github-reviewed/2026/07/GHSA-xxxx-xxxx-xxxx/GHSA-xxxx-xxxx-xxxx.json

# Import into mayu
./bin/mayu ingest --file GHSA-xxxx-xxxx-xxxx.json
```

> **Note**: Returns 404 if the advisory has not yet been reflected in the global Advisory Database. Use Method 3 in that case.

### Method 2: GitHub REST API (GitHub-native Format)

```bash
# Global Advisory API (no auth required, rate-limited)
curl -sH "Accept: application/vnd.github+json" \
  https://api.github.com/advisories/GHSA-xxxx-xxxx-xxxx

# Repository Advisory API (requires token)
curl -sH "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  https://api.github.com/repos/{owner}/{repo}/security-advisories/GHSA-xxxx-xxxx-xxxx
```

> **Note**: The REST API response is in GitHub's proprietary format, not OSV. Conversion to OSV format is required before importing into mayu.

### Method 3: Manual OSV JSON Construction

Read the information from the repository Security Advisory page (e.g., `https://github.com/{owner}/{repo}/security/advisories/GHSA-xxxx`) and construct OSV-format JSON manually.

Required fields:
- `id` — GHSA ID
- `modified` — Last modification timestamp (ISO 8601)

Recommended fields:
- `schema_version` — `"1.6.0"`
- `published` — Publication timestamp
- `aliases` — CVE IDs, etc.
- `summary` — One-line summary
- `details` — Detailed description
- `severity` — CVSS vector
- `affected` — Affected packages and version ranges
- `references` — Reference links
- `credits` — Reporters/finders

Template:

```json
{
    "schema_version": "1.6.0",
    "id": "GHSA-xxxx-xxxx-xxxx",
    "published": "2026-01-01T00:00:00Z",
    "modified": "2026-01-01T00:00:00Z",
    "aliases": [
        "CVE-2026-XXXXX"
    ],
    "summary": "One-line summary of the vulnerability",
    "details": "Detailed description of the vulnerability and its impact.",
    "severity": [
        {
            "type": "CVSS_V3",
            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        }
    ],
    "affected": [
        {
            "package": {
                "ecosystem": "Ecosystem",
                "name": "package-name"
            },
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "1.0.0"},
                        {"fixed": "1.0.1"}
                    ]
                }
            ]
        }
    ],
    "references": [
        {
            "type": "ADVISORY",
            "url": "https://github.com/{owner}/{repo}/security/advisories/GHSA-xxxx-xxxx-xxxx"
        },
        {
            "type": "WEB",
            "url": "https://example.com/release-notes"
        }
    ],
    "credits": [
        {
            "name": "Researcher Name",
            "type": "FINDER"
        }
    ]
}
```

## Importing into mayu

```bash
# Single file
./bin/mayu ingest --file GHSA-xxxx-xxxx-xxxx.json

# Multiple files
./bin/mayu ingest --file vuln1.json vuln2.json vuln3.json

# Custom DB URL
./bin/mayu ingest --file vuln1.json --db-url postgres://user:pass@host/db
```

## Worked Example: WordPress CVE-2026-60137 / CVE-2026-63030

Two critical vulnerabilities disclosed in WordPress 7.0.2 (July 17, 2026). Repository Security Advisories existed but had not yet propagated to the GitHub Advisory Database or OSV.

### Information Sources

| Source | URL | Information Obtained |
|--------|-----|---------------------|
| WordPress release notes | https://wordpress.org/news/2026/07/wordpress-7-0-2-release/ | Affected versions, backports, CVE/GHSA mapping |
| Repo Advisory (SQLi) | https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-fpp7-x2x2-2mjf | Affected versions, summary, severity |
| Repo Advisory (RCE) | https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ff9f-jf42-662q | Affected versions, summary, severity |
| NVD (via mayu DB) | `mayu search --id CVE-2026-60137` | CVSS, CWE |
| MITRE (via mayu DB) | Direct DB query | SSVC assessment, CISA-ADP CVSS |

### Created OSV JSON Files

<details>
<summary>GHSA-fpp7-x2x2-2mjf.json (CVE-2026-60137 — SQL Injection)</summary>

```json
{
    "schema_version": "1.6.0",
    "id": "GHSA-fpp7-x2x2-2mjf",
    "published": "2026-07-17T19:14:12Z",
    "modified": "2026-07-17T19:14:12Z",
    "aliases": ["CVE-2026-60137"],
    "summary": "Facilitated SQL injection vulnerability in the author__not_in parameter of WP_Query",
    "details": "WordPress versions 6.8 and higher are vulnerable to an SQL injection issue. In WordPress versions 6.9 and higher, this combined with a REST API batch-route confusion issue (GHSA-ff9f-jf42-662q) leads to Remote Code Execution.",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
    "affected": [{
        "package": {"ecosystem": "WordPress", "name": "wordpress"},
        "ranges": [
            {"type": "ECOSYSTEM", "events": [{"introduced": "6.8.0"}, {"fixed": "6.8.6"}]},
            {"type": "ECOSYSTEM", "events": [{"introduced": "6.9.0"}, {"fixed": "6.9.5"}]},
            {"type": "ECOSYSTEM", "events": [{"introduced": "7.0.0"}, {"fixed": "7.0.2"}]}
        ]
    }],
    "references": [
        {"type": "ADVISORY", "url": "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-fpp7-x2x2-2mjf"},
        {"type": "WEB", "url": "https://wordpress.org/news/2026/07/wordpress-7-0-2-release/"}
    ],
    "credits": [{"name": "TF1T, dtro, and haongo", "type": "FINDER"}]
}
```

</details>

<details>
<summary>GHSA-ff9f-jf42-662q.json (CVE-2026-63030 — RCE via Route Confusion)</summary>

```json
{
    "schema_version": "1.6.0",
    "id": "GHSA-ff9f-jf42-662q",
    "published": "2026-07-17T19:14:12Z",
    "modified": "2026-07-17T19:14:12Z",
    "aliases": ["CVE-2026-63030"],
    "summary": "REST API batch-route confusion and SQL injection issue leading to Remote Code Execution",
    "details": "WordPress versions 6.9 and higher are vulnerable to a REST API batch-route confusion weakness, which combined with an SQL injection issue (GHSA-fpp7-x2x2-2mjf) leads to Remote Code Execution.",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "affected": [{
        "package": {"ecosystem": "WordPress", "name": "wordpress"},
        "ranges": [
            {"type": "ECOSYSTEM", "events": [{"introduced": "6.9.0"}, {"fixed": "6.9.5"}]},
            {"type": "ECOSYSTEM", "events": [{"introduced": "7.0.0"}, {"fixed": "7.0.2"}]}
        ]
    }],
    "references": [
        {"type": "ADVISORY", "url": "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ff9f-jf42-662q"},
        {"type": "WEB", "url": "https://wordpress.org/news/2026/07/wordpress-7-0-2-release/"}
    ],
    "credits": [{"name": "Adam Kues (Assetnote / Searchlight Cyber)", "type": "FINDER"}]
}
```

</details>

### Import Execution

```bash
./bin/mayu ingest --file \
  /tmp/mayu-import/GHSA-fpp7-x2x2-2mjf.json \
  /tmp/mayu-import/GHSA-ff9f-jf42-662q.json
```

```
=== Importing 2 local OSV JSON file(s) ===
  ✓ /tmp/mayu-import/GHSA-fpp7-x2x2-2mjf.json (id=GHSA-fpp7-x2x2-2mjf, aliases=[CVE-2026-60137])
  ✓ /tmp/mayu-import/GHSA-ff9f-jf42-662q.json (id=GHSA-ff9f-jf42-662q, aliases=[CVE-2026-63030])

Done: 2 imported, 0 failed
```

## Important Notes

- Manually created JSON will be overwritten when official data sources are updated (OSV upsert rules)
- Once reflected in the GitHub Advisory Database, `mayu ingest --all` will automatically fetch the latest data
- The `ecosystem` field accepts values not in OSV's official ecosystem list (e.g., `WordPress`), but search behavior may be limited until official support is added
- The OSV `id` field has a unique constraint — re-importing the same GHSA ID will overwrite existing data

## Related Resources

- [OSV Schema Specification](https://ossf.github.io/osv-schema/)
- [GitHub Advisory Database Repository](https://github.com/github/advisory-database)
- [GitHub Security Advisories REST API](https://docs.github.com/en/rest/security-advisories)
- [WP Sec Adv (Wordfence → Composer)](https://github.com/typisttech/wpsecadv) — WordPress security advisories for Composer
