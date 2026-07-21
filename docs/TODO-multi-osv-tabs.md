# Vulnerability Detail: Multi-OSV Tab UI

## Background

When a single CVE has multiple OSV entries (e.g., GHSA-x32m-mvfj-52xv and GHSA-2vgg-9h6w-m454 both mapping to CVE-2024-21652), each may have different CVSS scores, affected packages, and details. Currently, `buildBaseDetail` only fetches one OSV entry (`LIMIT 1`), so data from other entries is lost.

## Proposed Design

### Backend Changes

1. **API response**: Return all OSV entries for the vulnerability in a new `osv_entries` array field within `VulnerabilityDetail`.
   ```json
   {
     "id": "CVE-2024-21652",
     "osv_entries": [
       {
         "osv_id": "GHSA-x32m-mvfj-52xv",
         "severity": [...],
         "affected": [...],
         "references": [...],
         ...
       },
       {
         "osv_id": "GHSA-2vgg-9h6w-m454",
         "severity": [...],
         "affected": [...],
         "references": [...],
         ...
       }
     ],
     "severity_worst": "CRITICAL",
     "severity_best": "MEDIUM",
     "nvd": {...},
     "mitre": {...},
     ...
   }
   ```

2. **Resolve tab from URL**: When accessed via `/vulnerabilities/GHSA-x32m-mvfj-52xv`, resolve to CVE-2024-21652 (existing behavior) but also return which `osv_id` was requested so the frontend can select the correct tab.

### Frontend Changes

1. **Tab UI**: Show tabs for each OSV entry (labeled by osv_id) within the detail page.
2. **Per-tab content**: Each tab displays that entry's severity, affected packages, references, and credits.
3. **Shared header**: The vulnerability ID (CVE-2024-21652), summary, severity_worst–severity_best badge, published/modified dates remain outside tabs.
4. **Shared sections**: NVD, MITRE, EPSS, KEV, LEV sections remain outside tabs (they're per-CVE, not per-OSV-entry).
5. **Active tab from URL**: If navigated via an alias (e.g., GHSA-xxx), that tab is pre-selected.
6. **Single OSV entry**: If only one OSV entry exists, no tabs are shown (current behavior preserved).

### Severity Panel Fix

Currently the severity section only shows one OSV entry's scores. With the tab design:
- Each tab shows its own severity scores
- The header badge shows the aggregated range (CRITICAL – MEDIUM)

## Priority

Medium — improves data completeness for multi-advisory CVEs but the current single-entry display is functional for most cases.
