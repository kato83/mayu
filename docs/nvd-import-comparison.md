# NVD Import Methods: Native vs. OSV-Converted

## Background

Mayu supports two methods for importing NVD (National Vulnerability Database) CVE data:

| Command | Data Source | Format |
|---------|-------------|--------|
| `mayu ingest --source nvd --native` | NVD directly (nvd.nist.gov) | NVD JSON Feed 2.0 |
| `mayu ingest --source nvd` | Google OSV conversion bucket | OSV JSON |

This document explains the differences between these two approaches based on a source code analysis of the [OSV conversion tool](https://github.com/google/osv.dev/tree/master/vulnfeeds/cmd/converters/cve/nvd-cve-osv) and an examination of the actual converted output.

## What the OSV Conversion Does

The OSV project's `nvd-cve-osv` tool is **not a simple format conversion**. It performs significant enrichment:

### 1. CPE → Git Repository Resolution

The tool uses a `cpe_product_to_repo.json` dictionary that maps CPE vendor/product names to GitHub repositories. It also derives repository URLs from CVE reference links.

```
CPE: cpe:2.3:a:microsoft:.net:*:*:*:*:*:*:*:*
  → Repository: https://github.com/dotnet/core
```

### 2. Git Commit Range Generation (Primary Value-Add)

The most significant enrichment: version ranges from NVD CPE data are resolved to actual Git commit hashes by matching repository tags.

```json
{
  "ranges": [{
    "type": "GIT",
    "repo": "https://github.com/dotnet/core",
    "events": [
      {"introduced": "63772e2191a750dd3cafa75914cacdb038c7520c"},
      {"fixed": "acd462c1e06e83a766b2385970316348765025d3"}
    ]
  }]
}
```

This enables C/C++ vulnerability matching via commit hashes, as described in the [OSV blog post](https://osv.dev/blog/posts/introducing-broad-c-c++-support/).

### 3. Version Extraction from Text

When CPE version data is insufficient, the tool attempts to extract version information from the CVE description text.

### 4. What It Does NOT Add

- **No `package` field** (ecosystem, name, purl) — confirmed across 50+ samples
- **No ECOSYSTEM-type ranges** — only GIT-type ranges are generated
- No additional CVSS scoring beyond what NVD provides

## Comparison

| Aspect | OSV-Converted (`--source nvd`) | NVD Native (`--source nvd --native`) |
|--------|-------------------------------|--------------------------------------|
| **Coverage** | Partial (52–82% conversion success rate per year) | Complete (all CVEs) |
| **Git commit ranges** | ✅ Added via tag resolution | ❌ Not available in NVD |
| **CPE configurations** | ❌ Lost (AND/OR logic not preserved) | ✅ Full CPE match logic preserved |
| **Package info (purl/ecosystem)** | ❌ Not added | ❌ Not in NVD either |
| **CVSS/Severity** | ✅ Preserved | ✅ Full (all metric versions) |
| **CWE information** | ❌ Not included | ✅ Preserved |
| **Version ranges** | Stored in `database_specific.extracted_events` | Stored in `nvd_cpe_matches` table |
| **Raw data reversibility** | OSV JSON (derivative) | NVD JSON (authoritative source) |
| **Data freshness** | Depends on OSV pipeline schedule | Direct from NVD |
| **Delta updates** | ❌ No delta mechanism | ✅ Modified feed available |

## Conversion Success Rates (from OSV logs)

The OSV conversion tool reports per-year metrics:

| Year | Success Rate |
|------|-------------|
| 2016 | 81.6% |
| 2017 | 77.1% |
| 2018 | 64.2% |
| 2019 | 71.3% |
| 2020 | 73.5% |
| 2021 | 74.3% |
| 2022 | 75.3% |
| 2023 | 73.0% |
| 2024 | 52.3% |

"Success" means the tool was able to resolve CPE data to Git commit ranges. The remaining CVEs are either out of scope (no viable Git repository) or fail version resolution.

## Conversion Outcomes

The tool categorizes each CVE into one of these outcomes:

- **Successful** — Git commit ranges resolved
- **NoRepos** — No Git repository could be associated with the CPE
- **NoRanges** — Repository found but version→commit resolution failed
- **FixUnresolvable** — Fix commit could not be determined
- **Rejected** — CVE was rejected/invalid

## Implications for Mayu

### When NVD Native is Sufficient

For Mayu's primary use cases — vulnerability search by CVE ID, package name, ecosystem, CVSS severity, and CPE-based matching — the NVD native import provides:

- **Complete coverage**: Every CVE is imported (not just the 52–82% that convert successfully)
- **Full CPE logic**: AND/OR configuration nodes are preserved for accurate product matching
- **CWE data**: Weakness enumeration is available for filtering/display
- **Delta updates**: Only modified CVEs are re-fetched on subsequent runs
- **Authoritative source**: Data comes directly from NIST, not a derivative

### When OSV-Converted Would Be Preferred

The OSV-converted data's unique value is **Git commit-level affected ranges**. This matters only if Mayu were to implement:

- C/C++ vulnerability matching by Git commit hash (similar to OSV-Scanner)
- Submodule/vendored dependency scanning at the commit level

Currently, Mayu does not implement this functionality.

## Recommendation

Given that:
1. NVD native provides complete CVE coverage (vs. partial for OSV-converted)
2. Mayu already has full NVD native import with CPE decomposition
3. The OSV conversion does not add purl/ecosystem/package information
4. The primary enrichment (Git commit ranges) serves a use case Mayu doesn't currently support
5. Having two `--source nvd` modes (with/without `--native`) creates user confusion

**The `--native` flag should be removed and `--source nvd` should always use the NVD native feed directly.** This simplifies the CLI interface without losing any functionality that Mayu currently uses.

If Git commit-level C/C++ matching is needed in the future, it could be re-introduced as a separate data source (e.g., `--source osv-nvd`) with clear documentation of its purpose and limitations.

## References

- [OSV NVD-CVE-OSV Converter Source](https://github.com/google/osv.dev/tree/master/vulnfeeds/cmd/converters/cve/nvd-cve-osv)
- [OSV Blog: Introducing broad C/C++ vulnerability management support](https://osv.dev/blog/posts/introducing-broad-c-c++-support/)
- [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities)
- [OSV Converted NVD Data (GCS)](https://storage.googleapis.com/cve-osv-conversion/index.html?prefix=osv-output/)
- [OSV Schema Specification](https://ossf.github.io/osv-schema/)
