-- CISA KEV (Known Exploited Vulnerabilities) table for storing entries from
-- the CISA KEV catalog (https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
-- Follows the same reversibility pattern as nvd_entries, mitre_entries, and epss_scores:
-- raw_json preserves the original catalog entry for full data reversibility.

BEGIN;

-- Main KEV entries table (1 row per CVE)
-- The KEV catalog is a flat list of vulnerabilities known to be exploited in the wild.
CREATE TABLE kev_entries (
    id                          BIGINT          GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cve_id                      TEXT            NOT NULL,
    vulnerability_id            TEXT            NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    vendor_project              TEXT            NOT NULL,
    product                     TEXT            NOT NULL,
    vulnerability_name          TEXT            NOT NULL,
    date_added                  DATE            NOT NULL,  -- Date added to KEV catalog
    short_description           TEXT            NOT NULL,
    required_action             TEXT            NOT NULL,
    due_date                    DATE            NOT NULL,  -- Remediation due date
    known_ransomware_campaign_use TEXT          NOT NULL DEFAULT 'Unknown',  -- Known, Unknown
    notes                       TEXT,
    cwes                        TEXT[],         -- CWE IDs (e.g., CWE-502, CWE-78)
    raw_json                    JSONB           NOT NULL,  -- Original catalog entry (reversibility)
    CONSTRAINT kev_entries_cve_id_unique UNIQUE (cve_id)
);

-- Indexes for kev_entries
CREATE INDEX idx_kev_entries_vulnerability_id ON kev_entries (vulnerability_id);
CREATE INDEX idx_kev_entries_cve_id ON kev_entries (cve_id);
CREATE INDEX idx_kev_entries_vendor_project ON kev_entries (vendor_project);
CREATE INDEX idx_kev_entries_product ON kev_entries (product);
CREATE INDEX idx_kev_entries_date_added ON kev_entries (date_added DESC);
CREATE INDEX idx_kev_entries_due_date ON kev_entries (due_date DESC);
CREATE INDEX idx_kev_entries_ransomware ON kev_entries (known_ransomware_campaign_use);

COMMIT;
