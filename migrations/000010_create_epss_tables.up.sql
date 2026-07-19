-- EPSS (Exploit Prediction Scoring System) tables for storing EPSS scores
-- from the FIRST API (https://api.first.org/data/v1/epss).
-- Follows the same reversibility pattern as nvd_entries and mitre_entries:
-- raw_json preserves the original API response for full data reversibility.

BEGIN;

-- Main EPSS scores table (1 row per CVE per score_date)
-- EPSS scores are updated daily; we store the latest score for each CVE,
-- replacing the previous entry on reimport (same pattern as NVD/MITRE).
CREATE TABLE epss_scores (
    id                  BIGINT          GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cve_id              TEXT            NOT NULL,
    vulnerability_id    TEXT            NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    epss                FLOAT8          NOT NULL,  -- Probability of exploitation (0.0-1.0)
    percentile          FLOAT8          NOT NULL,  -- Relative ranking among all CVEs (0.0-1.0)
    score_date          DATE            NOT NULL,  -- Date the score was calculated
    raw_json            JSONB           NOT NULL,  -- Original API response entry (reversibility)
    CONSTRAINT epss_scores_cve_id_date_unique UNIQUE (cve_id, score_date)
);

-- Indexes for epss_scores
CREATE INDEX idx_epss_scores_vulnerability_id ON epss_scores (vulnerability_id);
CREATE INDEX idx_epss_scores_cve_id ON epss_scores (cve_id);
CREATE INDEX idx_epss_scores_epss ON epss_scores (epss DESC);
CREATE INDEX idx_epss_scores_percentile ON epss_scores (percentile DESC);
CREATE INDEX idx_epss_scores_score_date ON epss_scores (score_date DESC);

COMMIT;
