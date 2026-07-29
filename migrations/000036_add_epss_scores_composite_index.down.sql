-- Revert: restore original single-column index and drop composite index.

DROP INDEX IF EXISTS idx_epss_scores_vuln_date;

CREATE INDEX idx_epss_scores_vulnerability_id
    ON epss_scores (vulnerability_id);
