-- Revert: restore original single-column index and drop composite index.

CREATE INDEX CONCURRENTLY idx_epss_scores_vulnerability_id
    ON epss_scores (vulnerability_id);

DROP INDEX CONCURRENTLY idx_epss_scores_vuln_date;
