-- Add composite index for EPSS trending performance optimization.
--
-- The EPSS trending query uses:
--   DISTINCT ON (vulnerability_id) ... ORDER BY vulnerability_id, score_date DESC
-- which requires sorting 130M+ rows without a composite index.
--
-- This covering index enables Index-Only Scan for:
-- 1. GetEPSSTrending: latest_scores and previous_scores CTEs
-- 2. GetEPSSHistory: WHERE vulnerability_id = $1 ORDER BY score_date
-- 3. GetLEVHistory: WHERE vulnerability_id = $1 ORDER BY score_date ASC
-- 4. RefreshEPSSSummary: DISTINCT ON (vulnerability_id) ORDER BY vulnerability_id, score_date DESC
--
-- INCLUDE (epss, percentile) avoids heap lookups for the most common SELECT columns.
-- CONCURRENTLY avoids locking the table during index creation on production.

CREATE INDEX CONCURRENTLY idx_epss_scores_vuln_date
    ON epss_scores (vulnerability_id, score_date DESC)
    INCLUDE (epss, percentile);

-- The old single-column index is now redundant (leading column of the new composite).
DROP INDEX CONCURRENTLY idx_epss_scores_vulnerability_id;
