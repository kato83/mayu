-- Create epss_daily_stats summary table for fast EPSS coverage queries.
-- This table stores per-date aggregates (at most ~900 rows for 2.5 years of data),
-- replacing expensive full-table scans of the epss_scores table (millions of rows).
CREATE TABLE IF NOT EXISTS epss_daily_stats (
    score_date DATE PRIMARY KEY,
    score_count INTEGER NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Populate from existing data (one-time migration).
INSERT INTO epss_daily_stats (score_date, score_count)
SELECT score_date, COUNT(*)
FROM epss_scores
GROUP BY score_date
ON CONFLICT DO NOTHING;
