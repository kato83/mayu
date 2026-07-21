-- osv_ecosystems: tracks known OSV ecosystem names for UI dropdowns.
-- Populated/updated during OSV ingest from osv_affected_packages.
CREATE TABLE IF NOT EXISTS osv_ecosystems (
    name TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
