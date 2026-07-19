-- Add composite index on (ecosystem, osv_entry_id) to osv_affected_packages.
-- This eliminates the inefficient plan where the planner scans by osv_entry_id
-- and then filters on ecosystem, discarding the majority of rows.

CREATE INDEX CONCURRENTLY idx_osv_affected_packages_ecosystem_entry
    ON osv_affected_packages (ecosystem, osv_entry_id);
