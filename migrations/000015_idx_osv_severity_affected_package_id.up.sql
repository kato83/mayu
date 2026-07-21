-- Add index on osv_severity.affected_package_id to speed up CASCADE deletes
-- from osv_affected_packages. Without this index, each row deletion triggers
-- a sequential scan of the entire osv_severity table for FK validation.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_osv_severity_affected_package_id
    ON osv_severity (affected_package_id)
    WHERE affected_package_id IS NOT NULL;
