-- Revert: remove source_osv_id from vulnerability_aliases

BEGIN;

-- Drop new indexes
DROP INDEX IF EXISTS idx_vulnerability_aliases_source_osv_id;
DROP INDEX IF EXISTS idx_vulnerability_aliases_unique;

-- Remove column
ALTER TABLE vulnerability_aliases DROP COLUMN source_osv_id;

-- Recreate original unique index
CREATE UNIQUE INDEX idx_vulnerability_aliases_unique
    ON vulnerability_aliases (vulnerability_id, alias);

COMMIT;
