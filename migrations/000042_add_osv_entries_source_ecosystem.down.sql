DROP INDEX IF EXISTS idx_osv_entries_source_ecosystem;
ALTER TABLE osv_entries DROP COLUMN IF EXISTS source_ecosystem;
