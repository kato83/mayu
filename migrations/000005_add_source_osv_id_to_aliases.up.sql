-- Add source_osv_id to vulnerability_aliases to track which OSV entry
-- contributed each alias. This enables safe per-entry alias cleanup
-- without affecting aliases contributed by other OSV entries.

BEGIN;

-- Add source_osv_id column (nullable initially for backfill)
ALTER TABLE vulnerability_aliases ADD COLUMN source_osv_id TEXT;

-- Backfill: for existing records, derive source_osv_id from the alias itself
-- if it matches an osv_entries.osv_id, otherwise use the vulnerability_id.
UPDATE vulnerability_aliases va
SET source_osv_id = COALESCE(
    (SELECT oe.osv_id FROM osv_entries oe WHERE oe.osv_id = va.alias LIMIT 1),
    (SELECT oe.osv_id FROM osv_entries oe WHERE oe.vulnerability_id = va.vulnerability_id LIMIT 1),
    va.vulnerability_id
);

-- Make NOT NULL after backfill
ALTER TABLE vulnerability_aliases ALTER COLUMN source_osv_id SET NOT NULL;

-- Drop old unique index and create new one including source_osv_id
DROP INDEX IF EXISTS idx_vulnerability_aliases_unique;
CREATE UNIQUE INDEX idx_vulnerability_aliases_unique
    ON vulnerability_aliases (vulnerability_id, alias, source_osv_id);

-- Index for efficient per-source cleanup queries
CREATE INDEX idx_vulnerability_aliases_source_osv_id
    ON vulnerability_aliases (source_osv_id);

COMMIT;
