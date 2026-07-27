BEGIN;

DROP TABLE IF EXISTS osv_entries_translation;

ALTER TABLE osv_entries DROP COLUMN IF EXISTS summary;
ALTER TABLE osv_entries DROP COLUMN IF EXISTS details;

COMMIT;
