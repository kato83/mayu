-- Migration 000013 rollback: Remove new schema tables, restore old columns.

BEGIN;

-- Drop new tables
DROP TABLE IF EXISTS purl_cpe_mapping;
DROP TABLE IF EXISTS product_identifiers;
DROP TABLE IF EXISTS vulnerability_summary;
DROP TABLE IF EXISTS alias_sources;

-- Drop decomposed CPE columns from nvd_cpe_matches
DROP INDEX IF EXISTS idx_nvdcpe_vendor_product;
DROP INDEX IF EXISTS idx_nvdcpe_product;
ALTER TABLE nvd_cpe_matches DROP COLUMN IF EXISTS cpe_part;
ALTER TABLE nvd_cpe_matches DROP COLUMN IF EXISTS cpe_vendor;
ALTER TABLE nvd_cpe_matches DROP COLUMN IF EXISTS cpe_product;
ALTER TABLE nvd_cpe_matches DROP COLUMN IF EXISTS cpe_version;
ALTER TABLE nvd_cpe_matches DROP COLUMN IF EXISTS cpe_update;
ALTER TABLE nvd_cpe_matches DROP COLUMN IF EXISTS cpe_edition;
ALTER TABLE nvd_cpe_matches DROP COLUMN IF EXISTS cpe_language;
ALTER TABLE nvd_cpe_matches DROP COLUMN IF EXISTS cpe_sw_edition;
ALTER TABLE nvd_cpe_matches DROP COLUMN IF EXISTS cpe_target_sw;
ALTER TABLE nvd_cpe_matches DROP COLUMN IF EXISTS cpe_target_hw;
ALTER TABLE nvd_cpe_matches DROP COLUMN IF EXISTS cpe_other;

-- Restore vulnerability_aliases columns
ALTER TABLE vulnerability_aliases ADD COLUMN IF NOT EXISTS ordering INT NOT NULL DEFAULT 0;
ALTER TABLE vulnerability_aliases ADD COLUMN IF NOT EXISTS source_osv_id TEXT;

-- Backfill source_osv_id from osv_entries
UPDATE vulnerability_aliases va
SET source_osv_id = COALESCE(
    (SELECT oe.osv_id FROM osv_entries oe WHERE oe.vulnerability_id = va.vulnerability_id LIMIT 1),
    va.vulnerability_id
)
WHERE source_osv_id IS NULL;

ALTER TABLE vulnerability_aliases ALTER COLUMN source_osv_id SET NOT NULL;

-- Recreate old unique index
DROP INDEX IF EXISTS idx_vulnerability_aliases_unique;
CREATE UNIQUE INDEX idx_vulnerability_aliases_unique
    ON vulnerability_aliases (vulnerability_id, alias, source_osv_id);
CREATE INDEX idx_vulnerability_aliases_source_osv_id
    ON vulnerability_aliases (source_osv_id);

-- Restore vulnerabilities.source column
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS source TEXT;
UPDATE vulnerabilities SET source = 'osv' WHERE source IS NULL;

COMMIT;
