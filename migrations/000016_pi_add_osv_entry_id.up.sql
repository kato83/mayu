-- Add osv_entry_id column to product_identifiers for per-entry granularity.
-- Previously, product_identifiers were deleted/re-created at the vulnerability_id
-- level, causing data loss when multiple OSV entries share the same CVE.

ALTER TABLE product_identifiers
    ADD COLUMN osv_entry_id TEXT REFERENCES osv_entries(osv_id) ON DELETE CASCADE;

CREATE INDEX idx_pi_osv_entry_id ON product_identifiers (osv_entry_id) WHERE osv_entry_id IS NOT NULL;

-- Backfill: For existing rows (source='osv'), attempt to resolve osv_entry_id
-- by matching ecosystem+name against osv_affected_packages.
-- For vulnerabilities with a single OSV entry, assign it directly.
UPDATE product_identifiers pi
SET osv_entry_id = sub.osv_id
FROM (
    SELECT oe.vulnerability_id, oe.osv_id
    FROM osv_entries oe
    WHERE NOT EXISTS (
        SELECT 1 FROM osv_entries oe2
        WHERE oe2.vulnerability_id = oe.vulnerability_id AND oe2.osv_id != oe.osv_id
    )
) sub
WHERE pi.source = 'osv'
  AND pi.vulnerability_id = sub.vulnerability_id
  AND pi.osv_entry_id IS NULL;

-- For vulnerabilities with multiple OSV entries, match by ecosystem+name via osv_affected_packages.
UPDATE product_identifiers pi
SET osv_entry_id = sub.osv_entry_id
FROM (
    SELECT DISTINCT ON (oap.osv_entry_id, pi2.ecosystem, pi2.name)
        pi2.id AS pi_id, oap.osv_entry_id
    FROM product_identifiers pi2
    JOIN osv_affected_packages oap
        ON oap.ecosystem = pi2.ecosystem AND oap.name = pi2.name
    JOIN osv_entries oe ON oe.osv_id = oap.osv_entry_id AND oe.vulnerability_id = pi2.vulnerability_id
    WHERE pi2.source = 'osv' AND pi2.osv_entry_id IS NULL
) sub
WHERE pi.id = sub.pi_id;
