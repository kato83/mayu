-- Rollback: restore original schema structure
-- WARNING: This is a destructive rollback. Data in vulnerability_aliases and
-- the unified vulnerabilities table will be lost (aliases are preserved in raw_json).

BEGIN;

-- ============================================================
-- Drop new tables and indexes
-- ============================================================

DROP INDEX IF EXISTS idx_vulnerability_aliases_vulnerability_id;
DROP INDEX IF EXISTS idx_vulnerability_aliases_alias;
DROP INDEX IF EXISTS idx_vulnerability_aliases_unique;
DROP INDEX IF EXISTS idx_vulnerabilities_modified;
DROP INDEX IF EXISTS idx_vulnerabilities_source;
DROP INDEX IF EXISTS idx_osv_entries_vulnerability_id;
DROP INDEX IF EXISTS idx_osv_entries_osv_id;
DROP INDEX IF EXISTS idx_osv_affected_packages_osv_entry_id;
DROP INDEX IF EXISTS idx_osv_affected_packages_ecosystem_name;
DROP INDEX IF EXISTS idx_osv_affected_packages_purl;
DROP INDEX IF EXISTS idx_osv_affected_ranges_package_id;
DROP INDEX IF EXISTS idx_osv_severity_entry_id;
DROP INDEX IF EXISTS idx_osv_references_entry_id;
DROP INDEX IF EXISTS idx_osv_credits_entry_id;

DROP TABLE IF EXISTS vulnerability_aliases;

-- ============================================================
-- Restore osv_credits → credits
-- ============================================================

ALTER TABLE osv_credits ADD COLUMN vulnerability_id TEXT;
UPDATE osv_credits c SET vulnerability_id = oe.osv_id FROM osv_entries oe WHERE c.osv_entry_id = oe.id;
ALTER TABLE osv_credits ALTER COLUMN vulnerability_id SET NOT NULL;
ALTER TABLE osv_credits DROP CONSTRAINT osv_credits_osv_entry_id_fkey;
ALTER TABLE osv_credits DROP COLUMN osv_entry_id;

-- ============================================================
-- Restore osv_references → references_
-- ============================================================

ALTER TABLE osv_references ADD COLUMN vulnerability_id TEXT;
UPDATE osv_references r SET vulnerability_id = oe.osv_id FROM osv_entries oe WHERE r.osv_entry_id = oe.id;
ALTER TABLE osv_references ALTER COLUMN vulnerability_id SET NOT NULL;
ALTER TABLE osv_references DROP CONSTRAINT osv_references_osv_entry_id_fkey;
ALTER TABLE osv_references DROP COLUMN osv_entry_id;

-- ============================================================
-- Restore osv_severity → severity
-- ============================================================

ALTER TABLE osv_severity ADD COLUMN vulnerability_id TEXT;
UPDATE osv_severity s SET vulnerability_id = oe.osv_id FROM osv_entries oe WHERE s.osv_entry_id = oe.id;
ALTER TABLE osv_severity ALTER COLUMN vulnerability_id SET NOT NULL;
ALTER TABLE osv_severity DROP CONSTRAINT osv_severity_osv_entry_id_fkey;
ALTER TABLE osv_severity DROP CONSTRAINT osv_severity_osv_affected_package_id_fkey;
ALTER TABLE osv_severity DROP COLUMN osv_entry_id;

-- ============================================================
-- Restore osv_affected_packages → affected_packages
-- ============================================================

ALTER TABLE osv_affected_packages ADD COLUMN vulnerability_id TEXT;
UPDATE osv_affected_packages ap SET vulnerability_id = oe.osv_id FROM osv_entries oe WHERE ap.osv_entry_id = oe.id;
ALTER TABLE osv_affected_packages ALTER COLUMN vulnerability_id SET NOT NULL;
ALTER TABLE osv_affected_packages DROP CONSTRAINT osv_affected_packages_osv_entry_id_fkey;
ALTER TABLE osv_affected_packages DROP COLUMN osv_entry_id;

-- ============================================================
-- Restore osv_entries → vulnerabilities
-- ============================================================

-- Add back columns from vulnerabilities master
ALTER TABLE osv_entries ADD COLUMN summary TEXT;
ALTER TABLE osv_entries ADD COLUMN details TEXT;
ALTER TABLE osv_entries ADD COLUMN published TIMESTAMPTZ;
ALTER TABLE osv_entries ADD COLUMN modified TIMESTAMPTZ;
ALTER TABLE osv_entries ADD COLUMN withdrawn TIMESTAMPTZ;
ALTER TABLE osv_entries ADD COLUMN aliases TEXT[];
ALTER TABLE osv_entries ADD COLUMN related TEXT[];
ALTER TABLE osv_entries ADD COLUMN upstream TEXT[];

-- Populate from the unified vulnerabilities table and raw_json
UPDATE osv_entries oe SET
    summary = v.summary,
    details = v.details,
    published = v.published,
    modified = v.modified,
    withdrawn = v.withdrawn
FROM vulnerabilities v
WHERE oe.vulnerability_id = v.id;

-- Restore aliases/related/upstream from raw_json
UPDATE osv_entries SET
    aliases = COALESCE(
        (SELECT array_agg(elem) FROM jsonb_array_elements_text(raw_json -> 'aliases') AS elem),
        '{}'::TEXT[]
    ),
    related = COALESCE(
        (SELECT array_agg(elem) FROM jsonb_array_elements_text(raw_json -> 'related') AS elem),
        '{}'::TEXT[]
    ),
    upstream = COALESCE(
        (SELECT array_agg(elem) FROM jsonb_array_elements_text(raw_json -> 'upstream') AS elem),
        '{}'::TEXT[]
    );

ALTER TABLE osv_entries ALTER COLUMN modified SET NOT NULL;

-- Drop the unified vulnerabilities table
DROP TABLE vulnerabilities;

-- Remove surrogate id and restore osv_id as PK
ALTER TABLE osv_entries DROP CONSTRAINT osv_entries_vulnerability_id_fkey;
ALTER TABLE osv_entries DROP COLUMN vulnerability_id;
ALTER TABLE osv_entries DROP CONSTRAINT osv_entries_pkey;
ALTER TABLE osv_entries DROP CONSTRAINT osv_entries_osv_id_unique;
ALTER TABLE osv_entries DROP COLUMN id;
ALTER TABLE osv_entries RENAME COLUMN osv_id TO id;
ALTER TABLE osv_entries ADD PRIMARY KEY (id);

-- ============================================================
-- Rename tables back
-- ============================================================

ALTER TABLE osv_entries RENAME TO vulnerabilities;
ALTER TABLE osv_affected_packages RENAME TO affected_packages;
ALTER TABLE osv_affected_ranges RENAME TO affected_ranges;
ALTER TABLE osv_severity RENAME TO severity;
ALTER TABLE osv_references RENAME TO references_;
ALTER TABLE osv_credits RENAME TO credits;

-- ============================================================
-- Restore FK constraints
-- ============================================================

ALTER TABLE affected_packages ADD CONSTRAINT affected_packages_vulnerability_id_fkey
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE;

ALTER TABLE severity ADD CONSTRAINT severity_vulnerability_id_fkey
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE;
ALTER TABLE severity ADD CONSTRAINT severity_affected_package_id_fkey
    FOREIGN KEY (affected_package_id) REFERENCES affected_packages(id) ON DELETE CASCADE;

ALTER TABLE references_ ADD CONSTRAINT references__vulnerability_id_fkey
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE;

ALTER TABLE credits ADD CONSTRAINT credits_vulnerability_id_fkey
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE;

-- ============================================================
-- Restore indexes (from migration 000002)
-- ============================================================

CREATE INDEX idx_vulnerabilities_modified ON vulnerabilities (modified DESC);
CREATE INDEX idx_affected_packages_ecosystem_name ON affected_packages (ecosystem, name);
CREATE INDEX idx_affected_packages_vulnerability_id ON affected_packages (vulnerability_id);
CREATE INDEX idx_affected_packages_purl ON affected_packages (purl) WHERE purl IS NOT NULL;
CREATE INDEX idx_affected_ranges_affected_package_id ON affected_ranges (affected_package_id);
CREATE INDEX idx_severity_vulnerability_id ON severity (vulnerability_id);
CREATE INDEX idx_references_vulnerability_id ON references_ (vulnerability_id);
CREATE INDEX idx_credits_vulnerability_id ON credits (vulnerability_id);
CREATE INDEX idx_vulnerabilities_aliases ON vulnerabilities USING GIN (aliases);

-- ============================================================
-- Restore sync_state column name
-- ============================================================

ALTER TABLE sync_state RENAME COLUMN source TO ecosystem;

COMMIT;
