-- Schema refactoring: separate OSV-specific tables, create unified vulnerability master,
-- externalize aliases into a proper relation table.
--
-- This migration preserves existing data by renaming tables and migrating data
-- from the old vulnerabilities table into the new structure.

BEGIN;

-- ============================================================
-- Step 1: Rename existing OSV-specific tables with osv_ prefix
-- ============================================================

ALTER TABLE affected_packages RENAME TO osv_affected_packages;
ALTER TABLE affected_ranges RENAME TO osv_affected_ranges;
ALTER TABLE severity RENAME TO osv_severity;
ALTER TABLE references_ RENAME TO osv_references;
ALTER TABLE credits RENAME TO osv_credits;

-- ============================================================
-- Step 2: Rename FK columns in osv_affected_packages
--         vulnerability_id → osv_entry_id (will be re-pointed after osv_entries is created)
-- ============================================================

-- We'll handle the FK re-pointing after creating osv_entries.

-- ============================================================
-- Step 3: Create the new unified vulnerabilities master table
--         (rename existing vulnerabilities to osv_entries first)
-- ============================================================

-- Rename old vulnerabilities table to osv_entries
ALTER TABLE vulnerabilities RENAME TO osv_entries;

-- Add a bigint surrogate PK to osv_entries (the old TEXT PK 'id' becomes a natural key)
-- First, we need to drop all FK constraints pointing to old vulnerabilities(id)
ALTER TABLE osv_affected_packages DROP CONSTRAINT affected_packages_vulnerability_id_fkey;
ALTER TABLE osv_severity DROP CONSTRAINT severity_vulnerability_id_fkey;
ALTER TABLE osv_references DROP CONSTRAINT references__vulnerability_id_fkey;
ALTER TABLE osv_credits DROP CONSTRAINT credits_vulnerability_id_fkey;

-- Add surrogate id column to osv_entries
ALTER TABLE osv_entries RENAME COLUMN id TO osv_id;
ALTER TABLE osv_entries ADD COLUMN id BIGINT GENERATED ALWAYS AS IDENTITY;

-- Drop old PK and create new one
ALTER TABLE osv_entries DROP CONSTRAINT vulnerabilities_pkey;
ALTER TABLE osv_entries ADD PRIMARY KEY (id);
ALTER TABLE osv_entries ADD CONSTRAINT osv_entries_osv_id_unique UNIQUE (osv_id);

-- Add vulnerability_id FK column to osv_entries (will reference the new vulnerabilities table)
ALTER TABLE osv_entries ADD COLUMN vulnerability_id TEXT NOT NULL DEFAULT '';

-- ============================================================
-- Step 4: Create the new unified vulnerabilities table
-- ============================================================

CREATE TABLE vulnerabilities (
    id              TEXT        PRIMARY KEY,
    source          TEXT        NOT NULL DEFAULT 'osv',
    summary         TEXT,
    details         TEXT,
    published       TIMESTAMPTZ,
    modified        TIMESTAMPTZ NOT NULL,
    withdrawn       TIMESTAMPTZ
);

-- ============================================================
-- Step 5: Populate vulnerabilities from osv_entries
--         Use osv_id as the vulnerability id (CVE if in aliases, else osv_id)
-- ============================================================

-- For now, use osv_id as the canonical vulnerability id.
-- A future enhancement could resolve CVE aliases to canonical IDs.
INSERT INTO vulnerabilities (id, source, summary, details, published, modified, withdrawn)
SELECT
    osv_id,
    'osv',
    summary,
    details,
    published,
    modified,
    withdrawn
FROM osv_entries
ON CONFLICT (id) DO NOTHING;

-- Point osv_entries.vulnerability_id to the new vulnerabilities table
UPDATE osv_entries SET vulnerability_id = osv_id;

-- Now add the FK constraint
ALTER TABLE osv_entries ALTER COLUMN vulnerability_id DROP DEFAULT;
ALTER TABLE osv_entries ADD CONSTRAINT osv_entries_vulnerability_id_fkey
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE;

-- ============================================================
-- Step 6: Clean up osv_entries - remove columns that moved to vulnerabilities
-- ============================================================

ALTER TABLE osv_entries DROP COLUMN summary;
ALTER TABLE osv_entries DROP COLUMN details;
ALTER TABLE osv_entries DROP COLUMN published;
ALTER TABLE osv_entries DROP COLUMN modified;
ALTER TABLE osv_entries DROP COLUMN withdrawn;

-- Remove aliases/related/upstream arrays (aliases goes to external table, others stay in raw_json)
ALTER TABLE osv_entries DROP COLUMN aliases;
ALTER TABLE osv_entries DROP COLUMN related;
ALTER TABLE osv_entries DROP COLUMN upstream;

-- ============================================================
-- Step 7: Re-point osv_affected_packages FK to osv_entries.id (BIGINT)
-- ============================================================

-- Add new osv_entry_id column
ALTER TABLE osv_affected_packages ADD COLUMN osv_entry_id BIGINT;

-- Populate it from osv_entries
UPDATE osv_affected_packages ap
SET osv_entry_id = oe.id
FROM osv_entries oe
WHERE ap.vulnerability_id = oe.osv_id;

-- Make it NOT NULL and add FK
ALTER TABLE osv_affected_packages ALTER COLUMN osv_entry_id SET NOT NULL;
ALTER TABLE osv_affected_packages ADD CONSTRAINT osv_affected_packages_osv_entry_id_fkey
    FOREIGN KEY (osv_entry_id) REFERENCES osv_entries(id) ON DELETE CASCADE;

-- Drop old vulnerability_id column
ALTER TABLE osv_affected_packages DROP COLUMN vulnerability_id;

-- ============================================================
-- Step 8: Re-point osv_severity FK to osv_entries.id (BIGINT)
-- ============================================================

ALTER TABLE osv_severity ADD COLUMN osv_entry_id BIGINT;

UPDATE osv_severity s
SET osv_entry_id = oe.id
FROM osv_entries oe
WHERE s.vulnerability_id = oe.osv_id;

ALTER TABLE osv_severity ALTER COLUMN osv_entry_id SET NOT NULL;
ALTER TABLE osv_severity ADD CONSTRAINT osv_severity_osv_entry_id_fkey
    FOREIGN KEY (osv_entry_id) REFERENCES osv_entries(id) ON DELETE CASCADE;

-- Update affected_package_id FK to point to osv_affected_packages
ALTER TABLE osv_severity DROP CONSTRAINT IF EXISTS severity_affected_package_id_fkey;
ALTER TABLE osv_severity ADD CONSTRAINT osv_severity_osv_affected_package_id_fkey
    FOREIGN KEY (affected_package_id) REFERENCES osv_affected_packages(id) ON DELETE CASCADE;

ALTER TABLE osv_severity DROP COLUMN vulnerability_id;

-- ============================================================
-- Step 9: Re-point osv_references FK to osv_entries.id (BIGINT)
-- ============================================================

ALTER TABLE osv_references ADD COLUMN osv_entry_id BIGINT;

UPDATE osv_references r
SET osv_entry_id = oe.id
FROM osv_entries oe
WHERE r.vulnerability_id = oe.osv_id;

ALTER TABLE osv_references ALTER COLUMN osv_entry_id SET NOT NULL;
ALTER TABLE osv_references ADD CONSTRAINT osv_references_osv_entry_id_fkey
    FOREIGN KEY (osv_entry_id) REFERENCES osv_entries(id) ON DELETE CASCADE;

ALTER TABLE osv_references DROP COLUMN vulnerability_id;

-- ============================================================
-- Step 10: Re-point osv_credits FK to osv_entries.id (BIGINT)
-- ============================================================

ALTER TABLE osv_credits ADD COLUMN osv_entry_id BIGINT;

UPDATE osv_credits c
SET osv_entry_id = oe.id
FROM osv_entries oe
WHERE c.vulnerability_id = oe.osv_id;

ALTER TABLE osv_credits ALTER COLUMN osv_entry_id SET NOT NULL;
ALTER TABLE osv_credits ADD CONSTRAINT osv_credits_osv_entry_id_fkey
    FOREIGN KEY (osv_entry_id) REFERENCES osv_entries(id) ON DELETE CASCADE;

ALTER TABLE osv_credits DROP COLUMN vulnerability_id;

-- ============================================================
-- Step 11: Create vulnerability_aliases table
-- ============================================================

CREATE TABLE vulnerability_aliases (
    id                  BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    vulnerability_id    TEXT        NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    alias               TEXT        NOT NULL,
    ordering            INT         NOT NULL DEFAULT 0
);

-- Populate from the old aliases array (stored in raw_json)
INSERT INTO vulnerability_aliases (vulnerability_id, alias, ordering)
SELECT
    oe.vulnerability_id,
    alias.value,
    alias.ordinality - 1
FROM osv_entries oe,
     jsonb_array_elements_text(oe.raw_json -> 'aliases') WITH ORDINALITY AS alias(value, ordinality);

-- ============================================================
-- Step 12: Update sync_state to use source-prefixed keys
-- ============================================================

-- Rename ecosystem column to source for clarity
ALTER TABLE sync_state RENAME COLUMN ecosystem TO source;

-- ============================================================
-- Step 13: Recreate indexes for new table structure
-- ============================================================

-- Drop old indexes
DROP INDEX IF EXISTS idx_vulnerabilities_modified;
DROP INDEX IF EXISTS idx_affected_packages_ecosystem_name;
DROP INDEX IF EXISTS idx_affected_packages_vulnerability_id;
DROP INDEX IF EXISTS idx_affected_packages_purl;
DROP INDEX IF EXISTS idx_affected_ranges_affected_package_id;
DROP INDEX IF EXISTS idx_severity_vulnerability_id;
DROP INDEX IF EXISTS idx_references_vulnerability_id;
DROP INDEX IF EXISTS idx_credits_vulnerability_id;
DROP INDEX IF EXISTS idx_vulnerabilities_aliases;

-- New indexes: vulnerabilities (unified)
CREATE INDEX idx_vulnerabilities_modified ON vulnerabilities (modified DESC);
CREATE INDEX idx_vulnerabilities_source ON vulnerabilities (source);

-- New indexes: vulnerability_aliases
CREATE INDEX idx_vulnerability_aliases_vulnerability_id ON vulnerability_aliases (vulnerability_id);
CREATE INDEX idx_vulnerability_aliases_alias ON vulnerability_aliases (alias);
CREATE UNIQUE INDEX idx_vulnerability_aliases_unique ON vulnerability_aliases (vulnerability_id, alias);

-- New indexes: osv_entries
CREATE INDEX idx_osv_entries_vulnerability_id ON osv_entries (vulnerability_id);
CREATE UNIQUE INDEX idx_osv_entries_osv_id ON osv_entries (osv_id);

-- New indexes: osv_affected_packages
CREATE INDEX idx_osv_affected_packages_osv_entry_id ON osv_affected_packages (osv_entry_id);
CREATE INDEX idx_osv_affected_packages_ecosystem_name ON osv_affected_packages (ecosystem, name);
CREATE INDEX idx_osv_affected_packages_purl ON osv_affected_packages (purl) WHERE purl IS NOT NULL;

-- New indexes: osv_affected_ranges
CREATE INDEX idx_osv_affected_ranges_package_id ON osv_affected_ranges (affected_package_id);

-- New indexes: osv_severity
CREATE INDEX idx_osv_severity_entry_id ON osv_severity (osv_entry_id);

-- New indexes: osv_references
CREATE INDEX idx_osv_references_entry_id ON osv_references (osv_entry_id);

-- New indexes: osv_credits
CREATE INDEX idx_osv_credits_entry_id ON osv_credits (osv_entry_id);

COMMIT;
