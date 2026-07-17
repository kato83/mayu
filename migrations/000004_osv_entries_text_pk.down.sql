-- Rollback: restore BIGINT surrogate id on osv_entries, revert child FK columns to BIGINT.

BEGIN;

-- ============================================================
-- Step 1: Drop FK constraints
-- ============================================================

ALTER TABLE osv_affected_packages DROP CONSTRAINT osv_affected_packages_osv_entry_id_fkey;
ALTER TABLE osv_severity DROP CONSTRAINT osv_severity_osv_entry_id_fkey;
ALTER TABLE osv_references DROP CONSTRAINT osv_references_osv_entry_id_fkey;
ALTER TABLE osv_credits DROP CONSTRAINT osv_credits_osv_entry_id_fkey;

-- ============================================================
-- Step 2: Restore BIGINT id on osv_entries
-- ============================================================

ALTER TABLE osv_entries DROP CONSTRAINT osv_entries_pkey;
ALTER TABLE osv_entries ADD COLUMN id BIGINT GENERATED ALWAYS AS IDENTITY;
ALTER TABLE osv_entries ADD PRIMARY KEY (id);
ALTER TABLE osv_entries ADD CONSTRAINT osv_entries_osv_id_unique UNIQUE (osv_id);
CREATE UNIQUE INDEX idx_osv_entries_osv_id ON osv_entries (osv_id);

-- ============================================================
-- Step 3: Revert child tables osv_entry_id from TEXT to BIGINT
-- ============================================================

-- osv_affected_packages
ALTER TABLE osv_affected_packages ADD COLUMN osv_entry_id_new BIGINT;
UPDATE osv_affected_packages ap SET osv_entry_id_new = oe.id FROM osv_entries oe WHERE ap.osv_entry_id = oe.osv_id;
ALTER TABLE osv_affected_packages ALTER COLUMN osv_entry_id_new SET NOT NULL;
ALTER TABLE osv_affected_packages DROP COLUMN osv_entry_id;
ALTER TABLE osv_affected_packages RENAME COLUMN osv_entry_id_new TO osv_entry_id;

-- osv_severity
ALTER TABLE osv_severity ADD COLUMN osv_entry_id_new BIGINT;
UPDATE osv_severity s SET osv_entry_id_new = oe.id FROM osv_entries oe WHERE s.osv_entry_id = oe.osv_id;
ALTER TABLE osv_severity ALTER COLUMN osv_entry_id_new SET NOT NULL;
ALTER TABLE osv_severity DROP COLUMN osv_entry_id;
ALTER TABLE osv_severity RENAME COLUMN osv_entry_id_new TO osv_entry_id;

-- osv_references
ALTER TABLE osv_references ADD COLUMN osv_entry_id_new BIGINT;
UPDATE osv_references r SET osv_entry_id_new = oe.id FROM osv_entries oe WHERE r.osv_entry_id = oe.osv_id;
ALTER TABLE osv_references ALTER COLUMN osv_entry_id_new SET NOT NULL;
ALTER TABLE osv_references DROP COLUMN osv_entry_id;
ALTER TABLE osv_references RENAME COLUMN osv_entry_id_new TO osv_entry_id;

-- osv_credits
ALTER TABLE osv_credits ADD COLUMN osv_entry_id_new BIGINT;
UPDATE osv_credits c SET osv_entry_id_new = oe.id FROM osv_entries oe WHERE c.osv_entry_id = oe.osv_id;
ALTER TABLE osv_credits ALTER COLUMN osv_entry_id_new SET NOT NULL;
ALTER TABLE osv_credits DROP COLUMN osv_entry_id;
ALTER TABLE osv_credits RENAME COLUMN osv_entry_id_new TO osv_entry_id;

-- ============================================================
-- Step 4: Restore FK constraints referencing osv_entries(id)
-- ============================================================

ALTER TABLE osv_affected_packages ADD CONSTRAINT osv_affected_packages_osv_entry_id_fkey
    FOREIGN KEY (osv_entry_id) REFERENCES osv_entries(id) ON DELETE CASCADE;

ALTER TABLE osv_severity ADD CONSTRAINT osv_severity_osv_entry_id_fkey
    FOREIGN KEY (osv_entry_id) REFERENCES osv_entries(id) ON DELETE CASCADE;

ALTER TABLE osv_references ADD CONSTRAINT osv_references_osv_entry_id_fkey
    FOREIGN KEY (osv_entry_id) REFERENCES osv_entries(id) ON DELETE CASCADE;

ALTER TABLE osv_credits ADD CONSTRAINT osv_credits_osv_entry_id_fkey
    FOREIGN KEY (osv_entry_id) REFERENCES osv_entries(id) ON DELETE CASCADE;

-- ============================================================
-- Step 5: Recreate indexes
-- ============================================================

DROP INDEX IF EXISTS idx_osv_affected_packages_osv_entry_id;
DROP INDEX IF EXISTS idx_osv_severity_osv_entry_id;
DROP INDEX IF EXISTS idx_osv_references_osv_entry_id;
DROP INDEX IF EXISTS idx_osv_credits_osv_entry_id;

CREATE INDEX idx_osv_affected_packages_osv_entry_id ON osv_affected_packages (osv_entry_id);
CREATE INDEX idx_osv_severity_entry_id ON osv_severity (osv_entry_id);
CREATE INDEX idx_osv_references_entry_id ON osv_references (osv_entry_id);
CREATE INDEX idx_osv_credits_entry_id ON osv_credits (osv_entry_id);

COMMIT;
