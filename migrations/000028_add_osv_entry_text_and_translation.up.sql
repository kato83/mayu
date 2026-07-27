-- Migration 000028: Add summary/details columns back to osv_entries
-- and create osv_entries_translation table for per-entry translations.
--
-- These columns were removed in migration 000003 because the first OSV entry's
-- text was promoted to vulnerabilities.summary/details. However, when multiple
-- OSV entries share one CVE, each entry has its own details that needs to be
-- stored and translated independently.

BEGIN;

-- ============================================================
-- 1. Add summary and details columns to osv_entries
-- ============================================================
ALTER TABLE osv_entries ADD COLUMN summary TEXT;
ALTER TABLE osv_entries ADD COLUMN details TEXT;

-- Backfill from raw_json for existing entries.
-- PostgreSQL can extract from JSONB; raw_json is JSONB.
UPDATE osv_entries
SET summary = raw_json->>'summary',
    details = raw_json->>'details'
WHERE raw_json IS NOT NULL;

-- ============================================================
-- 2. Create osv_entries_translation table
--    Translations for OSV entry summary and details fields.
-- ============================================================
CREATE TABLE osv_entries_translation (
    id              BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    osv_entry_id    TEXT        NOT NULL REFERENCES osv_entries(osv_id) ON DELETE CASCADE,
    locale          TEXT        NOT NULL,  -- BCP 47: 'ja', 'ko', 'zh-Hans', etc.
    summary         TEXT,
    details         TEXT,
    translated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (osv_entry_id, locale)
);

CREATE INDEX idx_osv_entry_translation_entry_id ON osv_entries_translation (osv_entry_id);
CREATE INDEX idx_osv_entry_translation_locale ON osv_entries_translation (locale);

COMMIT;
