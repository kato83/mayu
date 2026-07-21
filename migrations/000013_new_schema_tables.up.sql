-- Migration 000013: New schema tables
-- Adds vulnerability_summary, product_identifiers, purl_cpe_mapping, alias_sources.
-- Refactors vulnerability_aliases (removes ordering/source_osv_id, adds junction table).
-- Drops vulnerabilities.source column.

BEGIN;

-- ============================================================
-- 1. Drop vulnerabilities.source column
-- ============================================================
ALTER TABLE vulnerabilities DROP COLUMN IF EXISTS source;

-- ============================================================
-- 2. Refactor vulnerability_aliases
--    - Remove ordering column
--    - Remove source_osv_id column (moved to alias_sources junction table)
--    - Change UNIQUE constraint to (vulnerability_id, alias)
-- ============================================================

-- Drop existing unique index that includes source_osv_id
DROP INDEX IF EXISTS idx_vulnerability_aliases_unique;
DROP INDEX IF EXISTS idx_vulnerability_aliases_source_osv_id;

-- Drop columns
ALTER TABLE vulnerability_aliases DROP COLUMN IF EXISTS ordering;
ALTER TABLE vulnerability_aliases DROP COLUMN IF EXISTS source_osv_id;

-- Add new simpler unique constraint
CREATE UNIQUE INDEX idx_vulnerability_aliases_unique
    ON vulnerability_aliases (vulnerability_id, alias);

-- ============================================================
-- 3. Create alias_sources junction table
--    Tracks which OSV entry contributed each alias.
-- ============================================================
CREATE TABLE alias_sources (
    id          BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    alias_id    BIGINT      NOT NULL REFERENCES vulnerability_aliases(id) ON DELETE CASCADE,
    osv_id      TEXT        NOT NULL REFERENCES osv_entries(osv_id) ON DELETE CASCADE,
    UNIQUE (alias_id, osv_id)
);

CREATE INDEX idx_alias_sources_alias_id ON alias_sources (alias_id);
CREATE INDEX idx_alias_sources_osv_id ON alias_sources (osv_id);

-- ============================================================
-- 4. Create vulnerability_summary table
--    Pre-computed derived data for list views and filtering.
-- ============================================================
CREATE TABLE vulnerability_summary (
    vulnerability_id    TEXT        PRIMARY KEY REFERENCES vulnerabilities(id) ON DELETE CASCADE,

    -- Normalized severity (5-level: 5=CRITICAL, 4=HIGH, 3=MEDIUM, 2=LOW, 1=NONE)
    severity_worst      SMALLINT,
    severity_best       SMALLINT,

    -- Per-source score details (JSONB array)
    scores_detail       JSONB,

    -- EPSS latest
    epss_score          FLOAT8,
    epss_percentile     FLOAT8,

    -- Flags
    in_kev              BOOLEAN     NOT NULL DEFAULT false,
    lev_score           FLOAT8,

    -- Search aggregates
    ecosystem_list      TEXT[],
    cwe_list            TEXT[],

    -- Tracking
    computed_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_vs_severity_worst ON vulnerability_summary (severity_worst DESC NULLS LAST);
CREATE INDEX idx_vs_severity_range ON vulnerability_summary (severity_best, severity_worst);
CREATE INDEX idx_vs_epss ON vulnerability_summary (epss_score DESC NULLS LAST);
CREATE INDEX idx_vs_in_kev ON vulnerability_summary (in_kev) WHERE in_kev = true;
CREATE INDEX idx_vs_ecosystems ON vulnerability_summary USING GIN (ecosystem_list);
CREATE INDEX idx_vs_cwes ON vulnerability_summary USING GIN (cwe_list);
CREATE INDEX idx_vs_scores_detail ON vulnerability_summary USING GIN (scores_detail jsonb_path_ops);

-- ============================================================
-- 5. Create product_identifiers table
--    Unified package/product search table with decomposed CPE/purl.
-- ============================================================
CREATE TABLE product_identifiers (
    id                      BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    vulnerability_id        TEXT        NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    source                  TEXT        NOT NULL,

    -- Purl fields (decomposed)
    purl_type               TEXT,
    purl_namespace          TEXT,
    purl_name               TEXT,
    purl_version            TEXT,
    purl_qualifiers         TEXT,
    purl_subpath            TEXT,

    -- CPE fields (decomposed from cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other)
    cpe_part                TEXT,
    cpe_vendor              TEXT,
    cpe_product             TEXT,
    cpe_version             TEXT,
    cpe_update              TEXT,
    cpe_edition             TEXT,
    cpe_language            TEXT,
    cpe_sw_edition          TEXT,
    cpe_target_sw           TEXT,
    cpe_target_hw           TEXT,
    cpe_other               TEXT,

    -- Generic fields
    ecosystem               TEXT,
    name                    TEXT,
    vendor                  TEXT,
    product                 TEXT,
    version_constraint      JSONB
);

CREATE INDEX idx_pi_vuln_id ON product_identifiers (vulnerability_id);
CREATE INDEX idx_pi_source ON product_identifiers (vulnerability_id, source);
CREATE INDEX idx_pi_purl_type_ns_name ON product_identifiers (purl_type, purl_namespace, purl_name) WHERE purl_type IS NOT NULL;
CREATE INDEX idx_pi_purl_name ON product_identifiers (purl_name) WHERE purl_name IS NOT NULL;
CREATE INDEX idx_pi_cpe_vendor_product ON product_identifiers (cpe_vendor, cpe_product) WHERE cpe_vendor IS NOT NULL;
CREATE INDEX idx_pi_ecosystem_name ON product_identifiers (ecosystem, name) WHERE ecosystem IS NOT NULL;
CREATE INDEX idx_pi_vendor_product ON product_identifiers (vendor, product) WHERE vendor IS NOT NULL;

-- ============================================================
-- 6. Create purl_cpe_mapping table
--    Bidirectional mapping between purl and CPE identifiers.
-- ============================================================
CREATE TABLE purl_cpe_mapping (
    id              BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    purl_type       TEXT        NOT NULL,
    purl_name       TEXT        NOT NULL,
    cpe_vendor      TEXT        NOT NULL,
    cpe_product     TEXT        NOT NULL,
    confidence      FLOAT8      NOT NULL DEFAULT 1.0,
    source          TEXT,
    UNIQUE (purl_type, purl_name, cpe_vendor, cpe_product)
);

CREATE INDEX idx_pcm_purl ON purl_cpe_mapping (purl_type, purl_name);
CREATE INDEX idx_pcm_cpe ON purl_cpe_mapping (cpe_vendor, cpe_product);

-- ============================================================
-- 7. Add decomposed CPE fields to nvd_cpe_matches
--    Enables direct field-level queries without parsing the criteria URI.
-- ============================================================
ALTER TABLE nvd_cpe_matches ADD COLUMN cpe_part TEXT;
ALTER TABLE nvd_cpe_matches ADD COLUMN cpe_vendor TEXT;
ALTER TABLE nvd_cpe_matches ADD COLUMN cpe_product TEXT;
ALTER TABLE nvd_cpe_matches ADD COLUMN cpe_version TEXT;
ALTER TABLE nvd_cpe_matches ADD COLUMN cpe_update TEXT;
ALTER TABLE nvd_cpe_matches ADD COLUMN cpe_edition TEXT;
ALTER TABLE nvd_cpe_matches ADD COLUMN cpe_language TEXT;
ALTER TABLE nvd_cpe_matches ADD COLUMN cpe_sw_edition TEXT;
ALTER TABLE nvd_cpe_matches ADD COLUMN cpe_target_sw TEXT;
ALTER TABLE nvd_cpe_matches ADD COLUMN cpe_target_hw TEXT;
ALTER TABLE nvd_cpe_matches ADD COLUMN cpe_other TEXT;

CREATE INDEX idx_nvdcpe_vendor_product ON nvd_cpe_matches (cpe_vendor, cpe_product) WHERE cpe_vendor IS NOT NULL;
CREATE INDEX idx_nvdcpe_product ON nvd_cpe_matches (cpe_product) WHERE cpe_product IS NOT NULL;

-- ============================================================
-- 8. Backfill alias_sources from existing vulnerability_aliases
--    Uses osv_entries to establish the link.
-- ============================================================
INSERT INTO alias_sources (alias_id, osv_id)
SELECT va.id, oe.osv_id
FROM vulnerability_aliases va
JOIN osv_entries oe ON oe.vulnerability_id = va.vulnerability_id
ON CONFLICT DO NOTHING;

COMMIT;
