-- Migration 000026: Create translation tables for i18n support
-- Adds separate translation tables for text-heavy columns to distinguish
-- upstream-provided translations from mayu-generated translations.

BEGIN;

-- ============================================================
-- 1. vulnerabilities_translation
--    Translations for vulnerability summary and details.
-- ============================================================
CREATE TABLE vulnerabilities_translation (
    id                  BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    vulnerability_id    TEXT        NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    locale              TEXT        NOT NULL,  -- BCP 47: 'ja', 'ko', 'zh-Hans', etc.
    summary             TEXT,
    details             TEXT,
    translated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (vulnerability_id, locale)
);

CREATE INDEX idx_vuln_translation_vuln_id ON vulnerabilities_translation (vulnerability_id);
CREATE INDEX idx_vuln_translation_locale ON vulnerabilities_translation (locale);

-- ============================================================
-- 2. kev_entries_translation
--    Translations for CISA KEV catalog text fields.
-- ============================================================
CREATE TABLE kev_entries_translation (
    id                  BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kev_entry_id        BIGINT      NOT NULL REFERENCES kev_entries(id) ON DELETE CASCADE,
    locale              TEXT        NOT NULL,  -- BCP 47
    vulnerability_name  TEXT,
    short_description   TEXT,
    required_action     TEXT,
    notes               TEXT,
    translated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (kev_entry_id, locale)
);

CREATE INDEX idx_kev_translation_entry_id ON kev_entries_translation (kev_entry_id);
CREATE INDEX idx_kev_translation_locale ON kev_entries_translation (locale);

-- ============================================================
-- 3. nvd_descriptions_translation
--    Translations for NVD description values.
--    Separates mayu-generated translations from upstream NVD-provided
--    multi-language descriptions (which live in nvd_descriptions.lang).
-- ============================================================
CREATE TABLE nvd_descriptions_translation (
    id                  BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    nvd_description_id  BIGINT      NOT NULL REFERENCES nvd_descriptions(id) ON DELETE CASCADE,
    locale              TEXT        NOT NULL,  -- BCP 47
    value               TEXT        NOT NULL,
    translated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (nvd_description_id, locale)
);

CREATE INDEX idx_nvd_desc_translation_desc_id ON nvd_descriptions_translation (nvd_description_id);
CREATE INDEX idx_nvd_desc_translation_locale ON nvd_descriptions_translation (locale);

-- ============================================================
-- 4. mitre_problem_types_translation
--    Translations for MITRE problem type descriptions.
--    Separates mayu-generated translations from upstream MITRE-provided
--    descriptions (which use mitre_problem_types.lang).
-- ============================================================
CREATE TABLE mitre_problem_types_translation (
    id                  BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    problem_type_id     BIGINT      NOT NULL REFERENCES mitre_problem_types(id) ON DELETE CASCADE,
    locale              TEXT        NOT NULL,  -- BCP 47
    description         TEXT        NOT NULL,
    translated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (problem_type_id, locale)
);

CREATE INDEX idx_mitre_pt_translation_pt_id ON mitre_problem_types_translation (problem_type_id);
CREATE INDEX idx_mitre_pt_translation_locale ON mitre_problem_types_translation (locale);

-- ============================================================
-- 5. mitre_credits_translation
--    Translations for MITRE credit values.
--    Separates mayu-generated translations from upstream MITRE-provided
--    values (which use mitre_credits.lang).
-- ============================================================
CREATE TABLE mitre_credits_translation (
    id                  BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    credit_id           BIGINT      NOT NULL REFERENCES mitre_credits(id) ON DELETE CASCADE,
    locale              TEXT        NOT NULL,  -- BCP 47
    value               TEXT        NOT NULL,
    translated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (credit_id, locale)
);

CREATE INDEX idx_mitre_credits_translation_credit_id ON mitre_credits_translation (credit_id);
CREATE INDEX idx_mitre_credits_translation_locale ON mitre_credits_translation (locale);

COMMIT;
