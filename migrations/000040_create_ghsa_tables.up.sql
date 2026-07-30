-- GHSA (GitHub Security Advisories) dedicated tables.
-- Stores data from the GitHub Repository Security Advisories API
-- as a first-class source, separate from OSV.

-- ghsa_entries: One row per GHSA advisory (primary source record).
CREATE TABLE ghsa_entries (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ghsa_id TEXT NOT NULL UNIQUE,
    vulnerability_id TEXT NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    cve_id TEXT,
    summary TEXT,
    description TEXT,
    severity TEXT,
    state TEXT NOT NULL DEFAULT 'published',
    html_url TEXT,
    published_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ,
    withdrawn_at TIMESTAMPTZ,
    raw_json JSONB NOT NULL
);

CREATE INDEX idx_ghsa_entries_vulnerability_id ON ghsa_entries(vulnerability_id);
CREATE INDEX idx_ghsa_entries_cve_id ON ghsa_entries(cve_id) WHERE cve_id IS NOT NULL;

-- ghsa_vulnerabilities: Affected packages within a GHSA advisory.
CREATE TABLE ghsa_vulnerabilities (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ghsa_entry_id BIGINT NOT NULL REFERENCES ghsa_entries(id) ON DELETE CASCADE,
    ecosystem TEXT NOT NULL,
    package_name TEXT NOT NULL,
    vulnerable_version_range TEXT,
    patched_versions TEXT,
    vulnerable_functions TEXT[]
);

CREATE INDEX idx_ghsa_vulnerabilities_entry_id ON ghsa_vulnerabilities(ghsa_entry_id);
CREATE INDEX idx_ghsa_vulnerabilities_package ON ghsa_vulnerabilities(ecosystem, package_name);

-- ghsa_credits: Credit entries for GHSA advisories.
CREATE TABLE ghsa_credits (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ghsa_entry_id BIGINT NOT NULL REFERENCES ghsa_entries(id) ON DELETE CASCADE,
    login TEXT NOT NULL,
    credit_type TEXT
);

CREATE INDEX idx_ghsa_credits_entry_id ON ghsa_credits(ghsa_entry_id);

-- ghsa_cwes: CWE associations for GHSA advisories.
CREATE TABLE ghsa_cwes (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ghsa_entry_id BIGINT NOT NULL REFERENCES ghsa_entries(id) ON DELETE CASCADE,
    cwe_id TEXT NOT NULL,
    name TEXT
);

CREATE INDEX idx_ghsa_cwes_entry_id ON ghsa_cwes(ghsa_entry_id);

-- ghsa_entries_translation: Mayu-generated translations for GHSA advisories.
CREATE TABLE ghsa_entries_translation (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ghsa_entry_id BIGINT NOT NULL REFERENCES ghsa_entries(id) ON DELETE CASCADE,
    locale TEXT NOT NULL,
    summary TEXT,
    description TEXT,
    translated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (ghsa_entry_id, locale)
);

CREATE INDEX idx_ghsa_entries_translation_entry_locale ON ghsa_entries_translation(ghsa_entry_id, locale);
