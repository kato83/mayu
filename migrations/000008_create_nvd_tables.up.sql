-- NVD JSON Feed 2.0 native tables for storing CVE data directly from NVD.
-- Follows the same pattern as osv_* tables: raw_json for reversibility,
-- normalized columns for search/filtering.

BEGIN;

-- Main NVD entry table (1 row per CVE)
CREATE TABLE nvd_entries (
    id                  BIGINT          GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cve_id              TEXT            NOT NULL,
    vulnerability_id    TEXT            NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    source_identifier   TEXT,
    vuln_status         TEXT,
    published           TIMESTAMPTZ     NOT NULL,
    last_modified       TIMESTAMPTZ     NOT NULL,
    raw_json            JSONB           NOT NULL,
    CONSTRAINT nvd_entries_cve_id_unique UNIQUE (cve_id)
);

-- NVD descriptions (multi-language)
CREATE TABLE nvd_descriptions (
    id              BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    nvd_entry_id    BIGINT      NOT NULL REFERENCES nvd_entries(id) ON DELETE CASCADE,
    lang            TEXT        NOT NULL,
    value           TEXT        NOT NULL
);

-- NVD CVSS metrics (supports v2, v3.0, v3.1, v4.0)
CREATE TABLE nvd_metrics (
    id                      BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    nvd_entry_id            BIGINT      NOT NULL REFERENCES nvd_entries(id) ON DELETE CASCADE,
    version                 TEXT        NOT NULL,  -- 'v2', 'v30', 'v31', 'v40'
    source                  TEXT        NOT NULL,
    type                    TEXT        NOT NULL,  -- 'Primary' or 'Secondary'
    cvss_data               JSONB       NOT NULL,  -- Full CVSS vector data
    base_score              FLOAT8,
    base_severity           TEXT,
    exploitability_score    FLOAT8,
    impact_score            FLOAT8
);

-- NVD weaknesses (CWE mappings)
-- Each row represents a single CWE ID. When a weakness entry has multiple
-- description items (e.g. CWE-400 and CWE-770), they are expanded into
-- separate rows during ingestion.
CREATE TABLE nvd_weaknesses (
    id              BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    nvd_entry_id    BIGINT      NOT NULL REFERENCES nvd_entries(id) ON DELETE CASCADE,
    source          TEXT        NOT NULL,
    type            TEXT        NOT NULL,  -- 'Primary' or 'Secondary'
    cwe_id          TEXT        NOT NULL   -- e.g. 'CWE-79'
);

-- NVD configurations (CPE applicability statements)
CREATE TABLE nvd_configurations (
    id              BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    nvd_entry_id    BIGINT      NOT NULL REFERENCES nvd_entries(id) ON DELETE CASCADE,
    operator        TEXT,                  -- 'AND' or 'OR'
    negate          BOOLEAN     NOT NULL DEFAULT false,
    raw_nodes       JSONB       NOT NULL   -- Full node tree for reversibility
);

-- NVD CPE match entries (flattened from configurations for search)
CREATE TABLE nvd_cpe_matches (
    id                      BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    configuration_id        BIGINT      NOT NULL REFERENCES nvd_configurations(id) ON DELETE CASCADE,
    vulnerable              BOOLEAN     NOT NULL,
    criteria                TEXT        NOT NULL,  -- CPE 2.3 URI
    match_criteria_id       TEXT        NOT NULL,  -- UUID
    version_start_including TEXT,
    version_start_excluding TEXT,
    version_end_including   TEXT,
    version_end_excluding   TEXT
);

-- NVD references
CREATE TABLE nvd_references (
    id              BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    nvd_entry_id    BIGINT      NOT NULL REFERENCES nvd_entries(id) ON DELETE CASCADE,
    url             TEXT        NOT NULL,
    source          TEXT,
    tags            TEXT[]
);

-- Indexes for nvd_entries
CREATE INDEX idx_nvd_entries_vulnerability_id ON nvd_entries (vulnerability_id);
CREATE INDEX idx_nvd_entries_last_modified ON nvd_entries (last_modified DESC);
CREATE INDEX idx_nvd_entries_vuln_status ON nvd_entries (vuln_status);

-- Indexes for nvd_descriptions
CREATE INDEX idx_nvd_descriptions_entry_id ON nvd_descriptions (nvd_entry_id);

-- Indexes for nvd_metrics
CREATE INDEX idx_nvd_metrics_entry_id ON nvd_metrics (nvd_entry_id);
CREATE INDEX idx_nvd_metrics_base_score ON nvd_metrics (base_score);

-- Indexes for nvd_weaknesses
CREATE INDEX idx_nvd_weaknesses_entry_id ON nvd_weaknesses (nvd_entry_id);
CREATE INDEX idx_nvd_weaknesses_cwe_id ON nvd_weaknesses (cwe_id);

-- Indexes for nvd_configurations
CREATE INDEX idx_nvd_configurations_entry_id ON nvd_configurations (nvd_entry_id);

-- Indexes for nvd_cpe_matches
CREATE INDEX idx_nvd_cpe_matches_configuration_id ON nvd_cpe_matches (configuration_id);
CREATE INDEX idx_nvd_cpe_matches_criteria ON nvd_cpe_matches (criteria);

-- Indexes for nvd_references
CREATE INDEX idx_nvd_references_entry_id ON nvd_references (nvd_entry_id);

COMMIT;
