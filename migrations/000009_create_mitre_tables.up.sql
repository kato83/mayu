BEGIN;

-- Main MITRE CVE entry table (1 row per CVE Record)
CREATE TABLE mitre_entries (
    id                  BIGINT          GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cve_id              TEXT            NOT NULL,
    vulnerability_id    TEXT            NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    data_version        TEXT            NOT NULL,  -- '5.0', '5.1', '5.2'
    state               TEXT            NOT NULL,  -- 'PUBLISHED', 'REJECTED'
    assigner_org_id     TEXT,
    assigner_short_name TEXT,
    date_reserved       TIMESTAMPTZ,
    date_published      TIMESTAMPTZ,
    date_updated        TIMESTAMPTZ,
    raw_json            JSONB           NOT NULL,
    CONSTRAINT mitre_entries_cve_id_unique UNIQUE (cve_id)
);

-- Container table (CNA + ADP containers)
CREATE TABLE mitre_containers (
    id                  BIGINT          GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    mitre_entry_id      BIGINT          NOT NULL REFERENCES mitre_entries(id) ON DELETE CASCADE,
    container_type      TEXT            NOT NULL,  -- 'cna' or 'adp'
    title               TEXT,                      -- e.g. 'CISA ADP Vulnrichment', 'CVE Program Container'
    provider_org_id     TEXT,
    provider_short_name TEXT,
    date_updated        TIMESTAMPTZ
);

-- Affected products
CREATE TABLE mitre_affected (
    id              BIGINT          GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    container_id    BIGINT          NOT NULL REFERENCES mitre_containers(id) ON DELETE CASCADE,
    vendor          TEXT,
    product         TEXT,
    default_status  TEXT,           -- 'affected', 'unaffected', 'unknown'
    platforms       TEXT[],
    modules         TEXT[],
    package_url     TEXT            -- PURL identifier (CVE Record Format 5.2+)
);

-- Affected version ranges
CREATE TABLE mitre_affected_versions (
    id                  BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    affected_id         BIGINT      NOT NULL REFERENCES mitre_affected(id) ON DELETE CASCADE,
    version             TEXT,
    version_type        TEXT,       -- 'semver', 'custom', 'python', 'rpm', etc.
    status              TEXT        NOT NULL,  -- 'affected', 'unaffected'
    less_than           TEXT,
    less_than_or_equal  TEXT,
    changes             JSONB       -- [{"at": "1.2.3", "status": "unaffected"}]
);

-- CVSS/SSVC metrics
CREATE TABLE mitre_metrics (
    id              BIGINT          GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    container_id    BIGINT          NOT NULL REFERENCES mitre_containers(id) ON DELETE CASCADE,
    format          TEXT            NOT NULL,  -- 'CVSS', 'SSVC', etc.
    cvss_version    TEXT,           -- '2.0', '3.0', '3.1', '4.0'
    base_score      FLOAT8,
    base_severity   TEXT,
    vector_string   TEXT,
    cvss_data       JSONB,          -- Full CVSS/SSVC data object
    scenarios       JSONB           -- Attack scenarios [{"lang": "en", "value": "GENERAL"}]
);

-- Problem types (CWE classifications)
CREATE TABLE mitre_problem_types (
    id              BIGINT          GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    container_id    BIGINT          NOT NULL REFERENCES mitre_containers(id) ON DELETE CASCADE,
    cwe_id          TEXT,           -- 'CWE-79', etc.
    description     TEXT            NOT NULL,
    lang            TEXT            NOT NULL DEFAULT 'en'
);

-- References
CREATE TABLE mitre_references (
    id              BIGINT          GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    container_id    BIGINT          NOT NULL REFERENCES mitre_containers(id) ON DELETE CASCADE,
    url             TEXT            NOT NULL,
    name            TEXT,
    tags            TEXT[]
);

-- Credits
CREATE TABLE mitre_credits (
    id              BIGINT          GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    container_id    BIGINT          NOT NULL REFERENCES mitre_containers(id) ON DELETE CASCADE,
    credit_type     TEXT,           -- 'finder', 'reporter', 'analyst', 'coordinator', etc.
    value           TEXT            NOT NULL,
    lang            TEXT            NOT NULL DEFAULT 'en'
);

-- Indexes for mitre_entries
CREATE INDEX idx_mitre_entries_vulnerability_id ON mitre_entries (vulnerability_id);
CREATE INDEX idx_mitre_entries_date_updated ON mitre_entries (date_updated DESC);
CREATE INDEX idx_mitre_entries_state ON mitre_entries (state);

-- Indexes for mitre_containers
CREATE INDEX idx_mitre_containers_entry_id ON mitre_containers (mitre_entry_id);
CREATE INDEX idx_mitre_containers_type ON mitre_containers (container_type);

-- Indexes for mitre_affected
CREATE INDEX idx_mitre_affected_container_id ON mitre_affected (container_id);
CREATE INDEX idx_mitre_affected_product ON mitre_affected (vendor, product);

-- Indexes for mitre_affected_versions
CREATE INDEX idx_mitre_affected_versions_affected_id ON mitre_affected_versions (affected_id);

-- Indexes for mitre_metrics
CREATE INDEX idx_mitre_metrics_container_id ON mitre_metrics (container_id);
CREATE INDEX idx_mitre_metrics_base_score ON mitre_metrics (base_score);

-- Indexes for mitre_problem_types
CREATE INDEX idx_mitre_problem_types_container_id ON mitre_problem_types (container_id);
CREATE INDEX idx_mitre_problem_types_cwe_id ON mitre_problem_types (cwe_id);

-- Indexes for mitre_references
CREATE INDEX idx_mitre_references_container_id ON mitre_references (container_id);

-- Indexes for mitre_credits
CREATE INDEX idx_mitre_credits_container_id ON mitre_credits (container_id);

COMMIT;
