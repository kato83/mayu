-- OSV vulnerability data schema
-- Based on OSV Schema v1.8.0: https://ossf.github.io/osv-schema/

BEGIN;

-- Main vulnerabilities table
CREATE TABLE vulnerabilities (
    id              TEXT        PRIMARY KEY,
    schema_version  TEXT,
    modified        TIMESTAMPTZ NOT NULL,
    published       TIMESTAMPTZ,
    withdrawn       TIMESTAMPTZ,
    aliases         TEXT[],
    related         TEXT[],
    upstream        TEXT[],
    summary         TEXT,
    details         TEXT,
    raw_json        JSONB       NOT NULL,
    database_specific JSONB
);

-- Affected packages
CREATE TABLE affected_packages (
    id                  BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    vulnerability_id    TEXT        NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    ecosystem           TEXT        NOT NULL,
    name                TEXT        NOT NULL,
    purl                TEXT,
    versions            TEXT[],
    ecosystem_specific  JSONB,
    database_specific   JSONB
);

-- Affected version ranges
CREATE TABLE affected_ranges (
    id                  BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    affected_package_id BIGINT      NOT NULL REFERENCES affected_packages(id) ON DELETE CASCADE,
    range_type          TEXT        NOT NULL,
    repo                TEXT,
    events              JSONB       NOT NULL,
    database_specific   JSONB
);

-- Severity scores (top-level or per-affected)
CREATE TABLE severity (
    id                  BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    vulnerability_id    TEXT        NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    affected_package_id BIGINT      REFERENCES affected_packages(id) ON DELETE CASCADE,
    severity_type       TEXT        NOT NULL,
    score               TEXT        NOT NULL,
    source              TEXT
);

-- References
CREATE TABLE references_ (
    id                  BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    vulnerability_id    TEXT        NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    reference_type      TEXT        NOT NULL,
    url                 TEXT        NOT NULL
);

-- Credits
CREATE TABLE credits (
    id                  BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    vulnerability_id    TEXT        NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    name                TEXT        NOT NULL,
    contact             TEXT[],
    credit_type         TEXT
);

-- Sync state for tracking incremental imports per ecosystem
CREATE TABLE sync_state (
    ecosystem           TEXT        PRIMARY KEY,
    last_modified_at    TIMESTAMPTZ NOT NULL,
    last_synced_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    record_count        BIGINT      NOT NULL DEFAULT 0
);

COMMIT;
