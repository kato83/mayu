CREATE TABLE sbom_projects (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, name)
);

CREATE TABLE sbom_versions (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    project_id BIGINT NOT NULL REFERENCES sbom_projects(id) ON DELETE CASCADE,
    version TEXT NOT NULL,
    environment TEXT,
    sbom_format TEXT NOT NULL,
    raw_sbom JSONB NOT NULL,
    component_count INT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (project_id, version)
);

CREATE TABLE sbom_scan_results (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    version_id BIGINT NOT NULL REFERENCES sbom_versions(id) ON DELETE CASCADE,
    scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    total_packages INT NOT NULL,
    vulnerable_packages INT NOT NULL,
    total_findings INT NOT NULL,
    new_findings INT NOT NULL DEFAULT 0,
    resolved_findings INT NOT NULL DEFAULT 0,
    findings JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'completed' CHECK (status IN ('completed', 'failed')),
    trigger TEXT NOT NULL DEFAULT 'manual' CHECK (trigger IN ('manual', 'ingest', 'api'))
);

CREATE INDEX idx_sbom_projects_user_id ON sbom_projects (user_id);
CREATE INDEX idx_sbom_versions_project_id ON sbom_versions (project_id);
CREATE INDEX idx_sbom_scan_results_version_id ON sbom_scan_results (version_id);
CREATE INDEX idx_sbom_scan_results_scanned_at ON sbom_scan_results (scanned_at);
CREATE INDEX idx_sbom_scan_results_status ON sbom_scan_results (status);
