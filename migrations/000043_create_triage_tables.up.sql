-- Triage server profile bindings: associates a triage profile with a specific server/asset.
CREATE TABLE triage_server_profile_bindings (
    id BIGSERIAL PRIMARY KEY,
    project_id BIGINT NOT NULL,
    server_label VARCHAR(255) NOT NULL,
    environment VARCHAR(100),
    profile_name VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(project_id, server_label)
);

CREATE INDEX idx_triage_spb_project ON triage_server_profile_bindings(project_id);
CREATE INDEX idx_triage_spb_server ON triage_server_profile_bindings(server_label);

-- Triage paths: cached remediation grouping results.
CREATE TABLE triage_paths (
    id VARCHAR(64) PRIMARY KEY,
    package_purl TEXT NOT NULL,
    current_version VARCHAR(255) NOT NULL,
    target_version VARCHAR(255) NOT NULL,
    ecosystem VARCHAR(100) NOT NULL,
    impact_score DOUBLE PRECISION NOT NULL,
    max_priority_level VARCHAR(20) NOT NULL,
    total_vuln_count INT NOT NULL,
    total_server_count INT NOT NULL,
    resolved_vulns JSONB NOT NULL,
    affected_servers JSONB NOT NULL,
    computed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_triage_paths_impact ON triage_paths(impact_score DESC);
CREATE INDEX idx_triage_paths_priority ON triage_paths(max_priority_level);
CREATE INDEX idx_triage_paths_ecosystem ON triage_paths(ecosystem);
