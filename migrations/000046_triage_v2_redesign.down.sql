-- Recreate old table
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

-- Migrate data back
INSERT INTO triage_server_profile_bindings (project_id, server_label, environment, profile_name, description, created_at, updated_at)
SELECT project_id, environment, environment, profile_name, description, created_at, updated_at
FROM project_environment_profiles;

-- Drop new table
DROP TABLE IF EXISTS project_environment_profiles;

-- Remove default_profile from sbom_projects
ALTER TABLE sbom_projects DROP COLUMN IF EXISTS default_profile;

-- Remove columns from triage_profiles
ALTER TABLE triage_profiles DROP CONSTRAINT IF EXISTS chk_triage_profiles_act_floor;
ALTER TABLE triage_profiles DROP CONSTRAINT IF EXISTS chk_triage_profiles_score_weight;
ALTER TABLE triage_profiles DROP COLUMN IF EXISTS act_floor;
ALTER TABLE triage_profiles DROP COLUMN IF EXISTS score_weight;
