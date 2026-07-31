DROP INDEX IF EXISTS idx_triage_paths_ecosystem;
DROP INDEX IF EXISTS idx_triage_paths_priority;
DROP INDEX IF EXISTS idx_triage_paths_impact;
DROP TABLE IF EXISTS triage_paths;

DROP INDEX IF EXISTS idx_triage_spb_server;
DROP INDEX IF EXISTS idx_triage_spb_project;
DROP TABLE IF EXISTS triage_server_profile_bindings;
