-- Rollback Migration 000026: Drop translation tables

BEGIN;

DROP TABLE IF EXISTS mitre_credits_translation;
DROP TABLE IF EXISTS mitre_problem_types_translation;
DROP TABLE IF EXISTS nvd_descriptions_translation;
DROP TABLE IF EXISTS kev_entries_translation;
DROP TABLE IF EXISTS vulnerabilities_translation;

COMMIT;
