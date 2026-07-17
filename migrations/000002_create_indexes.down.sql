BEGIN;

DROP INDEX IF EXISTS idx_vulnerabilities_aliases;
DROP INDEX IF EXISTS idx_credits_vulnerability_id;
DROP INDEX IF EXISTS idx_references_vulnerability_id;
DROP INDEX IF EXISTS idx_severity_vulnerability_id;
DROP INDEX IF EXISTS idx_affected_ranges_affected_package_id;
DROP INDEX IF EXISTS idx_affected_packages_purl;
DROP INDEX IF EXISTS idx_affected_packages_vulnerability_id;
DROP INDEX IF EXISTS idx_affected_packages_ecosystem_name;
DROP INDEX IF EXISTS idx_vulnerabilities_modified;

COMMIT;
