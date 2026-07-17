BEGIN;

DROP TABLE IF EXISTS sync_state;
DROP TABLE IF EXISTS credits;
DROP TABLE IF EXISTS references_;
DROP TABLE IF EXISTS severity;
DROP TABLE IF EXISTS affected_ranges;
DROP TABLE IF EXISTS affected_packages;
DROP TABLE IF EXISTS vulnerabilities;

COMMIT;
