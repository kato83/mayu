-- Indexes for vulnerability lookup performance

BEGIN;

-- Vulnerabilities: search by modification time (for delta sync)
CREATE INDEX idx_vulnerabilities_modified ON vulnerabilities (modified DESC);

-- Affected packages: search by ecosystem + package name (most common query)
CREATE INDEX idx_affected_packages_ecosystem_name ON affected_packages (ecosystem, name);

-- Affected packages: search by vulnerability
CREATE INDEX idx_affected_packages_vulnerability_id ON affected_packages (vulnerability_id);

-- Affected packages: search by purl
CREATE INDEX idx_affected_packages_purl ON affected_packages (purl) WHERE purl IS NOT NULL;

-- Affected ranges: lookup by package
CREATE INDEX idx_affected_ranges_affected_package_id ON affected_ranges (affected_package_id);

-- Severity: lookup by vulnerability
CREATE INDEX idx_severity_vulnerability_id ON severity (vulnerability_id);

-- References: lookup by vulnerability
CREATE INDEX idx_references_vulnerability_id ON references_ (vulnerability_id);

-- Credits: lookup by vulnerability
CREATE INDEX idx_credits_vulnerability_id ON credits (vulnerability_id);

-- Vulnerabilities: GIN index on aliases array for fast containment queries
CREATE INDEX idx_vulnerabilities_aliases ON vulnerabilities USING GIN (aliases);

COMMIT;
