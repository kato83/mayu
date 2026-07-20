-- Index for ORDER BY published DESC NULLS LAST (vulnerability listing sort)
CREATE INDEX idx_vulnerabilities_published ON vulnerabilities (published DESC NULLS LAST);
