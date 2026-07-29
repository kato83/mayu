CREATE TABLE sbom_finding_statuses (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    version_id BIGINT NOT NULL REFERENCES sbom_versions(id) ON DELETE CASCADE,
    vuln_id TEXT NOT NULL,
    purl TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'in_triage', 'suppressed', 'false_positive', 'risk_accepted', 'resolved')),
    justification TEXT,
    updated_by BIGINT REFERENCES users(id),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    UNIQUE (version_id, vuln_id, purl)
);

CREATE TABLE sbom_finding_status_log (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    finding_status_id BIGINT NOT NULL REFERENCES sbom_finding_statuses(id) ON DELETE CASCADE,
    old_status TEXT NOT NULL,
    new_status TEXT NOT NULL,
    justification TEXT,
    changed_by BIGINT REFERENCES users(id),
    changed_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_sbom_finding_statuses_version_id ON sbom_finding_statuses (version_id);
CREATE INDEX idx_sbom_finding_statuses_status ON sbom_finding_statuses (status);
CREATE INDEX idx_sbom_finding_statuses_vuln_id ON sbom_finding_statuses (vuln_id);
CREATE INDEX idx_sbom_finding_status_log_finding_status_id ON sbom_finding_status_log (finding_status_id);
