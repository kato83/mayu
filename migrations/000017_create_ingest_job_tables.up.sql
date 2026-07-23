CREATE TABLE ingest_jobs (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    command_args JSONB NOT NULL,
    source TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'running',
    total_count INT,
    success_count INT,
    failure_count INT,
    error_message TEXT,
    error_stack TEXT
);

CREATE TABLE ingest_failures (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    job_id BIGINT NOT NULL REFERENCES ingest_jobs(id) ON DELETE CASCADE,
    vuln_id TEXT NOT NULL,
    error_type TEXT NOT NULL,
    error_message TEXT,
    error_stack TEXT,
    failed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ingest_jobs_started_at ON ingest_jobs (started_at DESC);
CREATE INDEX idx_ingest_failures_job_id ON ingest_failures (job_id);
