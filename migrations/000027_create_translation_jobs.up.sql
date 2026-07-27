-- translation_jobs records background translation job executions.
-- Modeled after ingest_jobs: the API returns 202 Accepted with a job_id,
-- then the LLM translation runs in the background.
CREATE TABLE translation_jobs (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    vulnerability_id    TEXT        NOT NULL,
    locale              TEXT        NOT NULL,
    started_at          TIMESTAMPTZ NOT NULL,
    finished_at         TIMESTAMPTZ,
    status              TEXT        NOT NULL DEFAULT 'running',   -- running, success, failed
    fields_translated   INT,
    error_message       TEXT
);

CREATE INDEX idx_translation_jobs_started_at ON translation_jobs (started_at DESC);
CREATE INDEX idx_translation_jobs_vuln_locale ON translation_jobs (vulnerability_id, locale);
