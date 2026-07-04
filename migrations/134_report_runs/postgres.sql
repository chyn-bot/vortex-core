-- 134_report_runs — bookkeeping for the async report pipeline.
--
-- One row per background report generation: queued by a user, claimed
-- and rendered by the job worker (ir_job kind 'report.render'), the
-- artifact stored in the FileStore under reports/<run_id>.<ext>.
-- The "Generated Reports" inbox lists these rows; a retention sweep
-- deletes old rows and their blobs.

CREATE TABLE IF NOT EXISTS report_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id UUID NOT NULL,
    report_code VARCHAR(100) NOT NULL,
    report_name VARCHAR(255) NOT NULL,
    format VARCHAR(10) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'queued',  -- queued | running | done | failed
    error TEXT,
    -- FileStore key of the finished artifact (tenant-namespaced)
    store_key VARCHAR(512),
    file_size BIGINT,
    mime VARCHAR(100),
    requested_by UUID NOT NULL REFERENCES users(id),
    requested_by_name VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_report_runs_user
    ON report_runs(requested_by, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_report_runs_status
    ON report_runs(status);
