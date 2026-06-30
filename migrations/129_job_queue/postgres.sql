-- Durable background-job queue. Unlike the scheduler (recurring, time-driven),
-- this is for one-off async work that must survive restarts: enqueue a row,
-- a worker claims it (FOR UPDATE SKIP LOCKED), runs the registered handler for
-- its `kind`, and on failure retries with exponential backoff until
-- `max_attempts`, then dead-letters. First consumer: outbound email.
-- The queue is central (lives in the primary DB the worker polls); a job
-- carries `db_name` so its handler can resolve the right tenant pool.
CREATE TABLE IF NOT EXISTS ir_job (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    queue         VARCHAR(50)  NOT NULL DEFAULT 'default',
    kind          VARCHAR(100) NOT NULL,                 -- handler key, e.g. 'mail.send'
    payload       JSONB        NOT NULL DEFAULT '{}',
    status        VARCHAR(20)  NOT NULL DEFAULT 'pending', -- pending|running|succeeded|dead|cancelled
    priority      INTEGER      NOT NULL DEFAULT 0,        -- higher runs first
    attempts      INTEGER      NOT NULL DEFAULT 0,
    max_attempts  INTEGER      NOT NULL DEFAULT 5,
    run_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),    -- earliest run time (backoff)
    locked_at     TIMESTAMPTZ,
    locked_by     VARCHAR(100),
    last_error    TEXT,
    db_name       VARCHAR(100),                          -- tenant the handler runs against
    resource_type VARCHAR(100),                          -- optional trace target
    resource_id   VARCHAR(255),
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    finished_at   TIMESTAMPTZ
);
-- Claim index: only pending rows, ordered the way the worker claims them.
CREATE INDEX IF NOT EXISTS idx_ir_job_claim ON ir_job(run_at, priority DESC) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_ir_job_status ON ir_job(status, created_at DESC);
