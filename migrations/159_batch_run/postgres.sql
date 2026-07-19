-- Generic batch run engine.
--
-- A *run* processes a selected set of *items* through a domain processor in
-- partitioned chunks dispatched over the durable job queue (ir_job). It is
-- industry-neutral: a billing cycle, a mass-mailing, a data import, a
-- recompute job are all "a run over items". The engine owns lifecycle,
-- progress/exception counts, fail-item isolation, and idempotent restart;
-- the vertical owns the per-item processor (registered in code by run_kind).
--
-- Design principles this encodes (see IWK billing scope, but none are billing-
-- specific): fail-account/fail-item isolation (one bad item never halts a run),
-- idempotency by construction (an item is keyed on (run_id, item_key) with a
-- uniqueness constraint, so a restart reprocesses safely without duplication),
-- and trial vs live parity (a `trial` flag rides the run and is handed to the
-- processor, which suppresses side-effects — same compute path, different sink).

CREATE TABLE IF NOT EXISTS batch_run (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Processor key: which registered BatchProcessor handles this run's items,
    -- e.g. 'billing.cycle'. Mirrors ir_job.kind.
    run_kind        VARCHAR(100) NOT NULL,
    -- pending  : created, items may still be loading
    -- running  : chunks dispatched, workers processing
    -- completed: every item reached a terminal state (some may have failed)
    -- failed   : the run itself was aborted (not the same as having failed items)
    -- cancelled: operator-cancelled before completion
    status          VARCHAR(20)  NOT NULL DEFAULT 'pending',
    -- Free-form run parameters (cycle id, account selector, tariff version, …).
    params          JSONB        NOT NULL DEFAULT '{}',
    -- Trial runs use the identical processor; the flag is propagated so the
    -- processor gates GL posting / e-invoice / notification side-effects.
    trial           BOOLEAN      NOT NULL DEFAULT FALSE,
    -- How many items a single chunk (one ir_job) processes.
    chunk_size      INTEGER      NOT NULL DEFAULT 500,
    total_items     INTEGER      NOT NULL DEFAULT 0,
    processed_items INTEGER      NOT NULL DEFAULT 0,  -- reached a terminal state
    succeeded_items INTEGER      NOT NULL DEFAULT 0,
    exception_items INTEGER      NOT NULL DEFAULT 0,  -- failed → exception queue
    -- Tenant the run (and its item processing) belongs to. Null = primary.
    db_name         VARCHAR(100),
    last_error      TEXT,
    created_by      VARCHAR(255),
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_batch_run_kind_status ON batch_run(run_kind, status, created_at DESC);

CREATE TABLE IF NOT EXISTS batch_run_item (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id        UUID NOT NULL REFERENCES batch_run(id) ON DELETE CASCADE,
    -- The idempotency key: the caller's stable identifier for the unit of work
    -- (an account id, a source row id). UNIQUE (run_id, item_key) is what makes
    -- a restart safe — re-adding the same item is a no-op, and a chunk that
    -- re-runs cannot create a second item row.
    item_key      VARCHAR(255) NOT NULL,
    -- Frozen inputs for this item (or a reference to a snapshot). The processor
    -- reads from here, never from live master data mid-run.
    payload       JSONB NOT NULL DEFAULT '{}',
    -- pending | succeeded | failed
    status        VARCHAR(20) NOT NULL DEFAULT 'pending',
    -- On failure: which pipeline stage the processor was in, for triage.
    stage_failed  VARCHAR(100),
    error_detail  TEXT,
    attempts      INTEGER NOT NULL DEFAULT 0,
    -- Terminal result payload the processor chose to record (bill id, etc.).
    result        JSONB,
    processed_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (run_id, item_key)
);

-- Claim/scan index: the chunk dispatcher pulls pending items for a run in id
-- order; the exception queue lists failed items for a run.
CREATE INDEX IF NOT EXISTS idx_batch_run_item_run_status ON batch_run_item(run_id, status, id);
