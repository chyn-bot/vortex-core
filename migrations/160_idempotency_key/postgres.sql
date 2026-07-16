-- Generic idempotency-key guard.
--
-- A durable "have I already done this?" ledger for any operation that must run
-- at most once despite retries, restarts, or at-least-once delivery: applying a
-- received webhook, emitting a one-off side-effect from a job, posting a bill
-- downstream. The caller picks a `scope` (the operation class, e.g.
-- 'webhook.inbound' or 'bill.finalize') and a `key` (the stable identifier of
-- the specific occurrence). The first claim of a (scope, key) wins; every later
-- claim is told it is a duplicate.
--
-- This is the general form of the same guarantee the batch engine gives its
-- items via UNIQUE(run_id, item_key): here it is reusable outside a run.
CREATE TABLE IF NOT EXISTS idempotency_key (
    scope      VARCHAR(100) NOT NULL,
    key        VARCHAR(255) NOT NULL,
    -- Optional stored outcome of the first successful run, so a duplicate can
    -- return the original result instead of recomputing (e.g. the id created).
    result     JSONB,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    PRIMARY KEY (scope, key)
);
