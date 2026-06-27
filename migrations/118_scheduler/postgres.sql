-- ============================================================================
-- Migration 118: Platform Scheduler
-- ============================================================================
--
-- Creates `scheduled_actions`, the storage for plugin-contributed
-- background jobs. The `vortex_framework::scheduler::Scheduler`
-- supervisor polls this table, claims due rows with
-- `FOR UPDATE SKIP LOCKED`, dispatches to registered handlers, and
-- records results.
--
-- Row lifecycle:
--
--   1. Plugin declares an action in code via Plugin::scheduled_actions().
--   2. Host starts, Scheduler::sync_definitions() upserts the row here.
--      On first insert: next_call = NOW() (runs immediately at next tick).
--      On subsequent startups: only name and interval are refreshed —
--      runtime state (active, next_call, counters) is preserved.
--   3. Supervisor polls, claims the row, runs the handler, records result.
--   4. An operator can SET active = FALSE or bump next_call directly in
--      SQL to disable / defer a job without redeploying.

CREATE TABLE IF NOT EXISTS scheduled_actions (
    -- Stable plugin-assigned code, e.g. "crm.lead_score_recompute".
    -- Must be globally unique across all plugins; the plugin's technical
    -- name is the conventional prefix.
    code              VARCHAR(100) PRIMARY KEY,

    -- Human-readable display name, refreshed from code on startup sync.
    name              VARCHAR(255) NOT NULL,

    -- Schedule family. Today only 'every' (fixed interval) is used;
    -- reserved for future 'cron' when cron-expression parsing is added.
    schedule_kind     VARCHAR(16)  NOT NULL DEFAULT 'every',

    -- Interval in seconds for schedule_kind = 'every'.
    interval_seconds  BIGINT       NOT NULL,

    -- Reserved: cron expression for schedule_kind = 'cron'. NULL until
    -- cron support lands.
    cron_expr         VARCHAR(100),

    -- Admin-togglable enable flag. Set from definition on first insert,
    -- then owned by the DB — subsequent startup syncs do not overwrite
    -- this so operators can disable a job without a code change.
    active            BOOLEAN      NOT NULL DEFAULT TRUE,

    -- When this action should next run. The supervisor claims the row
    -- when next_call <= NOW() AND active. Advanced atomically inside the
    -- claim transaction.
    next_call         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    -- Observability state, updated after every run.
    last_call         TIMESTAMPTZ,           -- when the last dispatch happened
    last_success      TIMESTAMPTZ,           -- when the last successful run finished
    last_error        TEXT,                  -- error message from the last failed run (NULL on success)
    last_duration_ms  BIGINT,                -- how long the last run took, ms
    run_count         BIGINT       NOT NULL DEFAULT 0,
    error_count       BIGINT       NOT NULL DEFAULT 0,

    created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Partial index on active rows ordered by next_call — this is the exact
-- shape of the supervisor's claim query, so the planner can satisfy it
-- with an index-only scan and the LIMIT 1 / SKIP LOCKED path stays cheap
-- even with thousands of active jobs.
CREATE INDEX IF NOT EXISTS idx_scheduled_actions_due
    ON scheduled_actions(next_call)
    WHERE active;

COMMENT ON TABLE scheduled_actions IS
    'Platform scheduler: plugin-contributed background jobs. Definitions sourced from Plugin::scheduled_actions() in Rust code; runtime state (next_call, counters, errors, admin-toggled active) owned by this table. Distributed-safe via FOR UPDATE SKIP LOCKED.';
COMMENT ON COLUMN scheduled_actions.code IS
    'Globally-unique action code, conventionally prefixed with the plugin technical name, e.g. "crm.lead_score_recompute".';
COMMENT ON COLUMN scheduled_actions.schedule_kind IS
    'Schedule family: "every" (fixed interval — uses interval_seconds) or future "cron" (uses cron_expr).';
COMMENT ON COLUMN scheduled_actions.active IS
    'Admin-togglable enable flag. Definition sync does NOT overwrite this after first insert.';
COMMENT ON COLUMN scheduled_actions.next_call IS
    'When this action is next due. Advanced by the supervisor inside the claim transaction.';
