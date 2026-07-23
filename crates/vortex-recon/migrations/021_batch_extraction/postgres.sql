-- Reconciliation — batch (async, ~50%-cheaper) invoice extraction.
--
-- Upload becomes a two-step flow: files land as drafts marked `queued`, and are
-- submitted to the Anthropic Message Batches API in bulk (manually or on a
-- schedule). A background poller completes finished batches. Urgent invoices
-- skip the queue via the synchronous "Extract now" button (ai_extract_state
-- jumps straight to `done`).

-- One submitted provider batch.
CREATE TABLE IF NOT EXISTS recon_ai_batch (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_batch_id VARCHAR(128),          -- Anthropic "msgbatch_…"
    provider          VARCHAR(32)  NOT NULL,
    model             VARCHAR(128) NOT NULL,
    status            VARCHAR(16)  NOT NULL DEFAULT 'submitted', -- submitted|ended|failed
    total             INTEGER NOT NULL DEFAULT 0,
    succeeded         INTEGER NOT NULL DEFAULT 0,
    errored           INTEGER NOT NULL DEFAULT 0,
    error             TEXT,
    created_by        UUID,
    submitted_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at          TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS recon_ai_batch_status_idx ON recon_ai_batch (status);

-- Per-invoice extraction state + which batch it rode in.
-- none = not queued (manual only) · queued = waiting for a batch ·
-- processing = submitted, awaiting results · done = extracted · error = failed
ALTER TABLE recon_batch ADD COLUMN IF NOT EXISTS ai_extract_state VARCHAR(16) NOT NULL DEFAULT 'none';
ALTER TABLE recon_batch ADD COLUMN IF NOT EXISTS ai_batch_id UUID;
CREATE INDEX IF NOT EXISTS recon_batch_ai_state_idx ON recon_batch (ai_extract_state);

-- Optional scheduled auto-submit of the queue (per active provider profile).
ALTER TABLE recon_ai_config ADD COLUMN IF NOT EXISTS batch_auto BOOLEAN NOT NULL DEFAULT false;
