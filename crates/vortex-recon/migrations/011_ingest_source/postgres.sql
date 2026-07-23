-- Reconciliation — remote invoice pickup (SFTP / FTP / FTPS auto-ingest).
--
-- Each source is a remote drop folder we poll on a schedule (and on demand).
-- New matching files are downloaded, stored via the FileStore, turned into a
-- draft recon_batch (same as a manual upload), then MOVED to a "processed"
-- subfolder on the remote so they are never re-imported. Secrets are stored
-- AES-256-GCM encrypted (VORTEX_SECRET_KEY) — never in the clear.

CREATE TABLE IF NOT EXISTS recon_ingest_source (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name              VARCHAR(120) NOT NULL DEFAULT 'Vendor drop',
    protocol          VARCHAR(8)  NOT NULL DEFAULT 'sftp',   -- sftp | ftp | ftps
    host              VARCHAR(255) NOT NULL,
    port              INTEGER NOT NULL DEFAULT 22,
    username          VARCHAR(190),
    password_enc      BYTEA,          -- AES-256-GCM
    private_key_enc   BYTEA,          -- AES-256-GCM (SFTP key auth, optional)
    key_hint          VARCHAR(16),    -- last-4 of the secret, for display
    remote_dir        VARCHAR(512) NOT NULL DEFAULT '/',
    processed_dir     VARCHAR(512),   -- destination for imported files (blank = <remote_dir>/processed)
    file_pattern      VARCHAR(120) NOT NULL DEFAULT '*.pdf',
    poll_interval_min INTEGER NOT NULL DEFAULT 15,
    active            BOOLEAN NOT NULL DEFAULT true,
    -- last poll outcome, shown on the config screen
    last_run_at       TIMESTAMPTZ,
    last_status       VARCHAR(16),    -- ok | error | running
    last_message      TEXT,
    last_count        INTEGER,
    updated_by        UUID REFERENCES users(id),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_recon_ingest_source_active ON recon_ingest_source(active);

-- One row per poll (manual or scheduled) — an audit trail of pickups.
CREATE TABLE IF NOT EXISTS recon_ingest_run (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id      UUID REFERENCES recon_ingest_source(id) ON DELETE CASCADE,
    started_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at    TIMESTAMPTZ,
    status         VARCHAR(16),        -- ok | error
    files_imported INTEGER NOT NULL DEFAULT 0,
    message        TEXT,
    trigger        VARCHAR(12)         -- manual | schedule
);
CREATE INDEX IF NOT EXISTS idx_recon_ingest_run_source ON recon_ingest_run(source_id, started_at DESC);
