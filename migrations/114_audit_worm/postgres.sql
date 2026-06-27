-- Migration 114: WORM Audit Ledger
--
-- Turns the pre-existing `audit_log` table into a cryptographically-chained,
-- append-only, per-tenant WORM ledger for regulated-industry audit compliance.
--
-- Two enforcement layers:
--   1. BEFORE UPDATE / DELETE / TRUNCATE triggers that RAISE EXCEPTION —
--      catches any direct SQL attempt and any application bug.
--   2. A `vortex_runtime` DB role with UPDATE/DELETE/TRUNCATE revoked on
--      `audit_log`. The application must connect as this role at runtime.
--      Migrations and admin tooling continue to use the owning role.
--
-- The PgAuditStorage Rust implementation (crates/vortex-security/src/audit/pg.rs)
-- writes through `audit_chain_head` under `FOR UPDATE` and stores the JCS
-- canonical payload in `canonical_payload` for deterministic verification.
--
-- This migration is NOT reversible: the chain columns cannot be dropped
-- once populated without destroying compliance evidence.

-- ============================================================================
-- 1. Chain + signing + dual-clock columns on audit_log
-- ============================================================================
ALTER TABLE audit_log
    ADD COLUMN IF NOT EXISTS prev_hash         BYTEA,
    ADD COLUMN IF NOT EXISTS entry_hash        BYTEA,
    ADD COLUMN IF NOT EXISTS chain_position    BIGINT,
    ADD COLUMN IF NOT EXISTS signature         BYTEA,
    ADD COLUMN IF NOT EXISTS signing_key_id    TEXT,
    ADD COLUMN IF NOT EXISTS canonical_payload TEXT,
    ADD COLUMN IF NOT EXISTS db_timestamp      TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Self-describing pre-chain / genesis / linked-chain shape. Three valid
-- states: (a) legacy pre-chain rows have all chain fields NULL, (b) the
-- synthetic genesis row per tenant has chain_position = 0 and no prev_hash,
-- (c) normal chained rows have both prev_hash and entry_hash set and a
-- positive chain_position. Any other combination is a corrupt row.
ALTER TABLE audit_log
    DROP CONSTRAINT IF EXISTS chk_audit_chain_shape;

ALTER TABLE audit_log
    ADD CONSTRAINT chk_audit_chain_shape
    CHECK (
        (chain_position IS NULL
            AND entry_hash IS NULL
            AND canonical_payload IS NULL)
        OR
        (chain_position = 0
            AND prev_hash IS NULL
            AND entry_hash IS NOT NULL
            AND canonical_payload IS NOT NULL)
        OR
        (chain_position > 0
            AND prev_hash IS NOT NULL
            AND entry_hash IS NOT NULL
            AND canonical_payload IS NOT NULL)
    );

-- One chain position per tenant. Partial index so legacy pre-chain rows
-- (chain_position IS NULL) do not participate.
CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_chain_per_tenant
    ON audit_log (company_id, chain_position)
    WHERE chain_position IS NOT NULL;

-- Fast lookup for chain verification walks.
CREATE INDEX IF NOT EXISTS idx_audit_chain_walk
    ON audit_log (company_id, chain_position)
    WHERE chain_position IS NOT NULL;

-- ============================================================================
-- 2. Per-tenant chain head
-- ============================================================================
CREATE TABLE IF NOT EXISTS audit_chain_head (
    company_id     UUID PRIMARY KEY REFERENCES companies(id),
    last_hash      BYTEA NOT NULL,
    last_position  BIGINT NOT NULL,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE audit_chain_head IS
    'Per-tenant head of the WORM audit hash chain. PgAuditStorage takes FOR UPDATE on the relevant row before appending a new audit entry.';

-- ============================================================================
-- 3. Ed25519 signing keys with validity windows for rotation
-- ============================================================================
CREATE TABLE IF NOT EXISTS audit_signing_keys (
    key_id      TEXT PRIMARY KEY,
    public_key  BYTEA NOT NULL,
    algorithm   TEXT NOT NULL DEFAULT 'ed25519',
    valid_from  TIMESTAMPTZ NOT NULL,
    valid_to    TIMESTAMPTZ,
    revoked_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE audit_signing_keys IS
    'Public keys used to verify Ed25519 signatures on audit_log entries. Entries signed with a key remain valid if entry.timestamp < key.revoked_at. Entries after revoked_at citing a revoked key are integrity violations.';

-- ============================================================================
-- 4. Append-only trigger — catches any UPDATE, DELETE, or TRUNCATE attempt
-- ============================================================================
CREATE OR REPLACE FUNCTION audit_log_block_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only (WORM); TG_OP=% blocked by WORM policy', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_log_no_update ON audit_log;
CREATE TRIGGER trg_audit_log_no_update
    BEFORE UPDATE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_block_mutation();

DROP TRIGGER IF EXISTS trg_audit_log_no_delete ON audit_log;
CREATE TRIGGER trg_audit_log_no_delete
    BEFORE DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_block_mutation();

DROP TRIGGER IF EXISTS trg_audit_log_no_truncate ON audit_log;
CREATE TRIGGER trg_audit_log_no_truncate
    BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_block_mutation();

-- The head table and signing key table are NOT append-only by design —
-- the head advances with every write and keys rotate over time. They are
-- protected solely by the runtime role's lack of DELETE privilege (see §5).

-- ============================================================================
-- 5. Runtime DB role with minimal privileges
-- ============================================================================
-- vortex_runtime is the role the application connects as at runtime. It
-- may INSERT into audit_log but cannot UPDATE, DELETE, or TRUNCATE it.
-- The owning role used to run this migration (typically 'remicle' or the
-- DB owner) retains full privileges for administrative tooling.
--
-- Role creation is wrapped in an exception handler: if the migration
-- role lacks CREATEROLE (common in shared dev databases), we log and
-- continue without failing the whole migration. The BEFORE triggers
-- above still enforce append-only semantics, so the ledger remains
-- tamper-evident — you just lose the second defence layer. Production
-- deployments should either run this migration as a role with
-- CREATEROLE or pre-create `vortex_runtime` out-of-band.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vortex_runtime') THEN
        BEGIN
            CREATE ROLE vortex_runtime LOGIN;
        EXCEPTION
            WHEN insufficient_privilege THEN
                RAISE NOTICE 'vortex_runtime role NOT created (migration role lacks CREATEROLE). Triggers still enforce append-only. Pre-create the role out-of-band to enable role-level REVOKE.';
        END;
    END IF;
END$$;

-- Apply grants/revokes only if the role exists.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vortex_runtime') THEN
        EXECUTE format('GRANT CONNECT ON DATABASE %I TO vortex_runtime', current_database());
        EXECUTE 'GRANT USAGE ON SCHEMA public TO vortex_runtime';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO vortex_runtime';
        EXECUTE 'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO vortex_runtime';
        EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO vortex_runtime';
        EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO vortex_runtime';

        -- Override: audit_log is insert-only + select for runtime. This
        -- is the belt that matches the trigger suspenders above.
        EXECUTE 'REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM vortex_runtime';

        -- Runtime may read and advance the chain head (UPDATE is needed
        -- for the UPSERT chain-head write path), but must never DELETE.
        EXECUTE 'REVOKE DELETE, TRUNCATE ON audit_chain_head FROM vortex_runtime';

        -- Runtime may read signing keys for verification and upsert its
        -- own public key on startup. It must never DELETE historical
        -- key records — they are needed to verify entries signed under
        -- a previous key.
        EXECUTE 'REVOKE DELETE, TRUNCATE ON audit_signing_keys FROM vortex_runtime';
    END IF;
END$$;

-- PUBLIC-level revokes are unconditional (they don't require CREATEROLE).
REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM PUBLIC;
REVOKE DELETE, TRUNCATE ON audit_chain_head FROM PUBLIC;
REVOKE DELETE, TRUNCATE ON audit_signing_keys FROM PUBLIC;

-- ============================================================================
-- 6. System-level attestation entry (recorded once per migration run)
-- ============================================================================
-- Insert a non-chained marker row so operators can prove exactly when the
-- WORM ledger became active. This row is intentionally pre-chain (no
-- chain_position) — the first real tenant write will create the genesis
-- row and start chain_position at 0.
INSERT INTO audit_log (
    user_id, username, action, resource_type, details,
    compliance_category, security_level, success
) VALUES (
    NULL,
    'system',
    'AUDIT_WORM_ENABLED',
    'audit_log',
    jsonb_build_object(
        'migration', '114_audit_worm',
        'trigger_enforcement', true,
        'runtime_role', 'vortex_runtime',
        'chain_enabled', true,
        'signing_enabled', 'env-driven'
    ),
    'audit_integrity',
    'HIGH',
    true
);
