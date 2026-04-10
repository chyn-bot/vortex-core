-- Migration 114: WORM Audit Ledger (MSSQL dialect)
--
-- Mirrors 114_audit_worm/postgres.sql. See that file for the authoritative
-- design rationale.
--
-- Dialect differences:
--   BYTEA            -> VARBINARY(MAX)
--   TEXT             -> NVARCHAR(MAX)
--   TIMESTAMPTZ      -> DATETIMEOFFSET
--   NOW()            -> SYSUTCDATETIME()
--   gen_random_uuid  -> NEWSEQUENTIALID() / NEWID()
--   BEFORE triggers  -> INSTEAD OF triggers with THROW
--   TRUNCATE trigger -> no row-level equivalent; enforced via DENY on role
--   RLS / pg DO blk  -> T-SQL IF NOT EXISTS blocks

-- ============================================================================
-- 1. Chain + signing + dual-clock columns on audit_log
-- ============================================================================
IF COL_LENGTH('audit_log', 'prev_hash') IS NULL
    ALTER TABLE audit_log ADD prev_hash VARBINARY(MAX) NULL;
IF COL_LENGTH('audit_log', 'entry_hash') IS NULL
    ALTER TABLE audit_log ADD entry_hash VARBINARY(MAX) NULL;
IF COL_LENGTH('audit_log', 'chain_position') IS NULL
    ALTER TABLE audit_log ADD chain_position BIGINT NULL;
IF COL_LENGTH('audit_log', 'signature') IS NULL
    ALTER TABLE audit_log ADD signature VARBINARY(MAX) NULL;
IF COL_LENGTH('audit_log', 'signing_key_id') IS NULL
    ALTER TABLE audit_log ADD signing_key_id NVARCHAR(255) NULL;
IF COL_LENGTH('audit_log', 'canonical_payload') IS NULL
    ALTER TABLE audit_log ADD canonical_payload NVARCHAR(MAX) NULL;
IF COL_LENGTH('audit_log', 'db_timestamp') IS NULL
    ALTER TABLE audit_log ADD db_timestamp DATETIMEOFFSET NOT NULL CONSTRAINT df_audit_log_db_timestamp DEFAULT SYSUTCDATETIME();
GO

-- Self-describing pre-chain / genesis / linked-chain shape.
IF OBJECT_ID('chk_audit_chain_shape', 'C') IS NOT NULL
    ALTER TABLE audit_log DROP CONSTRAINT chk_audit_chain_shape;
GO

ALTER TABLE audit_log
    ADD CONSTRAINT chk_audit_chain_shape CHECK (
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
GO

-- One chain position per tenant (filtered unique index is the SQL Server
-- analogue of Postgres partial unique indexes).
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_audit_chain_per_tenant' AND object_id = OBJECT_ID('audit_log'))
    CREATE UNIQUE INDEX idx_audit_chain_per_tenant
        ON audit_log (company_id, chain_position)
        WHERE chain_position IS NOT NULL;
GO

-- ============================================================================
-- 2. Per-tenant chain head
-- ============================================================================
IF OBJECT_ID('audit_chain_head', 'U') IS NULL
BEGIN
    CREATE TABLE audit_chain_head (
        company_id    UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
        last_hash     VARBINARY(MAX) NOT NULL,
        last_position BIGINT NOT NULL,
        updated_at    DATETIMEOFFSET NOT NULL DEFAULT SYSUTCDATETIME(),
        CONSTRAINT fk_audit_chain_head_company
            FOREIGN KEY (company_id) REFERENCES companies(id)
    );
END;
GO

-- ============================================================================
-- 3. Ed25519 signing keys
-- ============================================================================
IF OBJECT_ID('audit_signing_keys', 'U') IS NULL
BEGIN
    CREATE TABLE audit_signing_keys (
        key_id     NVARCHAR(255) NOT NULL PRIMARY KEY,
        public_key VARBINARY(MAX) NOT NULL,
        algorithm  NVARCHAR(50) NOT NULL DEFAULT 'ed25519',
        valid_from DATETIMEOFFSET NOT NULL,
        valid_to   DATETIMEOFFSET NULL,
        revoked_at DATETIMEOFFSET NULL,
        created_at DATETIMEOFFSET NOT NULL DEFAULT SYSUTCDATETIME()
    );
END;
GO

-- ============================================================================
-- 4. Append-only enforcement — INSTEAD OF UPDATE/DELETE triggers
-- ============================================================================
-- SQL Server has no BEFORE triggers. INSTEAD OF triggers run in place of
-- the mutation; a THROW inside them aborts the operation without applying
-- any changes.
IF OBJECT_ID('trg_audit_log_no_update', 'TR') IS NOT NULL
    DROP TRIGGER trg_audit_log_no_update;
GO
CREATE TRIGGER trg_audit_log_no_update ON audit_log
INSTEAD OF UPDATE AS
BEGIN
    THROW 51000, 'audit_log is append-only (WORM); UPDATE blocked by WORM policy', 1;
END;
GO

IF OBJECT_ID('trg_audit_log_no_delete', 'TR') IS NOT NULL
    DROP TRIGGER trg_audit_log_no_delete;
GO
CREATE TRIGGER trg_audit_log_no_delete ON audit_log
INSTEAD OF DELETE AS
BEGIN
    THROW 51000, 'audit_log is append-only (WORM); DELETE blocked by WORM policy', 1;
END;
GO

-- SQL Server has NO trigger type that fires on TRUNCATE TABLE. TRUNCATE
-- protection here must come from the role grant model below: runtime
-- roles are DENIED ALTER and DELETE on audit_log, which together block
-- the TRUNCATE permission chain. An additional DATABASE-level DDL trigger
-- for TRUNCATE_TABLE is left as a site-specific hardening step.

-- ============================================================================
-- 5. Runtime role with minimal privileges
-- ============================================================================
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'vortex_runtime')
BEGIN
    -- User without login — production deployments bind this to a SQL
    -- Server login or AAD identity at provisioning time.
    CREATE USER vortex_runtime WITHOUT LOGIN;
END;
GO

-- Baseline CRUD on the schema.
GRANT SELECT, INSERT, UPDATE, DELETE ON SCHEMA::dbo TO vortex_runtime;

-- Override: audit_log is SELECT + INSERT only for runtime.
DENY UPDATE, DELETE, ALTER, REFERENCES ON audit_log TO vortex_runtime;

-- Chain head allows UPDATE (for the UPSERT advance path) but forbids DELETE.
DENY DELETE, ALTER ON audit_chain_head TO vortex_runtime;

-- Signing keys: runtime may read + upsert its own, but never delete.
DENY DELETE, ALTER ON audit_signing_keys TO vortex_runtime;
GO

-- ============================================================================
-- 6. System-level attestation entry
-- ============================================================================
INSERT INTO audit_log (
    user_id, username, action, resource_type, details,
    cip_requirement, security_level, success
) VALUES (
    NULL,
    'system',
    'AUDIT_WORM_ENABLED',
    'audit_log',
    '{"migration":"114_audit_worm","trigger_enforcement":true,"runtime_role":"vortex_runtime","chain_enabled":true,"signing_enabled":"env-driven"}',
    'CIP-007-6 R5.5',
    'HIGH',
    1
);
GO
