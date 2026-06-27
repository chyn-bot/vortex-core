-- ============================================================================
-- Migration 117: Platform Sequence Service
-- ============================================================================
--
-- Promotes the EAM-specific `eam_sequences` table (introduced in
-- migration 105) to a generic, core-level `sequences` table used by
-- every Vortex vertical for atomic code generation.
--
-- The new schema introduces a composite primary key `(code, scope)`
-- so time-based sequences (yearly invoice numbers, monthly ticket
-- numbers) no longer need synthetic keys like `maintenance_2026` —
-- the period lives in its own column and the logical code stays
-- clean. Existing EAM data is migrated in place by splitting the old
-- synthetic keys.
--
-- Code namespacing convention: `<plugin_technical_name>.<logical>`,
-- e.g. `eam.equipment`, `crm.lead`, `sales.invoice`.

-- ----------------------------------------------------------------------------
-- 1. New generic sequences table
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS sequences (
    code          VARCHAR(100) NOT NULL,
    scope         VARCHAR(16)  NOT NULL DEFAULT '',
    current_value BIGINT       NOT NULL DEFAULT 0,
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    PRIMARY KEY (code, scope)
);

CREATE INDEX IF NOT EXISTS idx_sequences_code ON sequences(code);

COMMENT ON TABLE sequences IS
    'Platform sequence service — atomic no-gap counters for generated codes (equipment, work orders, invoices, tickets, …). See vortex_orm::sequence for the Rust API. Composite PK (code, scope) lets time-based sequences share a logical code across periods.';
COMMENT ON COLUMN sequences.code IS
    'Globally-unique dotted namespace, e.g. "eam.equipment", "sales.invoice". Plugins prefix with their technical name.';
COMMENT ON COLUMN sequences.scope IS
    'Period key for time-partitioned counters: empty for global, "2026" for yearly, "2026-04" for monthly.';

-- ----------------------------------------------------------------------------
-- 2. Migrate data from legacy eam_sequences
-- ----------------------------------------------------------------------------
--
-- The old table used synthetic keys like `maintenance_2026` to fake
-- per-year scoping. We detect these with a regex, split them into
-- (code, scope), and prefix the logical name with `eam.` so the new
-- namespace is consistent with the dotted convention.
--
-- Guarded by `to_regclass` so the migration is safe on fresh installs
-- where migration 105 has not yet created `eam_sequences`.

DO $$
BEGIN
    IF to_regclass('public.eam_sequences') IS NOT NULL THEN
        INSERT INTO sequences (code, scope, current_value, updated_at)
        SELECT
            'eam.' || CASE
                WHEN sequence_key ~ '_[0-9]{4}$'
                    THEN regexp_replace(sequence_key, '_[0-9]{4}$', '')
                ELSE sequence_key
            END AS code,
            CASE
                WHEN sequence_key ~ '_[0-9]{4}$'
                    THEN substring(sequence_key FROM '[0-9]{4}$')
                ELSE ''
            END AS scope,
            current_value,
            COALESCE(updated_at, NOW())
        FROM eam_sequences
        ON CONFLICT (code, scope) DO NOTHING;

        DROP TABLE eam_sequences;
    END IF;
END $$;
