-- ============================================================================
-- Migration 117: Platform Sequence Service
-- ============================================================================
--
-- A generic, core-level `sequences` table used by every Vortex
-- vertical for atomic, no-gap code generation.
--
-- The schema uses a composite primary key `(code, scope)` so
-- time-based sequences (yearly invoice numbers, monthly ticket
-- numbers) don't need synthetic keys — the period lives in its own
-- column and the logical code stays clean.
--
-- Code namespacing convention: `<plugin_technical_name>.<logical>`,
-- e.g. `crm.lead`, `sales.invoice`.

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
    'Platform sequence service — atomic no-gap counters for generated codes (leads, invoices, tickets, …). See vortex_orm::sequence for the Rust API. Composite PK (code, scope) lets time-based sequences share a logical code across periods.';
COMMENT ON COLUMN sequences.code IS
    'Globally-unique dotted namespace, e.g. "crm.lead", "sales.invoice". Plugins prefix with their technical name.';
COMMENT ON COLUMN sequences.scope IS
    'Period key for time-partitioned counters: empty for global, "2026" for yearly, "2026-04" for monthly.';
