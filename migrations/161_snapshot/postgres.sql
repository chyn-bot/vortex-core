-- Deterministic snapshot / freeze primitive.
--
-- The rule "calculation reads only from a frozen, versioned snapshot, never
-- live master data mid-run" is the foundation of any reproducible, defensible
-- batch computation — a bill that can be recomputed identically months later, a
-- valuation run, a payroll cycle. It is not billing-specific: it is the generic
-- shape of "freeze the inputs, then compute against the freeze".
--
-- A *set* is one freeze, identified by a caller `label` and an auto-assigned
-- monotonic `version` (the "snapshot_version" other records reference). A set is
-- 'open' while records are being frozen into it, then 'sealed' — after which it
-- is immutable and safe to read deterministically. There is no update or delete
-- path for records, so a sealed set reproduces byte-for-byte.
CREATE TABLE IF NOT EXISTS snapshot_set (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- What is being frozen, e.g. 'billing.cycle.2026-07'. Versions are scoped
    -- to a label so each subject has its own version line.
    label      VARCHAR(150) NOT NULL,
    -- Monotonic per label: version 1, 2, 3… Assigned at create time.
    version    INTEGER      NOT NULL,
    -- open   : records may still be frozen in
    -- sealed : immutable; the only state calculation should read from
    status     VARCHAR(20)  NOT NULL DEFAULT 'open',
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    sealed_at  TIMESTAMPTZ,
    UNIQUE (label, version)
);

CREATE TABLE IF NOT EXISTS snapshot_record (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    set_id     UUID NOT NULL REFERENCES snapshot_set(id) ON DELETE CASCADE,
    -- The subject of this frozen record — an account id, a source row id. Unique
    -- within the set: one frozen state per entity per freeze.
    entity_key VARCHAR(255) NOT NULL,
    -- The frozen inputs. Calculation reads this and nothing live.
    data       JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (set_id, entity_key)
);

CREATE INDEX IF NOT EXISTS idx_snapshot_set_label ON snapshot_set(label, version DESC);
