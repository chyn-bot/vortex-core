-- Versioned rules & adjustment engine.
--
-- Exception logic — rebates, overrides, surcharges, adjustments — expressed as
-- *data* an analyst authors and versions, not as hardcoded branches. This is
-- the generic, industry-neutral core of what a billing "rules matrix" needs,
-- but it is not billing-specific: any domain with data-authored, auditable,
-- reproducible business rules reuses it.
--
-- It is deliberately NOT the two rule mechanisms already in core: Cedar
-- (authorization — may this user do this?) and automation rules (on record
-- save, set a field). This engine takes an input document and produces zero or
-- more typed *adjustments* (an amount + a reason), recording exactly which rule
-- version fired — the calculation-time rules a bill/valuation/payroll needs.
--
-- Reproducibility is the whole point: a rule_set is versioned per `code`. A
-- 'draft' version is editable; 'publishing' it makes it immutable. Old records
-- reference the version that applied, so re-evaluating them months later against
-- that version reproduces the original result even after the rules have since
-- changed (a new version).
CREATE TABLE IF NOT EXISTS rule_set (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Stable identifier of the rule family, e.g. 'billing.adjustments'.
    code         VARCHAR(150) NOT NULL,
    -- Monotonic per code. Draft 3 supersedes published 2, and so on.
    version      INTEGER      NOT NULL,
    -- draft     : editable; rules may be added/changed
    -- published : immutable; the only state evaluation should load for a live run
    -- archived  : retired; kept for historical reproducibility
    status       VARCHAR(20)  NOT NULL DEFAULT 'draft',
    title        VARCHAR(255) NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    published_at TIMESTAMPTZ,
    UNIQUE (code, version)
);

CREATE TABLE IF NOT EXISTS rule (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_set_id     UUID NOT NULL REFERENCES rule_set(id) ON DELETE CASCADE,
    -- Evaluation order within the set (ascending).
    seq             INTEGER NOT NULL DEFAULT 0,
    name            VARCHAR(255) NOT NULL,
    -- Condition AST (see the `Condition` enum): when does this rule fire?
    condition       JSONB NOT NULL DEFAULT '{"op":"always"}',
    -- The kind of adjustment this rule produces when it fires (an open string,
    -- e.g. 'rebate', 'surcharge', 'override' — the vertical names its own types).
    adjustment_type VARCHAR(100) NOT NULL,
    -- Amount AST (see the `Amount` enum): how much, given the input document?
    amount          JSONB NOT NULL DEFAULT '{"kind":"fixed","value":"0"}',
    -- Optional machine-readable reason attached to the produced adjustment.
    reason_code     VARCHAR(100),
    active          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rule_set_code ON rule_set(code, version DESC);
CREATE INDEX IF NOT EXISTS idx_rule_set_lookup ON rule(rule_set_id, seq);
