-- Reconciliation — self-learning extraction knowledge base.
--
-- When a reviewer spots a wrong extraction, they type a correction ("the
-- discount is the 4th column, not tax"; "supplier code is the digits after
-- 'Akaun'"). The correction is stored here and injected into the extraction
-- prompt for future runs, so the model improves per supplier over time. This
-- is in-context learning (retrieval into the prompt), not model retraining —
-- fully auditable and reversible: a hint can be deactivated at any time.
--
-- Scope: supplier_no = a specific supplier's invoice layout; NULL = a global
-- rule applied to every extraction.

CREATE TABLE IF NOT EXISTS recon_extract_hint (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    supplier_no     VARCHAR(64),          -- NULL = global rule
    hint            TEXT NOT NULL,
    source_batch_id UUID,                 -- invoice the feedback came from (soft ref)
    active          BOOLEAN NOT NULL DEFAULT true,
    created_by      UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS recon_extract_hint_supplier_idx
    ON recon_extract_hint (supplier_no) WHERE active;
