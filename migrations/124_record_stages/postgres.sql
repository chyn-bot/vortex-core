-- Generic, data-driven stages for the core status-bar widget.
-- Any model can have user-managed stages: rows here, keyed by (model, code).
-- The record stores the stage `code` in its own status column (e.g.
-- contacts.record_state); this table maps code -> label/color/order/visibility.
CREATE TABLE IF NOT EXISTS record_stages (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    model          VARCHAR(100) NOT NULL,
    code           VARCHAR(50)  NOT NULL,
    label          VARCHAR(100) NOT NULL,
    color          VARCHAR(20)  NOT NULL DEFAULT 'neutral',
    sequence       INTEGER      NOT NULL DEFAULT 10,
    -- false => the stage shows in the bar only while it is the current value
    -- (Odoo `statusbar_visible` exclusion, e.g. a Cancelled stage).
    always_visible BOOLEAN      NOT NULL DEFAULT true,
    active         BOOLEAN      NOT NULL DEFAULT true,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_record_stages_model_code UNIQUE (model, code)
);
CREATE INDEX IF NOT EXISTS idx_record_stages_model ON record_stages(model, sequence);
