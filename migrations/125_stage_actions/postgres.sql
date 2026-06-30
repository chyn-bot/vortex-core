-- Lockable stages: when a record sits in a locked stage its fields are
-- read-only (enforced in the handler, not just the UI). Multiple stages
-- may be locked.
ALTER TABLE record_stages ADD COLUMN IF NOT EXISTS locked BOOLEAN NOT NULL DEFAULT false;

-- Role-gated transition buttons (Odoo `<button states= groups=>`). Each row
-- is a button that moves a record from `from_stage` (NULL = any) to
-- `target_stage`, visible/usable only to users holding `required_role`
-- (NULL = anyone). Visibility is mirrored by server-side enforcement.
CREATE TABLE IF NOT EXISTS record_stage_actions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    model         VARCHAR(100) NOT NULL,
    label         VARCHAR(100) NOT NULL,
    target_stage  VARCHAR(50)  NOT NULL,
    from_stage    VARCHAR(50),
    required_role VARCHAR(100),
    color         VARCHAR(20)  NOT NULL DEFAULT 'primary',
    sequence      INTEGER      NOT NULL DEFAULT 10,
    active        BOOLEAN      NOT NULL DEFAULT true,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_stage_actions_model_label UNIQUE (model, label)
);
CREATE INDEX IF NOT EXISTS idx_stage_actions_model ON record_stage_actions(model, sequence);
