-- No-code automation rules (Initiative #3).
--
-- "When a record of <model> is created/updated AND matches an optional
-- condition, run a built-in action." Rules are data — an admin authors them in
-- the UI, no Rust, no deploy. The generic form save (and, later, the REST API)
-- evaluate them after a record changes.
--
-- v1 supports one optional condition (field / operator / value) and the
-- `set_field` action. Both the condition field and the action field are
-- validated against the code-derived registry (ir_model_field) at run time, so
-- a rule can only ever read/write a real, registered column of its model —
-- never arbitrary SQL. Actions write directly (not through the form-save path),
-- so a rule that sets a field cannot re-trigger itself.

CREATE TABLE IF NOT EXISTS automation_rule (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    model_name      VARCHAR(255) NOT NULL,
    trigger_event   VARCHAR(20)  NOT NULL,
    condition_field VARCHAR(255),
    condition_op    VARCHAR(20),
    condition_value TEXT,
    action_type     VARCHAR(30)  NOT NULL DEFAULT 'set_field',
    action_field    VARCHAR(255) NOT NULL,
    action_value    TEXT,
    active          BOOLEAN NOT NULL DEFAULT true,
    created_by      UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_automation_trigger CHECK (trigger_event IN ('create', 'update')),
    CONSTRAINT chk_automation_action  CHECK (action_type IN ('set_field'))
);

CREATE INDEX IF NOT EXISTS idx_automation_rule_lookup
    ON automation_rule (model_name, trigger_event) WHERE active;
