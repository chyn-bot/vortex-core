-- Per-tenant custom fields (Initiative #2).
--
-- Lets a tenant admin add fields to an existing model at runtime — no Rust,
-- no recompile, no runtime DDL on the model's own table. A custom field is a
-- row in `ir_model_field` with `is_custom = true`; its values live in the
-- central `ir_custom_value` overflow store, keyed by (model, record). The
-- generic form framework renders and persists them automatically.
--
-- Because the derive-based registry sync only ever UPSERTs the code-declared
-- fields (never deletes), custom rows sit safely alongside them.

ALTER TABLE ir_model_field ADD COLUMN IF NOT EXISTS is_custom BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE ir_model_field ADD COLUMN IF NOT EXISTS help TEXT;

-- Central overflow store for custom-field values. One JSONB blob per record,
-- keyed by the model's registry name + the record's UUID. Avoids per-table
-- columns and therefore any runtime DDL — a new custom field is immediately
-- usable on every existing record of the model.
CREATE TABLE IF NOT EXISTS ir_custom_value (
    model_name VARCHAR(255) NOT NULL,
    record_id  UUID NOT NULL,
    data       JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (model_name, record_id)
);

CREATE INDEX IF NOT EXISTS idx_ir_custom_value_model ON ir_custom_value(model_name);
