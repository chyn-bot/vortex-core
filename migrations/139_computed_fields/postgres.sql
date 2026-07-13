-- Computed / related virtual fields (Initiative #5).
--
-- A computed field is an admin-authored virtual field (x_-prefixed, like a
-- custom field) whose value is DERIVED rather than entered. Two kinds:
--
--   * related  — pull a value across a many2one: compute_expr = "<m2o>.<field>"
--                (e.g. partner_id.email). Evaluated with a validated LEFT JOIN.
--   * expr     — an arithmetic expression over the record's own numeric fields:
--                compute_expr = "(qty * unit_price) - discount". Every identifier
--                is checked against the code-derived registry before it reaches
--                SQL; Postgres does the maths.
--
-- Reuses the custom-field machinery: a computed field is an ir_model_field row
-- with is_custom = true AND is_computed = true, and its evaluated value is
-- stored (read-only) in the same ir_custom_value overflow store on every save,
-- so it needs no column on the model's own table and no runtime DDL.

ALTER TABLE ir_model_field ADD COLUMN IF NOT EXISTS is_computed   BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE ir_model_field ADD COLUMN IF NOT EXISTS compute_kind  VARCHAR(20);
ALTER TABLE ir_model_field ADD COLUMN IF NOT EXISTS compute_expr  TEXT;
