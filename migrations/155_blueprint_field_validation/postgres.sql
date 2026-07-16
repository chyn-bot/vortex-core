-- Blueprints: per-field required / unique validation.
--
-- `is_required` is enforced at the form layer (a `required` input attribute plus
-- a server-side non-empty check) so it applies cleanly to fields added to a
-- table that already has rows. `is_unique` is enforced by a real partial UNIQUE
-- index on the generated column (created through the Blueprint DDL layer), so
-- uniqueness holds regardless of how a record is written. Both default to false,
-- so existing Blueprint fields are unaffected.
ALTER TABLE ir_model_field ADD COLUMN IF NOT EXISTS is_required BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE ir_model_field ADD COLUMN IF NOT EXISTS is_unique   BOOLEAN NOT NULL DEFAULT false;
