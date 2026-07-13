-- Reverse 145_blueprints.
--
-- NOTE: generated `x_*` record tables created at runtime by the blueprint DDL
-- service are intentionally NOT dropped here — they hold user data. Drop them
-- deliberately via the blueprint delete path (or by hand) before relying on a
-- clean down-migration.

DROP TABLE IF EXISTS blueprint_ddl_log;
DROP TABLE IF EXISTS blueprint_version;
DROP TABLE IF EXISTS blueprint;

ALTER TABLE ir_model_field DROP CONSTRAINT IF EXISTS chk_ir_model_field_source;
ALTER TABLE ir_model       DROP CONSTRAINT IF EXISTS chk_ir_model_source;

ALTER TABLE ir_model_field DROP COLUMN IF EXISTS source;
ALTER TABLE ir_model       DROP COLUMN IF EXISTS is_virtual;
ALTER TABLE ir_model       DROP COLUMN IF EXISTS source;
