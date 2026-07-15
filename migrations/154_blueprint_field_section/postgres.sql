-- Blueprints: group form fields into named sections (cards).
--
-- The generic record form renders one card per section, laid out two-up across
-- the full width (like the Contacts form's General / Contact Info / Address
-- cards) instead of a single narrow card. A NULL/empty section falls back to a
-- default "General" card, so existing Blueprints keep working unchanged.
ALTER TABLE ir_model_field ADD COLUMN IF NOT EXISTS section VARCHAR(64);
