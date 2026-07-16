-- Blueprints: per-section form layout.
--
-- Sections (the field-grouping labels set in the Layout card) are laid out on a
-- two-column grid on the record form. `section_config` stores per-section width
-- keyed by section label — `{"Contact": {"width": "half"}, ...}`. A section
-- defaults to full width (its own row) when absent, so existing Blueprints are
-- unaffected; two half-width sections pack side by side, and a full-width
-- section spans the row (acting as a page break between paired sections).
ALTER TABLE ir_model ADD COLUMN IF NOT EXISTS section_config JSONB NOT NULL DEFAULT '{}'::jsonb;
