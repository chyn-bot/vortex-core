-- Blueprints: per-field form width for a 2-column form layout.
--
-- The generic record form (/form/{model}/{id}) previously stacked every field
-- full-width, one per row. `col_span` lets a field occupy one column (half) or
-- both (full) of a 2-column responsive grid, so an admin can lay fields out
-- side by side from the Blueprint designer's Layout card.
--
--   2 = full width (default — preserves the existing one-field-per-row form)
--   1 = half width (pairs up with the next half-width field on wide screens)
ALTER TABLE ir_model_field ADD COLUMN IF NOT EXISTS col_span SMALLINT NOT NULL DEFAULT 2;
