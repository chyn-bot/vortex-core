-- Custom-field placement (Initiative #2 enhancement).
--
-- A custom field can be anchored to appear immediately after a named built-in
-- field on the record form (e.g. right after "name"). NULL keeps the existing
-- behaviour: the field renders in the "Custom Fields" section at the bottom.
--
-- Only meaningful for is_custom = true rows; derived fields leave it NULL.

ALTER TABLE ir_model_field
    ADD COLUMN IF NOT EXISTS position_after VARCHAR(255);
