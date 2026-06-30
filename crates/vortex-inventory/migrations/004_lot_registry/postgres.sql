-- Register stock_lot in the platform metadata registry so the generic
-- list/pivot/API layer can discover it. Idempotent.

INSERT INTO ir_model (name, display_name, table_name, module)
VALUES ('stock_lot', 'Lots / Serials', 'stock_lot', 'inventory')
ON CONFLICT (name) DO UPDATE
    SET display_name = EXCLUDED.display_name,
        table_name   = EXCLUDED.table_name,
        module       = EXCLUDED.module,
        is_active    = true;

WITH m AS (SELECT id FROM ir_model WHERE name = 'stock_lot')
INSERT INTO ir_model_field
    (model_id, name, display_name, field_type, related_model, selection_options, sequence)
VALUES
    ((SELECT id FROM m), 'name',       'Number',   'string',    NULL,            NULL,                              10),
    ((SELECT id FROM m), 'product_id', 'Product',  'many2one',  'stock_product', NULL,                              20),
    ((SELECT id FROM m), 'lot_type',   'Type',     'selection', NULL,            '["lot","serial"]'::jsonb,         30),
    ((SELECT id FROM m), 'active',     'Active',   'boolean',   NULL,            NULL,                              40)
ON CONFLICT (model_id, name) DO UPDATE
    SET display_name      = EXCLUDED.display_name,
        field_type        = EXCLUDED.field_type,
        related_model     = EXCLUDED.related_model,
        selection_options = EXCLUDED.selection_options,
        sequence          = EXCLUDED.sequence;
