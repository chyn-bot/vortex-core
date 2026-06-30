-- Register purchase_order in the platform metadata registry so the
-- generic list/pivot/API layer can discover it. Idempotent.

INSERT INTO ir_model (name, display_name, table_name, module)
VALUES ('purchase_order', 'Purchase Orders', 'purchase_order', 'purchase')
ON CONFLICT (name) DO UPDATE
    SET display_name = EXCLUDED.display_name,
        table_name   = EXCLUDED.table_name,
        module       = EXCLUDED.module,
        is_active    = true;

WITH m AS (SELECT id FROM ir_model WHERE name = 'purchase_order')
INSERT INTO ir_model_field
    (model_id, name, display_name, field_type, related_model, selection_options, sequence)
VALUES
    ((SELECT id FROM m), 'number',        'Number',     'string',    NULL,       NULL,                                                          10),
    ((SELECT id FROM m), 'vendor_id',     'Vendor',     'many2one',  'contacts', NULL,                                                          20),
    ((SELECT id FROM m), 'order_date',    'Order Date', 'date',      NULL,       NULL,                                                          30),
    ((SELECT id FROM m), 'state',         'Status',     'selection', NULL,       '["draft","confirmed","received","cancelled"]'::jsonb,         40),
    ((SELECT id FROM m), 'total_amount',  'Total',      'monetary',  NULL,       NULL,                                                          50)
ON CONFLICT (model_id, name) DO UPDATE
    SET display_name      = EXCLUDED.display_name,
        field_type        = EXCLUDED.field_type,
        related_model     = EXCLUDED.related_model,
        selection_options = EXCLUDED.selection_options,
        sequence          = EXCLUDED.sequence;
