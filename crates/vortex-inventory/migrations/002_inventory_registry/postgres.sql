-- Register the inventory models in the platform metadata registry so the
-- generic views (/pivot, /kanban, /graph, /calendar) and the public REST
-- API can discover their fields and types. Idempotent.

-- ── stock_product ───────────────────────────────────────────────────────
INSERT INTO ir_model (name, display_name, table_name, module)
VALUES ('stock_product', 'Products', 'stock_product', 'inventory')
ON CONFLICT (name) DO UPDATE
    SET display_name = EXCLUDED.display_name,
        table_name   = EXCLUDED.table_name,
        module       = EXCLUDED.module,
        is_active    = true;

WITH m AS (SELECT id FROM ir_model WHERE name = 'stock_product')
INSERT INTO ir_model_field
    (model_id, name, display_name, field_type, related_model, selection_options, sequence)
VALUES
    ((SELECT id FROM m), 'code',         'Code',        'string',    NULL,                     NULL,                                                 10),
    ((SELECT id FROM m), 'name',         'Name',        'string',    NULL,                     NULL,                                                 20),
    ((SELECT id FROM m), 'category_id',  'Category',    'many2one',  'stock_product_category', NULL,                                                 30),
    ((SELECT id FROM m), 'product_type', 'Type',        'selection', NULL,                     '["stockable","consumable","service"]'::jsonb,        40),
    ((SELECT id FROM m), 'tracking',     'Tracking',    'selection', NULL,                     '["none","lot","serial"]'::jsonb,                     50),
    ((SELECT id FROM m), 'cost',         'Cost',        'monetary',  NULL,                     NULL,                                                 60),
    ((SELECT id FROM m), 'reorder_min',  'Reorder Min', 'number',    NULL,                     NULL,                                                 70),
    ((SELECT id FROM m), 'active',       'Active',      'boolean',   NULL,                     NULL,                                                 80)
ON CONFLICT (model_id, name) DO UPDATE
    SET display_name      = EXCLUDED.display_name,
        field_type        = EXCLUDED.field_type,
        related_model     = EXCLUDED.related_model,
        selection_options = EXCLUDED.selection_options,
        sequence          = EXCLUDED.sequence;

-- ── stock_location ──────────────────────────────────────────────────────
INSERT INTO ir_model (name, display_name, table_name, module)
VALUES ('stock_location', 'Locations', 'stock_location', 'inventory')
ON CONFLICT (name) DO UPDATE
    SET display_name = EXCLUDED.display_name,
        table_name   = EXCLUDED.table_name,
        module       = EXCLUDED.module,
        is_active    = true;

WITH m AS (SELECT id FROM ir_model WHERE name = 'stock_location')
INSERT INTO ir_model_field
    (model_id, name, display_name, field_type, related_model, selection_options, sequence)
VALUES
    ((SELECT id FROM m), 'code',          'Code',   'string',    NULL,             NULL,                                                                  10),
    ((SELECT id FROM m), 'name',          'Name',   'string',    NULL,             NULL,                                                                  20),
    ((SELECT id FROM m), 'location_type', 'Type',   'selection', NULL,             '["internal","supplier","customer","inventory","transit"]'::jsonb,     30),
    ((SELECT id FROM m), 'parent_id',     'Parent', 'many2one',  'stock_location', NULL,                                                                  40),
    ((SELECT id FROM m), 'active',        'Active', 'boolean',   NULL,             NULL,                                                                  50)
ON CONFLICT (model_id, name) DO UPDATE
    SET display_name      = EXCLUDED.display_name,
        field_type        = EXCLUDED.field_type,
        related_model     = EXCLUDED.related_model,
        selection_options = EXCLUDED.selection_options,
        sequence          = EXCLUDED.sequence;

-- ── stock_move ──────────────────────────────────────────────────────────
INSERT INTO ir_model (name, display_name, table_name, module)
VALUES ('stock_move', 'Stock Moves', 'stock_move', 'inventory')
ON CONFLICT (name) DO UPDATE
    SET display_name = EXCLUDED.display_name,
        table_name   = EXCLUDED.table_name,
        module       = EXCLUDED.module,
        is_active    = true;

WITH m AS (SELECT id FROM ir_model WHERE name = 'stock_move')
INSERT INTO ir_model_field
    (model_id, name, display_name, field_type, related_model, selection_options, sequence)
VALUES
    ((SELECT id FROM m), 'reference',          'Reference',   'string',    NULL,             NULL,                                          10),
    ((SELECT id FROM m), 'product_id',         'Product',     'many2one',  'stock_product',  NULL,                                          20),
    ((SELECT id FROM m), 'quantity',           'Quantity',    'number',    NULL,             NULL,                                          30),
    ((SELECT id FROM m), 'source_location_id', 'From',        'many2one',  'stock_location', NULL,                                          40),
    ((SELECT id FROM m), 'dest_location_id',   'To',          'many2one',  'stock_location', NULL,                                          50),
    ((SELECT id FROM m), 'state',              'Status',      'selection', NULL,             '["draft","done","cancelled"]'::jsonb,         60)
ON CONFLICT (model_id, name) DO UPDATE
    SET display_name      = EXCLUDED.display_name,
        field_type        = EXCLUDED.field_type,
        related_model     = EXCLUDED.related_model,
        selection_options = EXCLUDED.selection_options,
        sequence          = EXCLUDED.sequence;
