-- Register the maintenance models in the platform metadata registry so
-- the generic list/pivot/API layer can discover them. Idempotent.

-- ── maint_asset ─────────────────────────────────────────────────────────
INSERT INTO ir_model (name, display_name, table_name, module)
VALUES ('maint_asset', 'Assets', 'maint_asset', 'maintenance')
ON CONFLICT (name) DO UPDATE
    SET display_name = EXCLUDED.display_name, table_name = EXCLUDED.table_name,
        module = EXCLUDED.module, is_active = true;

WITH m AS (SELECT id FROM ir_model WHERE name = 'maint_asset')
INSERT INTO ir_model_field
    (model_id, name, display_name, field_type, related_model, selection_options, sequence)
VALUES
    ((SELECT id FROM m), 'code',        'Code',        'string',    NULL,                  NULL,                                                              10),
    ((SELECT id FROM m), 'name',        'Name',        'string',    NULL,                  NULL,                                                              20),
    ((SELECT id FROM m), 'category_id', 'Category',    'many2one',  'maint_asset_category', NULL,                                                             30),
    ((SELECT id FROM m), 'criticality', 'Criticality', 'selection', NULL,                  '["low","medium","high","critical"]'::jsonb,                       40),
    ((SELECT id FROM m), 'state',       'State',       'selection', NULL,                  '["operational","under_maintenance","down","decommissioned"]'::jsonb, 50)
ON CONFLICT (model_id, name) DO UPDATE
    SET display_name = EXCLUDED.display_name, field_type = EXCLUDED.field_type,
        related_model = EXCLUDED.related_model, selection_options = EXCLUDED.selection_options,
        sequence = EXCLUDED.sequence;

-- ── maint_work_order ────────────────────────────────────────────────────
INSERT INTO ir_model (name, display_name, table_name, module)
VALUES ('maint_work_order', 'Work Orders', 'maint_work_order', 'maintenance')
ON CONFLICT (name) DO UPDATE
    SET display_name = EXCLUDED.display_name, table_name = EXCLUDED.table_name,
        module = EXCLUDED.module, is_active = true;

WITH m AS (SELECT id FROM ir_model WHERE name = 'maint_work_order')
INSERT INTO ir_model_field
    (model_id, name, display_name, field_type, related_model, selection_options, sequence)
VALUES
    ((SELECT id FROM m), 'number',     'Number',    'string',    NULL,          NULL,                                                       10),
    ((SELECT id FROM m), 'asset_id',   'Asset',     'many2one',  'maint_asset', NULL,                                                       20),
    ((SELECT id FROM m), 'wo_type',    'Type',      'selection', NULL,          '["corrective","preventive","inspection"]'::jsonb,          30),
    ((SELECT id FROM m), 'priority',   'Priority',  'selection', NULL,          '["low","normal","high","urgent"]'::jsonb,                  40),
    ((SELECT id FROM m), 'state',      'Status',    'selection', NULL,          '["draft","in_progress","done","cancelled"]'::jsonb,        50)
ON CONFLICT (model_id, name) DO UPDATE
    SET display_name = EXCLUDED.display_name, field_type = EXCLUDED.field_type,
        related_model = EXCLUDED.related_model, selection_options = EXCLUDED.selection_options,
        sequence = EXCLUDED.sequence;

-- ── maint_plan ──────────────────────────────────────────────────────────
INSERT INTO ir_model (name, display_name, table_name, module)
VALUES ('maint_plan', 'Maintenance Plans', 'maint_plan', 'maintenance')
ON CONFLICT (name) DO UPDATE
    SET display_name = EXCLUDED.display_name, table_name = EXCLUDED.table_name,
        module = EXCLUDED.module, is_active = true;

WITH m AS (SELECT id FROM ir_model WHERE name = 'maint_plan')
INSERT INTO ir_model_field
    (model_id, name, display_name, field_type, related_model, selection_options, sequence)
VALUES
    ((SELECT id FROM m), 'name',           'Name',      'string',    NULL,          NULL,                              10),
    ((SELECT id FROM m), 'asset_id',       'Asset',     'many2one',  'maint_asset', NULL,                              20),
    ((SELECT id FROM m), 'frequency_unit', 'Frequency', 'selection', NULL,          '["day","week","month","year"]'::jsonb, 30),
    ((SELECT id FROM m), 'next_date',      'Next Date', 'date',      NULL,          NULL,                              40),
    ((SELECT id FROM m), 'state',          'State',     'selection', NULL,          '["active","paused"]'::jsonb,      50)
ON CONFLICT (model_id, name) DO UPDATE
    SET display_name = EXCLUDED.display_name, field_type = EXCLUDED.field_type,
        related_model = EXCLUDED.related_model, selection_options = EXCLUDED.selection_options,
        sequence = EXCLUDED.sequence;
