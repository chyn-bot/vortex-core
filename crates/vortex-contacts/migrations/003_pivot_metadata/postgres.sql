-- Register the `contacts` model in the platform metadata registry so
-- the generic views (/pivot, /kanban, /graph, /calendar) can discover
-- its fields and types. Idempotent: rerunning is a no-op.

INSERT INTO ir_model (name, display_name, table_name, module)
VALUES ('contacts', 'Contacts', 'contacts', 'contacts')
ON CONFLICT (name) DO UPDATE
    SET display_name = EXCLUDED.display_name,
        table_name   = EXCLUDED.table_name,
        module       = EXCLUDED.module,
        is_active    = true;

WITH m AS (SELECT id FROM ir_model WHERE name = 'contacts')
INSERT INTO ir_model_field
    (model_id, name, display_name, field_type, related_model, selection_options, sequence)
VALUES
    ((SELECT id FROM m), 'name',         'Name',         'string',    NULL,        NULL,                                                   10),
    ((SELECT id FROM m), 'code',         'Code',         'string',    NULL,        NULL,                                                   20),
    ((SELECT id FROM m), 'contact_type', 'Type',         'selection', NULL,        '["customer","supplier","both","other"]'::jsonb,        30),
    ((SELECT id FROM m), 'is_company',   'Is Company',   'boolean',   NULL,        NULL,                                                   40),
    ((SELECT id FROM m), 'city',         'City',         'string',    NULL,        NULL,                                                   50),
    ((SELECT id FROM m), 'state_id',     'State',        'many2one',  'states',    NULL,                                                   60),
    ((SELECT id FROM m), 'country_id',   'Country',      'many2one',  'countries', NULL,                                                   70),
    ((SELECT id FROM m), 'parent_id',    'Parent',       'many2one',  'contacts',  NULL,                                                   80),
    ((SELECT id FROM m), 'credit_limit', 'Credit Limit', 'monetary',  NULL,        NULL,                                                   90),
    ((SELECT id FROM m), 'active',       'Active',       'boolean',   NULL,        NULL,                                                  100)
ON CONFLICT (model_id, name) DO UPDATE
    SET display_name      = EXCLUDED.display_name,
        field_type        = EXCLUDED.field_type,
        related_model     = EXCLUDED.related_model,
        selection_options = EXCLUDED.selection_options,
        sequence          = EXCLUDED.sequence;
