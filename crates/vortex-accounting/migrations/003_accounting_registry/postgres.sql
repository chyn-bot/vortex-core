-- Register accounting models in the platform metadata registry so the
-- generic list/pivot/API layer (/api/v1) can discover them. Idempotent.

INSERT INTO ir_model (name, display_name, table_name, module)
VALUES
    ('acc_move',    'Journal Entries',   'acc_move',    'accounting'),
    ('acc_account', 'Chart of Accounts', 'acc_account', 'accounting')
ON CONFLICT (name) DO UPDATE
    SET display_name = EXCLUDED.display_name,
        table_name   = EXCLUDED.table_name,
        module       = EXCLUDED.module,
        is_active    = true;

WITH m AS (SELECT id FROM ir_model WHERE name = 'acc_move')
INSERT INTO ir_model_field
    (model_id, name, display_name, field_type, related_model, selection_options, sequence)
VALUES
    ((SELECT id FROM m), 'number',          'Number',        'string',    NULL,       NULL, 10),
    ((SELECT id FROM m), 'move_date',       'Date',          'date',      NULL,       NULL, 20),
    ((SELECT id FROM m), 'move_type',       'Type',          'selection', NULL,
        '["entry","customer_invoice","customer_credit_note","vendor_bill","vendor_credit_note","payment"]'::jsonb, 30),
    ((SELECT id FROM m), 'partner_id',      'Partner',       'many2one',  'contacts', NULL, 40),
    ((SELECT id FROM m), 'state',           'Status',        'selection', NULL,
        '["draft","posted","cancelled"]'::jsonb, 50),
    ((SELECT id FROM m), 'payment_state',   'Payment',       'selection', NULL,
        '["not_paid","partial","paid","reversed"]'::jsonb, 60),
    ((SELECT id FROM m), 'total_amount',    'Total',         'monetary',  NULL,       NULL, 70),
    ((SELECT id FROM m), 'amount_residual', 'Open Amount',   'monetary',  NULL,       NULL, 80),
    ((SELECT id FROM m), 'due_date',        'Due Date',      'date',      NULL,       NULL, 90),
    ((SELECT id FROM m), 'ref',             'Reference',     'string',    NULL,       NULL, 100),
    ((SELECT id FROM m), 'origin_ref',      'Origin',        'string',    NULL,       NULL, 110)
ON CONFLICT (model_id, name) DO UPDATE
    SET display_name      = EXCLUDED.display_name,
        field_type        = EXCLUDED.field_type,
        related_model     = EXCLUDED.related_model,
        selection_options = EXCLUDED.selection_options,
        sequence          = EXCLUDED.sequence;

WITH m AS (SELECT id FROM ir_model WHERE name = 'acc_account')
INSERT INTO ir_model_field
    (model_id, name, display_name, field_type, related_model, selection_options, sequence)
VALUES
    ((SELECT id FROM m), 'code',         'Code',    'string',    NULL, NULL, 10),
    ((SELECT id FROM m), 'name',         'Account', 'string',    NULL, NULL, 20),
    ((SELECT id FROM m), 'account_type', 'Type',    'selection', NULL,
        '["asset_cash","asset_bank","asset_receivable","asset_current","asset_fixed","asset_non_current","liability_payable","liability_current","liability_non_current","equity","income","income_other","expense","expense_depreciation","expense_direct_cost"]'::jsonb, 30),
    ((SELECT id FROM m), 'reconcile',    'Reconcilable', 'boolean', NULL, NULL, 40),
    ((SELECT id FROM m), 'active',       'Active',  'boolean',   NULL, NULL, 50)
ON CONFLICT (model_id, name) DO UPDATE
    SET display_name      = EXCLUDED.display_name,
        field_type        = EXCLUDED.field_type,
        related_model     = EXCLUDED.related_model,
        selection_options = EXCLUDED.selection_options,
        sequence          = EXCLUDED.sequence;
