ALTER TABLE ir_model_field DROP CONSTRAINT IF EXISTS chk_ir_model_field_type;
ALTER TABLE ir_model_field ADD CONSTRAINT chk_ir_model_field_type CHECK (
    field_type = ANY (ARRAY[
        'string','char','text','boolean','integer','float','decimal','monetary',
        'number','date','datetime','selection','many2one','one2many',
        'many2many','uuid','json','binary'
    ]::text[])
);
