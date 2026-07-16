-- Blueprints: auto-number field type.
--
-- An `autonumber` field mints a prefixed, zero-padded reference on create
-- (e.g. "VIS-2026-0001") from the shared `sequences` table. It is stored as a
-- short text column, but the model registry's field_type CHECK constraint must
-- learn the new type name. Recreate the constraint with 'autonumber' added,
-- preserving every existing type.
ALTER TABLE ir_model_field DROP CONSTRAINT IF EXISTS chk_ir_model_field_type;
ALTER TABLE ir_model_field ADD CONSTRAINT chk_ir_model_field_type CHECK (
    field_type = ANY (ARRAY[
        'string','char','text','boolean','integer','float','decimal','monetary',
        'number','date','datetime','selection','autonumber','many2one','one2many',
        'many2many','uuid','json','binary'
    ]::text[])
);
