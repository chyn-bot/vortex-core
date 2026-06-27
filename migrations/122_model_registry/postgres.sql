-- Model metadata registry
--
-- Backs the generic model views (/list/{model}, /kanban/{model},
-- /graph/{model}, /calendar/{model}, /pivot/{model}) which need to
-- know a model's table name, fields, types, and display names at
-- runtime. Plugins seed rows here from their own migrations.

CREATE TABLE ir_model (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    display_name VARCHAR(255) NOT NULL,
    table_name VARCHAR(255) NOT NULL,
    module VARCHAR(100),
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ir_model_module ON ir_model(module);

CREATE TABLE ir_model_field (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    model_id UUID NOT NULL REFERENCES ir_model(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    field_type VARCHAR(50) NOT NULL,
    related_model VARCHAR(255),
    selection_options JSONB,
    sequence INTEGER NOT NULL DEFAULT 10,
    is_visible BOOLEAN NOT NULL DEFAULT true,
    CONSTRAINT uq_ir_model_field UNIQUE (model_id, name),
    CONSTRAINT chk_ir_model_field_type CHECK (
        field_type IN (
            'string', 'char', 'text', 'boolean', 'integer', 'float',
            'decimal', 'monetary', 'number', 'date', 'datetime',
            'selection', 'many2one', 'one2many', 'many2many',
            'uuid', 'json', 'binary'
        )
    )
);

CREATE INDEX idx_ir_model_field_model ON ir_model_field(model_id);
CREATE INDEX idx_ir_model_field_type ON ir_model_field(field_type);
