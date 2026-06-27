ALTER TABLE ir_model ADD COLUMN IF NOT EXISTS list_url VARCHAR(255);

COMMENT ON COLUMN ir_model.list_url IS
    'Canonical list-view URL for this model. When set, the generic /list/{model} handler 302-redirects here, so plugins that ship a richer custom list handler remain the single source of truth.';
