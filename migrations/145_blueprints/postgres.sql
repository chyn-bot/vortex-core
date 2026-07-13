-- Vortex Blueprints — Phase 0 foundations.
--
-- A Blueprint is a user-defined, governed model created from the browser with
-- no deploy. Its records live in a real generated table (`x_<name>`, one real
-- column per field) so the entire generic view layer, REST API, webhooks, and
-- automation — all of which already read the `ir_model` registry — work on it
-- unchanged. Those `x_*` tables are created at RUNTIME by the blueprint DDL
-- service (vortex_orm::blueprint), never here; this migration only lays the
-- metadata foundation.

-- ── Registry provenance ──────────────────────────────────────────────────
-- Every ir_model / ir_model_field row now declares where it came from:
--   derived   — projected from a #[derive(Model)] struct (the compiled core)
--   custom    — a low-code custom field (was: is_custom = true)
--   blueprint — part of a user-defined Blueprint
-- The boot-time registry prune owns ONLY 'derived' rows, so it can never
-- delete a custom or blueprint field.
ALTER TABLE ir_model
    ADD COLUMN IF NOT EXISTS source     VARCHAR(16) NOT NULL DEFAULT 'derived',
    ADD COLUMN IF NOT EXISTS is_virtual BOOLEAN     NOT NULL DEFAULT false;

ALTER TABLE ir_model_field
    ADD COLUMN IF NOT EXISTS source     VARCHAR(16) NOT NULL DEFAULT 'derived';

-- Backfill existing custom fields so the prune can switch off is_custom onto
-- the explicit source enum. (is_custom is retained for now for compatibility.)
UPDATE ir_model_field SET source = 'custom' WHERE is_custom = true AND source = 'derived';

ALTER TABLE ir_model       ADD CONSTRAINT chk_ir_model_source
    CHECK (source IN ('derived', 'blueprint'));
ALTER TABLE ir_model_field ADD CONSTRAINT chk_ir_model_field_source
    CHECK (source IN ('derived', 'custom', 'blueprint'));

-- ── Blueprint definition metadata (beyond the ir_model row) ──────────────
CREATE TABLE blueprint (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    model_id    UUID NOT NULL REFERENCES ir_model(id) ON DELETE CASCADE,
    company_id  UUID REFERENCES companies(id),
    status      VARCHAR(16) NOT NULL DEFAULT 'draft',   -- draft | active | archived
    icon        VARCHAR(64),
    description TEXT,
    created_by  UUID REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_blueprint_model UNIQUE (model_id),
    CONSTRAINT chk_blueprint_status CHECK (status IN ('draft', 'active', 'archived'))
);

-- Revision history of the definition — enables rollback and a schema-history
-- view; every mutating operation writes a snapshot.
CREATE TABLE blueprint_version (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    blueprint_id UUID NOT NULL REFERENCES blueprint(id) ON DELETE CASCADE,
    version      INTEGER NOT NULL,
    definition   JSONB NOT NULL,
    applied_by   UUID REFERENCES users(id),
    applied_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_blueprint_version UNIQUE (blueprint_id, version)
);

-- Per-tenant DDL ledger. Every CREATE/ALTER/DROP the DDL service runs against
-- a generated `x_*` table is recorded here, in the same transaction — so a
-- tenant's blueprint schema is reproducible and verifiable, the same guarantee
-- vortex_migrations gives for plugin schema. Closes the new drift surface
-- before it opens.
CREATE TABLE blueprint_ddl_log (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    blueprint_id UUID NOT NULL REFERENCES blueprint(id) ON DELETE CASCADE,
    statement    TEXT NOT NULL,
    applied_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_blueprint_ddl_log_blueprint ON blueprint_ddl_log (blueprint_id);
