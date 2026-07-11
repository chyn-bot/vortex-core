-- Saveable analytic views (Initiative #4 tail).
--
-- A saved_view persists the configuration of one of the generic analytic
-- views (pivot / graph / kanban / calendar) for a registered model, as a
-- user record: owned by its author, optionally shared with the tenant, and
-- optionally the shared default for that (model, view_type).
--
-- The config bag is a small JSONB object of query-param keys (rows, cols,
-- measure, agg, group_by, type, date_field). Every field name it stores is
-- validated against the model registry at save time (see
-- vortex_framework::saved_views), so loading a view can only reconstruct a
-- URL over real, registered columns.
--
-- This replaces the ir_ui_view / ir_ui_view_kanban / ir_ui_view_graph tables
-- the generic view handlers used to join — which no migration ever created.

CREATE TABLE IF NOT EXISTS saved_view (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    model_name  VARCHAR(128) NOT NULL,          -- ir_model.name
    view_type   VARCHAR(16)  NOT NULL,          -- pivot | graph | kanban | calendar
    name        VARCHAR(128) NOT NULL,
    config      JSONB        NOT NULL DEFAULT '{}'::jsonb,
    owner_id    UUID REFERENCES users(id) ON DELETE CASCADE,
    is_shared   BOOLEAN NOT NULL DEFAULT false,
    is_default  BOOLEAN NOT NULL DEFAULT false, -- the shared default for (model, view_type)
    sequence    INT     NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_saved_view_model
    ON saved_view (model_name, view_type);

-- At most one shared default per (model, view_type).
CREATE UNIQUE INDEX IF NOT EXISTS uq_saved_view_default
    ON saved_view (model_name, view_type)
    WHERE is_default;
