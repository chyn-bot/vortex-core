-- Saveable dashboards (Initiative #4).
--
-- A dashboard is a named board of widgets an operator assembles in the UI — no
-- code, no deploy. Each widget runs one aggregate query over a registered model
-- (`ir_model` / `ir_model_field`, the derive-sourced registry from Initiative
-- #1): a single KPI number, or a grouped "bars" breakdown (top-N group values by
-- an aggregate). Every identifier a widget names is validated against the
-- registry and every value is bound, so a widget can only read a real, registered
-- column of its model.

CREATE TABLE IF NOT EXISTS dashboard (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(255) NOT NULL,
    description TEXT,
    owner_id    UUID,
    is_shared   BOOLEAN NOT NULL DEFAULT false,
    sequence    INT NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS dashboard_widget (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    dashboard_id  UUID NOT NULL REFERENCES dashboard(id) ON DELETE CASCADE,
    title         VARCHAR(255) NOT NULL,
    widget_type   VARCHAR(20)  NOT NULL DEFAULT 'kpi',
    model_name    VARCHAR(255) NOT NULL,
    measure_field VARCHAR(255),
    aggregate     VARCHAR(10)  NOT NULL DEFAULT 'count',
    group_field   VARCHAR(255),
    filter_field  VARCHAR(255),
    filter_op     VARCHAR(10),
    filter_value  TEXT,
    row_limit     INT NOT NULL DEFAULT 8,
    col_span      INT NOT NULL DEFAULT 1,
    sequence      INT NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_widget_type CHECK (widget_type IN ('kpi', 'bars')),
    CONSTRAINT chk_widget_agg  CHECK (aggregate IN ('count', 'sum', 'avg', 'min', 'max'))
);

CREATE INDEX IF NOT EXISTS idx_dashboard_widget_dash
    ON dashboard_widget (dashboard_id, sequence);
CREATE INDEX IF NOT EXISTS idx_dashboard_owner
    ON dashboard (owner_id);
