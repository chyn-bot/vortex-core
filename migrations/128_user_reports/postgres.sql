-- User-authored reports (QWeb-like). Two shapes share one definition row:
--   tabular  — pick model + columns + filters + group-by + aggregates; the
--              engine builds safe SQL and renders a table (HTML/CSV/JSON).
--   template — an authored HTML template rendered with a sandboxed mini-syntax
--              ({{ field }}, {% for r in records %}, {% if %}); data escaped.
-- Authoring is gated to admins + the seeded "Report Author" role; running a
-- report can be further gated per-report via required_role.
CREATE TABLE IF NOT EXISTS ir_report (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code          VARCHAR(100) UNIQUE NOT NULL,
    name          VARCHAR(150) NOT NULL,
    description   TEXT,
    model_name    VARCHAR(100) NOT NULL,             -- ir_model.name
    report_type   VARCHAR(20)  NOT NULL DEFAULT 'tabular',  -- tabular|template
    sort_field    VARCHAR(100),
    sort_dir      VARCHAR(4)   NOT NULL DEFAULT 'asc',      -- asc|desc
    group_field   VARCHAR(100),                            -- tabular grouping
    template      TEXT,                                     -- template shape
    paper_size    VARCHAR(10)  NOT NULL DEFAULT 'A4',
    orientation   VARCHAR(10)  NOT NULL DEFAULT 'portrait',
    required_role VARCHAR(100),                            -- null = any user may run
    row_limit     INTEGER      NOT NULL DEFAULT 1000,
    sequence      INTEGER      NOT NULL DEFAULT 10,
    active        BOOLEAN      NOT NULL DEFAULT true,
    created_by    UUID,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ir_report_model ON ir_report(model_name);

-- Selected columns for a tabular report, in display order. aggregate != 'none'
-- turns the column into a per-group / grand-total measure.
CREATE TABLE IF NOT EXISTS ir_report_column (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id  UUID NOT NULL REFERENCES ir_report(id) ON DELETE CASCADE,
    field      VARCHAR(100) NOT NULL,
    label      VARCHAR(150),
    aggregate  VARCHAR(10)  NOT NULL DEFAULT 'none',  -- none|sum|avg|count|min|max
    sequence   INTEGER      NOT NULL DEFAULT 10
);
CREATE INDEX IF NOT EXISTS idx_ir_report_column_report ON ir_report_column(report_id, sequence);

-- Filter conditions ANDed together. value is bound as a parameter; field and
-- operator are validated against allow-lists before they touch SQL.
CREATE TABLE IF NOT EXISTS ir_report_filter (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id  UUID NOT NULL REFERENCES ir_report(id) ON DELETE CASCADE,
    field      VARCHAR(100) NOT NULL,
    operator   VARCHAR(10)  NOT NULL DEFAULT '=',     -- = != ilike > < >= <=
    value      TEXT,
    sequence   INTEGER      NOT NULL DEFAULT 10
);
CREATE INDEX IF NOT EXISTS idx_ir_report_filter_report ON ir_report_filter(report_id, sequence);

-- Seed the "Report Author" role (non-admin power users who may build reports).
INSERT INTO roles (id, name, description, is_system)
VALUES ('00000000-0000-0000-0000-000000000004', 'Report Author',
        'May create and edit user reports', true)
ON CONFLICT (id) DO NOTHING;
