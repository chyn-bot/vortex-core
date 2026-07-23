-- Report Studio — banded, pixel-perfect report layouts.
--
-- A banded report reuses the shared `ir_report` authoring row (model, roles,
-- filters, row limit) but carries its layout as a JSONB document rather than a
-- tabular column list. The document (page geometry + bands + XY-positioned
-- elements + expressions/variables) is authored by the Report Studio canvas and
-- rendered deterministically to HTML/PDF. `report_type` is a free VARCHAR in
-- `ir_report`, so no constraint change is needed to introduce the 'banded'
-- shape — only this side table.

CREATE TABLE IF NOT EXISTS ir_report_layout (
    report_id   UUID PRIMARY KEY REFERENCES ir_report(id) ON DELETE CASCADE,
    document    JSONB       NOT NULL DEFAULT '{}'::jsonb,
    version     INTEGER     NOT NULL DEFAULT 1,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by  UUID        REFERENCES users(id) ON DELETE SET NULL
);

COMMENT ON TABLE ir_report_layout IS
    'Banded report layout documents (Report Studio). One row per ir_report whose report_type = ''banded''.';
COMMENT ON COLUMN ir_report_layout.document IS
    'ReportLayout JSON: unit, page{size,orientation,width,height,margin,columns}, dataset{model,sort,groups}, params, variables, bands{title,pageHeader,columnHeader,groupHeaders,detail,groupFooters,columnFooter,pageFooter,summary}.';
