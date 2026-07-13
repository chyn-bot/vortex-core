-- 135_print_layout — user-customisable print layouts for transactional
-- documents (quotations, invoices, …).
--
-- Two tables:
--   * doc_layout          — company branding shared by every printed
--                           document (logo lives in the FileStore under
--                           "company/logo"; colours/fonts/footer here).
--                           Managed at /settings/document-layout.
--   * doc_print_templates — an optional per-document-type QWeb template
--                           body. Absence means the plugin's built-in
--                           default template is used. Managed at
--                           /settings/print-templates.
--
-- The rendering engine is the existing sandboxed template engine in
-- vortex_framework::user_reports (same {{ }} / {% for %} / {% if %}
-- syntax), so no new evaluator and no code execution.

CREATE TABLE IF NOT EXISTS doc_layout (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id   UUID,
    brand_color  TEXT NOT NULL DEFAULT '#0f3460',
    font_family  TEXT NOT NULL DEFAULT 'Helvetica, Arial, sans-serif',
    footer_html  TEXT NOT NULL DEFAULT '',
    paper_size   TEXT NOT NULL DEFAULT 'A4',
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by   UUID
);

CREATE TABLE IF NOT EXISTS doc_print_templates (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    doc_type    TEXT NOT NULL UNIQUE,
    body        TEXT NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by  UUID
);
