-- 010_note_templates — reusable Notes / Terms templates for quotations.
--
-- A template is a named block of rich text (formatting + tables) that a user
-- can drop into a quotation's Notes / Terms field. Applying a template COPIES
-- its body into the quote; editing the quote afterwards never changes the
-- template (copy-on-insert). Templates are maintained under
-- Sales ▸ Configuration ▸ Terms Templates.
CREATE TABLE IF NOT EXISTS sales_note_template (
    id         UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name       VARCHAR(200) NOT NULL,
    -- Sanitized rich-text HTML (same allow-list as quote notes).
    body       TEXT         NOT NULL DEFAULT '',
    active     BOOLEAN      NOT NULL DEFAULT TRUE,
    company_id UUID,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sales_note_template_active
    ON sales_note_template(active);
