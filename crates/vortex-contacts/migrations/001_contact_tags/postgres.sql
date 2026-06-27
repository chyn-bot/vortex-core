-- Contact tags: a many-to-many tagging system demonstrating
-- plugin-owned schema extensions on top of the core `contacts` table.
-- The core table is owned by migration 010_contacts; this plugin
-- adds metadata without touching the core schema.

CREATE TABLE IF NOT EXISTS contact_tags (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL,
    color VARCHAR(20) DEFAULT '#6B7280',
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (company_id, name)
);

CREATE TABLE IF NOT EXISTS contact_tag_rel (
    contact_id UUID NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    tag_id UUID NOT NULL REFERENCES contact_tags(id) ON DELETE CASCADE,
    PRIMARY KEY (contact_id, tag_id)
);

CREATE INDEX IF NOT EXISTS idx_contact_tag_rel_tag ON contact_tag_rel(tag_id);

COMMENT ON TABLE contact_tags IS 'Contact classification tags — plugin-owned extension on the core contacts table.';

-- Seed a few default tags
INSERT INTO contact_tags (name, color, company_id) VALUES
    ('VIP',        '#EF4444', '00000000-0000-0000-0000-000000000001'),
    ('Supplier',   '#3B82F6', '00000000-0000-0000-0000-000000000001'),
    ('Government', '#8B5CF6', '00000000-0000-0000-0000-000000000001')
ON CONFLICT (company_id, name) DO NOTHING;
