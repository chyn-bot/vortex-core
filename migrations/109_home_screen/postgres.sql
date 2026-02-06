-- Home Screen: Announcements and User Shortcuts

CREATE TABLE announcements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title VARCHAR(255) NOT NULL,
    body TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'info',
    is_pinned BOOLEAN NOT NULL DEFAULT false,
    publish_at TIMESTAMPTZ,
    expire_at TIMESTAMPTZ,
    company_id UUID NOT NULL REFERENCES companies(id),
    created_by UUID NOT NULL REFERENCES users(id),
    updated_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    active BOOLEAN NOT NULL DEFAULT true,
    CONSTRAINT chk_announcement_severity CHECK (severity IN ('info', 'success', 'warning', 'error'))
);

CREATE INDEX idx_announcements_company ON announcements(company_id);
CREATE INDEX idx_announcements_active ON announcements(company_id, active) WHERE active = true;
CREATE INDEX idx_announcements_publish ON announcements(publish_at) WHERE publish_at IS NOT NULL;

CREATE TABLE user_shortcuts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label VARCHAR(100) NOT NULL,
    url VARCHAR(1000) NOT NULL,
    icon VARCHAR(50) DEFAULT 'link',
    color VARCHAR(30) DEFAULT 'primary',
    sequence INTEGER NOT NULL DEFAULT 10,
    is_custom BOOLEAN NOT NULL DEFAULT false,
    company_id UUID NOT NULL REFERENCES companies(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    active BOOLEAN NOT NULL DEFAULT true
);

CREATE INDEX idx_user_shortcuts_user ON user_shortcuts(user_id);
CREATE INDEX idx_user_shortcuts_active ON user_shortcuts(user_id, active) WHERE active = true;
