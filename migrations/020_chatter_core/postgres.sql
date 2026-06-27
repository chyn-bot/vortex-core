-- Chatter System Core Tables
-- Provides Odoo-like messaging, activities, and notifications on any record

-- Activity types (configurable categories for scheduled activities)
CREATE TABLE chatter_activity_types (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    summary VARCHAR(255),
    icon VARCHAR(50) DEFAULT 'clock',
    color VARCHAR(20) DEFAULT 'primary',
    default_days INTEGER DEFAULT 1,
    res_model VARCHAR(255),  -- Optional: restrict to specific model
    sequence INTEGER DEFAULT 10,
    company_id UUID REFERENCES companies(id),  -- NULL = global
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_chatter_activity_types_active ON chatter_activity_types(active) WHERE active = true;

-- Seed default activity types
INSERT INTO chatter_activity_types (id, name, summary, icon, color, default_days, sequence) VALUES
    ('a0000000-0000-0000-0000-000000000001', 'To Do', 'Generic task to complete', 'check-circle', 'primary', 1, 10),
    ('a0000000-0000-0000-0000-000000000002', 'Call', 'Schedule a phone call', 'phone', 'info', 1, 20),
    ('a0000000-0000-0000-0000-000000000003', 'Meeting', 'Schedule a meeting', 'users', 'secondary', 3, 30),
    ('a0000000-0000-0000-0000-000000000004', 'Email', 'Send an email', 'mail', 'accent', 1, 40),
    ('a0000000-0000-0000-0000-000000000005', 'Follow Up', 'Follow up on this item', 'arrow-right', 'warning', 7, 50),
    ('a0000000-0000-0000-0000-000000000006', 'Review', 'Review required', 'eye', 'error', 3, 60);

-- Messages and notes on records
CREATE TABLE chatter_messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Polymorphic reference to any model/record
    res_model VARCHAR(255) NOT NULL,
    res_id UUID NOT NULL,
    -- Message content
    message_type VARCHAR(50) NOT NULL DEFAULT 'comment',  -- 'comment', 'note', 'notification', 'system'
    subtype VARCHAR(100),
    subject VARCHAR(500),
    body TEXT NOT NULL,
    body_format VARCHAR(20) DEFAULT 'html',  -- 'html', 'plain', 'markdown'
    -- Author
    author_id UUID NOT NULL REFERENCES users(id),
    -- Threading
    parent_id UUID REFERENCES chatter_messages(id) ON DELETE SET NULL,
    -- Flags
    is_internal BOOLEAN NOT NULL DEFAULT false,
    starred BOOLEAN NOT NULL DEFAULT false,
    pinned BOOLEAN NOT NULL DEFAULT false,
    -- Audit fields
    company_id UUID NOT NULL REFERENCES companies(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID NOT NULL REFERENCES users(id),
    -- Soft delete
    active BOOLEAN NOT NULL DEFAULT true,
    deleted_at TIMESTAMPTZ,
    deleted_by UUID REFERENCES users(id),
    -- Constraint
    CONSTRAINT chk_message_type CHECK (message_type IN ('comment', 'note', 'notification', 'system'))
);

CREATE INDEX idx_chatter_messages_resource ON chatter_messages(res_model, res_id);
CREATE INDEX idx_chatter_messages_author ON chatter_messages(author_id);
CREATE INDEX idx_chatter_messages_parent ON chatter_messages(parent_id);
CREATE INDEX idx_chatter_messages_company ON chatter_messages(company_id);
CREATE INDEX idx_chatter_messages_created ON chatter_messages(created_at DESC);
CREATE INDEX idx_chatter_messages_active ON chatter_messages(res_model, res_id, active) WHERE active = true;

-- Scheduled activities/reminders
CREATE TABLE chatter_activities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Polymorphic reference
    res_model VARCHAR(255) NOT NULL,
    res_id UUID NOT NULL,
    -- Activity details
    activity_type_id UUID NOT NULL REFERENCES chatter_activity_types(id),
    summary VARCHAR(500),
    note TEXT,
    due_date DATE NOT NULL,
    due_time TIME,
    -- Assignment
    assigned_to_id UUID NOT NULL REFERENCES users(id),
    assigned_by_id UUID NOT NULL REFERENCES users(id),
    -- Status
    state VARCHAR(50) NOT NULL DEFAULT 'pending',  -- 'pending', 'completed', 'overdue', 'cancelled'
    completed_at TIMESTAMPTZ,
    completed_by UUID REFERENCES users(id),
    feedback TEXT,
    -- Audit fields
    company_id UUID NOT NULL REFERENCES companies(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID NOT NULL REFERENCES users(id),
    active BOOLEAN NOT NULL DEFAULT true,
    -- Constraint
    CONSTRAINT chk_activity_state CHECK (state IN ('pending', 'completed', 'overdue', 'cancelled'))
);

CREATE INDEX idx_chatter_activities_resource ON chatter_activities(res_model, res_id);
CREATE INDEX idx_chatter_activities_assigned ON chatter_activities(assigned_to_id);
CREATE INDEX idx_chatter_activities_due ON chatter_activities(due_date, state);
CREATE INDEX idx_chatter_activities_state ON chatter_activities(state) WHERE state = 'pending';
CREATE INDEX idx_chatter_activities_company ON chatter_activities(company_id);

-- Follower subscriptions
CREATE TABLE chatter_followers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Polymorphic reference
    res_model VARCHAR(255) NOT NULL,
    res_id UUID NOT NULL,
    -- Follower
    user_id UUID NOT NULL REFERENCES users(id),
    -- Subscription settings
    subtype_ids JSONB DEFAULT '[]',  -- Array of subtypes to receive (empty = all)
    reason VARCHAR(255),  -- Why following: 'creator', 'assigned', 'mentioned', 'manual'
    -- Audit
    company_id UUID NOT NULL REFERENCES companies(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    active BOOLEAN NOT NULL DEFAULT true,
    -- Unique constraint
    CONSTRAINT uq_chatter_followers UNIQUE(res_model, res_id, user_id)
);

CREATE INDEX idx_chatter_followers_resource ON chatter_followers(res_model, res_id);
CREATE INDEX idx_chatter_followers_user ON chatter_followers(user_id);

-- File attachments
CREATE TABLE chatter_attachments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Can attach to message OR directly to record
    message_id UUID REFERENCES chatter_messages(id) ON DELETE CASCADE,
    -- Or directly to a record
    res_model VARCHAR(255),
    res_id UUID,
    -- File info
    name VARCHAR(255) NOT NULL,
    file_name VARCHAR(255) NOT NULL,
    file_path VARCHAR(1000) NOT NULL,
    file_size BIGINT NOT NULL,
    mime_type VARCHAR(255),
    checksum VARCHAR(64),  -- SHA-256 for audit integrity verification
    -- Metadata
    description TEXT,
    -- Audit
    company_id UUID NOT NULL REFERENCES companies(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID NOT NULL REFERENCES users(id),
    active BOOLEAN NOT NULL DEFAULT true,
    -- Ensure attachment belongs to either message or record (not both, not neither)
    CONSTRAINT chk_attachment_target CHECK (
        (message_id IS NOT NULL AND res_model IS NULL AND res_id IS NULL) OR
        (message_id IS NULL AND res_model IS NOT NULL AND res_id IS NOT NULL)
    )
);

CREATE INDEX idx_chatter_attachments_message ON chatter_attachments(message_id);
CREATE INDEX idx_chatter_attachments_resource ON chatter_attachments(res_model, res_id);

-- @mentions linking messages to users
CREATE TABLE chatter_mentions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    message_id UUID NOT NULL REFERENCES chatter_messages(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id),
    -- Notification tracking
    notified BOOLEAN NOT NULL DEFAULT false,
    notified_at TIMESTAMPTZ,
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Unique constraint
    CONSTRAINT uq_chatter_mentions UNIQUE(message_id, user_id)
);

CREATE INDEX idx_chatter_mentions_message ON chatter_mentions(message_id);
CREATE INDEX idx_chatter_mentions_user ON chatter_mentions(user_id);

-- In-app notifications
CREATE TABLE chatter_notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id),
    -- Source (one of these)
    message_id UUID REFERENCES chatter_messages(id) ON DELETE CASCADE,
    activity_id UUID REFERENCES chatter_activities(id) ON DELETE CASCADE,
    -- Notification details
    notification_type VARCHAR(50) NOT NULL,  -- 'message', 'mention', 'activity', 'follow'
    title VARCHAR(255) NOT NULL,
    body TEXT,
    -- Target (for navigation)
    res_model VARCHAR(255) NOT NULL,
    res_id UUID NOT NULL,
    -- Status
    is_read BOOLEAN NOT NULL DEFAULT false,
    read_at TIMESTAMPTZ,
    -- Audit
    company_id UUID NOT NULL REFERENCES companies(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    active BOOLEAN NOT NULL DEFAULT true,
    -- Constraint
    CONSTRAINT chk_notification_type CHECK (notification_type IN ('message', 'mention', 'activity', 'follow'))
);

CREATE INDEX idx_chatter_notifications_user ON chatter_notifications(user_id, is_read);
CREATE INDEX idx_chatter_notifications_unread ON chatter_notifications(user_id, created_at DESC) WHERE is_read = false;
CREATE INDEX idx_chatter_notifications_resource ON chatter_notifications(res_model, res_id);

-- Function to update activity state to 'overdue' (can be called by cron)
CREATE OR REPLACE FUNCTION update_overdue_activities() RETURNS void AS $$
BEGIN
    UPDATE chatter_activities
    SET state = 'overdue', updated_at = NOW()
    WHERE state = 'pending'
      AND due_date < CURRENT_DATE
      AND active = true;
END;
$$ LANGUAGE plpgsql;
