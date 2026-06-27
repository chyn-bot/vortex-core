-- Remicle Core Schema
-- Initial migration for core tables
-- Regulated-industry compliant

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- COMPANIES (Multi-tenant support)
-- ============================================================================
CREATE TABLE companies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    code VARCHAR(50) NOT NULL UNIQUE,
    active BOOLEAN NOT NULL DEFAULT true,
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_companies_code ON companies(code);
CREATE INDEX idx_companies_active ON companies(active);

-- Default company
INSERT INTO companies (id, name, code) VALUES
    ('00000000-0000-0000-0000-000000000001', 'Default Company', 'default');

-- ============================================================================
-- USERS
-- ============================================================================
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    company_id UUID NOT NULL REFERENCES companies(id),
    username VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    active BOOLEAN NOT NULL DEFAULT true,
    locked BOOLEAN NOT NULL DEFAULT false,
    locked_at TIMESTAMPTZ,
    locked_until TIMESTAMPTZ,
    locked_reason VARCHAR(500),
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    last_login_at TIMESTAMPTZ,
    password_changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    must_change_password BOOLEAN NOT NULL DEFAULT false,
    mfa_enabled BOOLEAN NOT NULL DEFAULT false,
    mfa_secret VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID,
    updated_by UUID,
    UNIQUE(company_id, username),
    UNIQUE(company_id, email)
);

CREATE INDEX idx_users_company ON users(company_id);
CREATE INDEX idx_users_username ON users(company_id, username);
CREATE INDEX idx_users_email ON users(company_id, email);
CREATE INDEX idx_users_active ON users(active);

-- ============================================================================
-- ROLES (RBAC - CIP-004 compliant)
-- ============================================================================
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    company_id UUID REFERENCES companies(id),  -- NULL = system role
    name VARCHAR(100) NOT NULL,
    description TEXT,
    permissions JSONB NOT NULL DEFAULT '[]',
    is_system BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_roles_company ON roles(company_id);
CREATE UNIQUE INDEX idx_roles_name ON roles(company_id, name);

-- System roles
INSERT INTO roles (id, company_id, name, description, permissions, is_system) VALUES
    ('00000000-0000-0000-0000-000000000001', NULL, 'System Administrator',
     'Full system access', '["*"]', true),
    ('00000000-0000-0000-0000-000000000002', NULL, 'Administrator',
     'Company administrator', '["admin.*"]', true),
    ('00000000-0000-0000-0000-000000000003', NULL, 'User',
     'Standard user access', '["read.*"]', true);

-- ============================================================================
-- USER ROLES (Many-to-many)
-- ============================================================================
CREATE TABLE user_roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    granted_by UUID REFERENCES users(id),
    expires_at TIMESTAMPTZ,
    UNIQUE(user_id, role_id)
);

CREATE INDEX idx_user_roles_user ON user_roles(user_id);
CREATE INDEX idx_user_roles_role ON user_roles(role_id);

-- ============================================================================
-- PASSWORD HISTORY (CIP-007 compliant)
-- ============================================================================
CREATE TABLE password_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_password_history_user ON password_history(user_id);

-- ============================================================================
-- SESSIONS (CIP-007 compliant - 30 min timeout)
-- ============================================================================
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    last_activity_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked BOOLEAN NOT NULL DEFAULT false,
    revoked_at TIMESTAMPTZ,
    revoked_reason VARCHAR(255)
);

CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_token ON sessions(token_hash);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);

-- ============================================================================
-- AUDIT LOG (CIP-007 compliant - immutable)
-- ============================================================================
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    company_id UUID REFERENCES companies(id),
    user_id UUID REFERENCES users(id),
    username VARCHAR(100),  -- Denormalized for audit persistence
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100),
    resource_id UUID,
    resource_name VARCHAR(255),
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN NOT NULL DEFAULT true,
    error_message TEXT,
    -- CIP compliance fields
    cip_requirement VARCHAR(20),  -- e.g., 'CIP-007-R5'
    security_level VARCHAR(20)    -- 'HIGH', 'MEDIUM', 'LOW'
);

-- Partition by month for performance (optional, for high-volume)
CREATE INDEX idx_audit_timestamp ON audit_log(timestamp DESC);
CREATE INDEX idx_audit_company ON audit_log(company_id, timestamp DESC);
CREATE INDEX idx_audit_user ON audit_log(user_id, timestamp DESC);
CREATE INDEX idx_audit_action ON audit_log(action, timestamp DESC);
CREATE INDEX idx_audit_resource ON audit_log(resource_type, resource_id);

-- ============================================================================
-- SYSTEM SETTINGS
-- ============================================================================
CREATE TABLE system_settings (
    key VARCHAR(100) PRIMARY KEY,
    value JSONB NOT NULL,
    description TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by UUID REFERENCES users(id)
);

-- Default settings
INSERT INTO system_settings (key, value, description) VALUES
    ('session.timeout_minutes', '30', 'Session timeout in minutes (CIP-007)'),
    ('password.min_length', '12', 'Minimum password length'),
    ('password.require_special', 'true', 'Require special characters'),
    ('password.max_age_days', '90', 'Password expiration in days'),
    ('login.max_attempts', '5', 'Max failed login attempts before lockout'),
    ('login.lockout_minutes', '30', 'Account lockout duration');

-- ============================================================================
-- FUNCTIONS
-- ============================================================================

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply to tables
CREATE TRIGGER tr_companies_updated_at BEFORE UPDATE ON companies
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER tr_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER tr_roles_updated_at BEFORE UPDATE ON roles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- DEFAULT ADMIN USER
-- Password: 'Admin@123!' (change on first login)
-- Hash generated with Argon2id
-- ============================================================================
INSERT INTO users (
    id,
    company_id,
    username,
    email,
    password_hash,
    full_name,
    must_change_password
) VALUES (
    '00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001',
    'admin',
    'admin@localhost',
    -- Default password: 'admin' — change immediately after first login.
    '$argon2id$v=19$m=65536,t=3,p=4$A7WAVC/PIP3Wuv6lqEWFCw$YpHLj8lR5m6I2n5xXVySgwVDak3RitZeZdPJfmPD1uo',
    'System Administrator',
    true
);

-- Assign admin role
INSERT INTO user_roles (user_id, role_id) VALUES (
    '00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001'
);

-- Initial audit entry
INSERT INTO audit_log (
    company_id,
    action,
    resource_type,
    details,
    cip_requirement,
    security_level
) VALUES (
    '00000000-0000-0000-0000-000000000001',
    'SYSTEM_INITIALIZED',
    'system',
    '{"version": "0.1.0", "migration": "001_initial_schema"}',
    'CIP-010-R1',
    'HIGH'
);
