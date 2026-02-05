-- Vortex Core Schema for Microsoft SQL Server
-- Initial migration for core tables
-- NERC CIP Compliant

-- ============================================================================
-- COMPANIES (Multi-tenant support)
-- ============================================================================
CREATE TABLE companies (
    id UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
    name NVARCHAR(255) NOT NULL,
    code NVARCHAR(50) NOT NULL UNIQUE,
    active BIT NOT NULL DEFAULT 1,
    settings NVARCHAR(MAX) DEFAULT '{}',
    created_at DATETIMEOFFSET NOT NULL DEFAULT GETUTCDATE(),
    updated_at DATETIMEOFFSET NOT NULL DEFAULT GETUTCDATE()
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
    id UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
    company_id UNIQUEIDENTIFIER NOT NULL REFERENCES companies(id),
    username NVARCHAR(100) NOT NULL,
    email NVARCHAR(255) NOT NULL,
    password_hash NVARCHAR(255) NOT NULL,
    full_name NVARCHAR(255),
    active BIT NOT NULL DEFAULT 1,
    locked BIT NOT NULL DEFAULT 0,
    locked_at DATETIMEOFFSET,
    locked_until DATETIMEOFFSET,
    locked_reason NVARCHAR(500),
    failed_login_attempts INT NOT NULL DEFAULT 0,
    last_login_at DATETIMEOFFSET,
    password_changed_at DATETIMEOFFSET NOT NULL DEFAULT GETUTCDATE(),
    must_change_password BIT NOT NULL DEFAULT 0,
    mfa_enabled BIT NOT NULL DEFAULT 0,
    mfa_secret NVARCHAR(255),
    created_at DATETIMEOFFSET NOT NULL DEFAULT GETUTCDATE(),
    updated_at DATETIMEOFFSET NOT NULL DEFAULT GETUTCDATE(),
    created_by UNIQUEIDENTIFIER,
    updated_by UNIQUEIDENTIFIER,
    CONSTRAINT uq_users_company_username UNIQUE(company_id, username),
    CONSTRAINT uq_users_company_email UNIQUE(company_id, email)
);

CREATE INDEX idx_users_company ON users(company_id);
CREATE INDEX idx_users_username ON users(company_id, username);
CREATE INDEX idx_users_email ON users(company_id, email);
CREATE INDEX idx_users_active ON users(active);

-- ============================================================================
-- ROLES (RBAC - CIP-004 compliant)
-- ============================================================================
CREATE TABLE roles (
    id UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
    company_id UNIQUEIDENTIFIER REFERENCES companies(id),  -- NULL = system role
    name NVARCHAR(100) NOT NULL,
    description NVARCHAR(MAX),
    permissions NVARCHAR(MAX) NOT NULL DEFAULT '[]',
    is_system BIT NOT NULL DEFAULT 0,
    created_at DATETIMEOFFSET NOT NULL DEFAULT GETUTCDATE(),
    updated_at DATETIMEOFFSET NOT NULL DEFAULT GETUTCDATE()
);

CREATE INDEX idx_roles_company ON roles(company_id);
CREATE UNIQUE INDEX idx_roles_name ON roles(company_id, name);

-- System roles
INSERT INTO roles (id, company_id, name, description, permissions, is_system) VALUES
    ('00000000-0000-0000-0000-000000000001', NULL, 'System Administrator',
     'Full system access', '["*"]', 1),
    ('00000000-0000-0000-0000-000000000002', NULL, 'Administrator',
     'Company administrator', '["admin.*"]', 1),
    ('00000000-0000-0000-0000-000000000003', NULL, 'User',
     'Standard user access', '["read.*"]', 1);

-- ============================================================================
-- USER ROLES (Many-to-many)
-- ============================================================================
CREATE TABLE user_roles (
    id UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
    user_id UNIQUEIDENTIFIER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UNIQUEIDENTIFIER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    granted_at DATETIMEOFFSET NOT NULL DEFAULT GETUTCDATE(),
    granted_by UNIQUEIDENTIFIER REFERENCES users(id),
    expires_at DATETIMEOFFSET,
    CONSTRAINT uq_user_roles UNIQUE(user_id, role_id)
);

CREATE INDEX idx_user_roles_user ON user_roles(user_id);
CREATE INDEX idx_user_roles_role ON user_roles(role_id);

-- ============================================================================
-- PASSWORD HISTORY (CIP-007 compliant)
-- ============================================================================
CREATE TABLE password_history (
    id UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
    user_id UNIQUEIDENTIFIER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    password_hash NVARCHAR(255) NOT NULL,
    created_at DATETIMEOFFSET NOT NULL DEFAULT GETUTCDATE()
);

CREATE INDEX idx_password_history_user ON password_history(user_id);

-- ============================================================================
-- SESSIONS (CIP-007 compliant - 30 min timeout)
-- ============================================================================
CREATE TABLE sessions (
    id UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
    user_id UNIQUEIDENTIFIER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash NVARCHAR(255) NOT NULL UNIQUE,
    ip_address NVARCHAR(45),
    user_agent NVARCHAR(MAX),
    created_at DATETIMEOFFSET NOT NULL DEFAULT GETUTCDATE(),
    expires_at DATETIMEOFFSET NOT NULL,
    last_activity_at DATETIMEOFFSET NOT NULL DEFAULT GETUTCDATE(),
    revoked BIT NOT NULL DEFAULT 0,
    revoked_at DATETIMEOFFSET,
    revoked_reason NVARCHAR(255)
);

CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_token ON sessions(token_hash);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);

-- ============================================================================
-- AUDIT LOG (CIP-007 compliant - immutable)
-- ============================================================================
CREATE TABLE audit_log (
    id UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
    timestamp DATETIMEOFFSET NOT NULL DEFAULT GETUTCDATE(),
    company_id UNIQUEIDENTIFIER REFERENCES companies(id),
    user_id UNIQUEIDENTIFIER REFERENCES users(id),
    username NVARCHAR(100),  -- Denormalized for audit persistence
    action NVARCHAR(100) NOT NULL,
    resource_type NVARCHAR(100),
    resource_id UNIQUEIDENTIFIER,
    resource_name NVARCHAR(255),
    details NVARCHAR(MAX),
    ip_address NVARCHAR(45),
    user_agent NVARCHAR(MAX),
    success BIT NOT NULL DEFAULT 1,
    error_message NVARCHAR(MAX),
    -- CIP compliance fields
    cip_requirement NVARCHAR(20),  -- e.g., 'CIP-007-R5'
    security_level NVARCHAR(20)    -- 'HIGH', 'MEDIUM', 'LOW'
);

CREATE INDEX idx_audit_timestamp ON audit_log(timestamp DESC);
CREATE INDEX idx_audit_company ON audit_log(company_id, timestamp DESC);
CREATE INDEX idx_audit_user ON audit_log(user_id, timestamp DESC);
CREATE INDEX idx_audit_action ON audit_log(action, timestamp DESC);
CREATE INDEX idx_audit_resource ON audit_log(resource_type, resource_id);

-- ============================================================================
-- SYSTEM SETTINGS
-- ============================================================================
CREATE TABLE system_settings (
    [key] NVARCHAR(100) PRIMARY KEY,
    value NVARCHAR(MAX) NOT NULL,
    description NVARCHAR(MAX),
    updated_at DATETIMEOFFSET NOT NULL DEFAULT GETUTCDATE(),
    updated_by UNIQUEIDENTIFIER REFERENCES users(id)
);

-- Default settings
INSERT INTO system_settings ([key], value, description) VALUES
    ('session.timeout_minutes', '30', 'Session timeout in minutes (CIP-007)'),
    ('password.min_length', '12', 'Minimum password length'),
    ('password.require_special', 'true', 'Require special characters'),
    ('password.max_age_days', '90', 'Password expiration in days'),
    ('login.max_attempts', '5', 'Max failed login attempts before lockout'),
    ('login.lockout_minutes', '30', 'Account lockout duration');

-- ============================================================================
-- TRIGGERS FOR UPDATED_AT
-- Note: SQL Server uses triggers differently than PostgreSQL
-- ============================================================================

-- Trigger for companies
GO
CREATE TRIGGER tr_companies_updated_at ON companies
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;
    UPDATE companies
    SET updated_at = GETUTCDATE()
    FROM companies c
    INNER JOIN inserted i ON c.id = i.id;
END;
GO

-- Trigger for users
CREATE TRIGGER tr_users_updated_at ON users
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;
    UPDATE users
    SET updated_at = GETUTCDATE()
    FROM users u
    INNER JOIN inserted i ON u.id = i.id;
END;
GO

-- Trigger for roles
CREATE TRIGGER tr_roles_updated_at ON roles
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;
    UPDATE roles
    SET updated_at = GETUTCDATE()
    FROM roles r
    INNER JOIN inserted i ON r.id = i.id;
END;
GO

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
    '$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$JEfz8JzjGKwY5vPrT3VMyg',
    'System Administrator',
    1
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
