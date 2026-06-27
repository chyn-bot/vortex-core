-- Access Control System for Microsoft SQL Server
-- Enterprise access management
-- Implements Odoo-style three-tier access control

-- ============================================================================
-- MODEL ACCESS (like ir.model.access)
-- Controls which roles can perform CRUD operations on which models
-- ============================================================================
CREATE TABLE model_access (
    id UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
    model_name NVARCHAR(255) NOT NULL,
    role_id UNIQUEIDENTIFIER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    perm_read BIT NOT NULL DEFAULT 0,
    perm_write BIT NOT NULL DEFAULT 0,
    perm_create BIT NOT NULL DEFAULT 0,
    perm_delete BIT NOT NULL DEFAULT 0,
    company_id UNIQUEIDENTIFIER REFERENCES companies(id) ON DELETE CASCADE,
    active BIT NOT NULL DEFAULT 1,
    created_at DATETIMEOFFSET NOT NULL DEFAULT GETUTCDATE(),
    updated_at DATETIMEOFFSET NOT NULL DEFAULT GETUTCDATE(),
    CONSTRAINT uq_model_access UNIQUE(model_name, role_id, company_id)
);

CREATE INDEX idx_model_access_model ON model_access(model_name);
CREATE INDEX idx_model_access_role ON model_access(role_id);
CREATE INDEX idx_model_access_company ON model_access(company_id);
CREATE INDEX idx_model_access_active ON model_access(active) WHERE active = 1;
GO

-- Trigger for updated_at
CREATE TRIGGER tr_model_access_updated_at ON model_access
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;
    UPDATE model_access
    SET updated_at = GETUTCDATE()
    FROM model_access m
    INNER JOIN inserted i ON m.id = i.id;
END;
GO

-- ============================================================================
-- RECORD RULES (like ir.rule)
-- Domain-based filtering to control which records a role can access
-- ============================================================================
CREATE TABLE record_rules (
    id UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
    name NVARCHAR(255) NOT NULL,
    model_name NVARCHAR(255) NOT NULL,
    domain_expression NVARCHAR(MAX) NOT NULL,
    role_id UNIQUEIDENTIFIER REFERENCES roles(id) ON DELETE CASCADE,  -- NULL = global rule
    perm_read BIT NOT NULL DEFAULT 1,
    perm_write BIT NOT NULL DEFAULT 1,
    perm_create BIT NOT NULL DEFAULT 1,
    perm_delete BIT NOT NULL DEFAULT 1,
    is_global BIT NOT NULL DEFAULT 0,
    priority INT NOT NULL DEFAULT 0,
    active BIT NOT NULL DEFAULT 1,
    company_id UNIQUEIDENTIFIER REFERENCES companies(id) ON DELETE CASCADE,
    created_at DATETIMEOFFSET NOT NULL DEFAULT GETUTCDATE(),
    updated_at DATETIMEOFFSET NOT NULL DEFAULT GETUTCDATE()
);

CREATE INDEX idx_record_rules_model ON record_rules(model_name);
CREATE INDEX idx_record_rules_role ON record_rules(role_id);
CREATE INDEX idx_record_rules_company ON record_rules(company_id);
CREATE INDEX idx_record_rules_global ON record_rules(is_global) WHERE is_global = 1;
CREATE INDEX idx_record_rules_active ON record_rules(active) WHERE active = 1;
CREATE INDEX idx_record_rules_priority ON record_rules(priority DESC);
GO

-- Trigger for updated_at
CREATE TRIGGER tr_record_rules_updated_at ON record_rules
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;
    UPDATE record_rules
    SET updated_at = GETUTCDATE()
    FROM record_rules r
    INNER JOIN inserted i ON r.id = i.id;
END;
GO

-- ============================================================================
-- FIELD ACCESS
-- Controls which fields are readable/writable by which roles
-- ============================================================================
CREATE TABLE field_access (
    id UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
    model_name NVARCHAR(255) NOT NULL,
    field_name NVARCHAR(255) NOT NULL,
    role_id UNIQUEIDENTIFIER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    readable BIT NOT NULL DEFAULT 1,
    writable BIT NOT NULL DEFAULT 1,
    company_id UNIQUEIDENTIFIER REFERENCES companies(id) ON DELETE CASCADE,
    active BIT NOT NULL DEFAULT 1,
    created_at DATETIMEOFFSET NOT NULL DEFAULT GETUTCDATE(),
    updated_at DATETIMEOFFSET NOT NULL DEFAULT GETUTCDATE(),
    CONSTRAINT uq_field_access UNIQUE(model_name, field_name, role_id, company_id)
);

CREATE INDEX idx_field_access_model ON field_access(model_name);
CREATE INDEX idx_field_access_model_field ON field_access(model_name, field_name);
CREATE INDEX idx_field_access_role ON field_access(role_id);
CREATE INDEX idx_field_access_company ON field_access(company_id);
GO

-- Trigger for updated_at
CREATE TRIGGER tr_field_access_updated_at ON field_access
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;
    UPDATE field_access
    SET updated_at = GETUTCDATE()
    FROM field_access f
    INNER JOIN inserted i ON f.id = i.id;
END;
GO

-- ============================================================================
-- DEFAULT MODEL ACCESS RULES
-- ============================================================================

-- System Administrator (full access to all models)
INSERT INTO model_access (model_name, role_id, perm_read, perm_write, perm_create, perm_delete)
VALUES
    ('users', '00000000-0000-0000-0000-000000000001', 1, 1, 1, 1),
    ('roles', '00000000-0000-0000-0000-000000000001', 1, 1, 1, 1),
    ('companies', '00000000-0000-0000-0000-000000000001', 1, 1, 1, 1),
    ('audit_log', '00000000-0000-0000-0000-000000000001', 1, 0, 0, 0),
    ('model_access', '00000000-0000-0000-0000-000000000001', 1, 1, 1, 1),
    ('record_rules', '00000000-0000-0000-0000-000000000001', 1, 1, 1, 1),
    ('field_access', '00000000-0000-0000-0000-000000000001', 1, 1, 1, 1);

-- Administrator (company-level admin)
INSERT INTO model_access (model_name, role_id, perm_read, perm_write, perm_create, perm_delete)
VALUES
    ('users', '00000000-0000-0000-0000-000000000002', 1, 1, 1, 0),
    ('roles', '00000000-0000-0000-0000-000000000002', 1, 0, 0, 0),
    ('companies', '00000000-0000-0000-0000-000000000002', 1, 0, 0, 0),
    ('audit_log', '00000000-0000-0000-0000-000000000002', 1, 0, 0, 0);

-- User (standard access)
INSERT INTO model_access (model_name, role_id, perm_read, perm_write, perm_create, perm_delete)
VALUES
    ('users', '00000000-0000-0000-0000-000000000003', 1, 0, 0, 0);

-- ============================================================================
-- DEFAULT RECORD RULES
-- ============================================================================

-- Global multi-tenant rule for users table
INSERT INTO record_rules (name, model_name, domain_expression, is_global, priority)
VALUES
    ('multi_tenant_users', 'users', '[("company_id", "=", current_company)]', 1, 100);

-- Global multi-tenant rule for roles (company-specific roles only)
INSERT INTO record_rules (name, model_name, domain_expression, is_global, priority)
VALUES
    ('multi_tenant_roles', 'roles', '["|", ("company_id", "=", current_company), ("company_id", "=", null)]', 1, 100);

-- User self-read rule (users can always read their own record)
INSERT INTO record_rules (name, model_name, domain_expression, role_id, priority)
VALUES
    ('user_self_read', 'users', '[("id", "=", current_user)]', '00000000-0000-0000-0000-000000000003', 50);

-- ============================================================================
-- DEFAULT FIELD ACCESS RULES
-- ============================================================================

-- Hide password_hash from regular users
INSERT INTO field_access (model_name, field_name, role_id, readable, writable)
VALUES
    ('users', 'password_hash', '00000000-0000-0000-0000-000000000003', 0, 0),
    ('users', 'mfa_secret', '00000000-0000-0000-0000-000000000003', 0, 0);

-- Admin can read but not write password_hash directly
INSERT INTO field_access (model_name, field_name, role_id, readable, writable)
VALUES
    ('users', 'password_hash', '00000000-0000-0000-0000-000000000002', 0, 0),
    ('users', 'mfa_secret', '00000000-0000-0000-0000-000000000002', 0, 0);

-- ============================================================================
-- AUDIT LOG ENTRY
-- ============================================================================
INSERT INTO audit_log (
    company_id,
    action,
    resource_type,
    details,
    cip_requirement,
    security_level
) VALUES (
    '00000000-0000-0000-0000-000000000001',
    'ACCESS_CONTROL_INITIALIZED',
    'system',
    '{"version": "0.1.0", "migration": "002_access_control"}',
    'CIP-004-7 R4',
    'HIGH'
);
