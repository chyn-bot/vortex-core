-- Access Control System
-- Enterprise access management
-- Implements Odoo-style three-tier access control

-- ============================================================================
-- MODEL ACCESS (like ir.model.access)
-- Controls which roles can perform CRUD operations on which models
-- ============================================================================
CREATE TABLE model_access (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    model_name VARCHAR(255) NOT NULL,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    perm_read BOOLEAN NOT NULL DEFAULT false,
    perm_write BOOLEAN NOT NULL DEFAULT false,
    perm_create BOOLEAN NOT NULL DEFAULT false,
    perm_delete BOOLEAN NOT NULL DEFAULT false,
    company_id UUID REFERENCES companies(id) ON DELETE CASCADE,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_model_access UNIQUE(model_name, role_id, company_id)
);

CREATE INDEX idx_model_access_model ON model_access(model_name);
CREATE INDEX idx_model_access_role ON model_access(role_id);
CREATE INDEX idx_model_access_company ON model_access(company_id);
CREATE INDEX idx_model_access_active ON model_access(active) WHERE active = true;

-- Trigger for updated_at
CREATE TRIGGER tr_model_access_updated_at BEFORE UPDATE ON model_access
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- RECORD RULES (like ir.rule)
-- Domain-based filtering to control which records a role can access
-- ============================================================================
CREATE TABLE record_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    model_name VARCHAR(255) NOT NULL,
    domain_expression TEXT NOT NULL,
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,  -- NULL = global rule
    perm_read BOOLEAN NOT NULL DEFAULT true,
    perm_write BOOLEAN NOT NULL DEFAULT true,
    perm_create BOOLEAN NOT NULL DEFAULT true,
    perm_delete BOOLEAN NOT NULL DEFAULT true,
    is_global BOOLEAN NOT NULL DEFAULT false,
    priority INTEGER NOT NULL DEFAULT 0,
    active BOOLEAN NOT NULL DEFAULT true,
    company_id UUID REFERENCES companies(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_record_rules_model ON record_rules(model_name);
CREATE INDEX idx_record_rules_role ON record_rules(role_id);
CREATE INDEX idx_record_rules_company ON record_rules(company_id);
CREATE INDEX idx_record_rules_global ON record_rules(is_global) WHERE is_global = true;
CREATE INDEX idx_record_rules_active ON record_rules(active) WHERE active = true;
CREATE INDEX idx_record_rules_priority ON record_rules(priority DESC);

-- Trigger for updated_at
CREATE TRIGGER tr_record_rules_updated_at BEFORE UPDATE ON record_rules
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- FIELD ACCESS
-- Controls which fields are readable/writable by which roles
-- ============================================================================
CREATE TABLE field_access (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    model_name VARCHAR(255) NOT NULL,
    field_name VARCHAR(255) NOT NULL,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    readable BOOLEAN NOT NULL DEFAULT true,
    writable BOOLEAN NOT NULL DEFAULT true,
    company_id UUID REFERENCES companies(id) ON DELETE CASCADE,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_field_access UNIQUE(model_name, field_name, role_id, company_id)
);

CREATE INDEX idx_field_access_model ON field_access(model_name);
CREATE INDEX idx_field_access_model_field ON field_access(model_name, field_name);
CREATE INDEX idx_field_access_role ON field_access(role_id);
CREATE INDEX idx_field_access_company ON field_access(company_id);

-- Trigger for updated_at
CREATE TRIGGER tr_field_access_updated_at BEFORE UPDATE ON field_access
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- DEFAULT MODEL ACCESS RULES
-- ============================================================================

-- System Administrator (full access to all models)
INSERT INTO model_access (model_name, role_id, perm_read, perm_write, perm_create, perm_delete)
VALUES
    ('users', '00000000-0000-0000-0000-000000000001', true, true, true, true),
    ('roles', '00000000-0000-0000-0000-000000000001', true, true, true, true),
    ('companies', '00000000-0000-0000-0000-000000000001', true, true, true, true),
    ('audit_log', '00000000-0000-0000-0000-000000000001', true, false, false, false),
    ('model_access', '00000000-0000-0000-0000-000000000001', true, true, true, true),
    ('record_rules', '00000000-0000-0000-0000-000000000001', true, true, true, true),
    ('field_access', '00000000-0000-0000-0000-000000000001', true, true, true, true);

-- Administrator (company-level admin)
INSERT INTO model_access (model_name, role_id, perm_read, perm_write, perm_create, perm_delete)
VALUES
    ('users', '00000000-0000-0000-0000-000000000002', true, true, true, false),
    ('roles', '00000000-0000-0000-0000-000000000002', true, false, false, false),
    ('companies', '00000000-0000-0000-0000-000000000002', true, false, false, false),
    ('audit_log', '00000000-0000-0000-0000-000000000002', true, false, false, false);

-- User (standard access)
INSERT INTO model_access (model_name, role_id, perm_read, perm_write, perm_create, perm_delete)
VALUES
    ('users', '00000000-0000-0000-0000-000000000003', true, false, false, false);

-- ============================================================================
-- DEFAULT RECORD RULES
-- ============================================================================

-- Global multi-tenant rule for users table
INSERT INTO record_rules (name, model_name, domain_expression, is_global, priority)
VALUES
    ('multi_tenant_users', 'users', '[("company_id", "=", current_company)]', true, 100);

-- Global multi-tenant rule for roles (company-specific roles only)
INSERT INTO record_rules (name, model_name, domain_expression, is_global, priority)
VALUES
    ('multi_tenant_roles', 'roles', '["|", ("company_id", "=", current_company), ("company_id", "=", null)]', true, 100);

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
    ('users', 'password_hash', '00000000-0000-0000-0000-000000000003', false, false),
    ('users', 'mfa_secret', '00000000-0000-0000-0000-000000000003', false, false);

-- Admin can read but not write password_hash directly
INSERT INTO field_access (model_name, field_name, role_id, readable, writable)
VALUES
    ('users', 'password_hash', '00000000-0000-0000-0000-000000000002', false, false),
    ('users', 'mfa_secret', '00000000-0000-0000-0000-000000000002', false, false);

-- ============================================================================
-- AUDIT LOG ENTRY
-- ============================================================================
INSERT INTO audit_log (
    company_id,
    action,
    resource_type,
    details,
    compliance_category,
    security_level
) VALUES (
    '00000000-0000-0000-0000-000000000001',
    'ACCESS_CONTROL_INITIALIZED',
    'system',
    '{"version": "0.1.0", "migration": "002_access_control"}',
    'authorization',
    'HIGH'
);
