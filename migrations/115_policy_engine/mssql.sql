-- Migration 115: Policy Engine (Cedar-based ABAC) — MSSQL dialect
--
-- See migrations/115_policy_engine/postgres.sql for the authoritative
-- design rationale.

IF OBJECT_ID('policy_rules', 'U') IS NULL
BEGIN
    CREATE TABLE policy_rules (
        id          UNIQUEIDENTIFIER NOT NULL PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
        name        NVARCHAR(255) NOT NULL,
        description NVARCHAR(MAX),
        policy_text NVARCHAR(MAX) NOT NULL,
        active      BIT NOT NULL DEFAULT 1,
        priority    INT NOT NULL DEFAULT 100,
        company_id  UNIQUEIDENTIFIER NULL,
        created_by  UNIQUEIDENTIFIER NULL,
        created_at  DATETIMEOFFSET NOT NULL DEFAULT SYSUTCDATETIME(),
        updated_at  DATETIMEOFFSET NOT NULL DEFAULT SYSUTCDATETIME(),
        CONSTRAINT uq_policy_rules_name UNIQUE (name),
        CONSTRAINT fk_policy_rules_company FOREIGN KEY (company_id) REFERENCES companies(id),
        CONSTRAINT fk_policy_rules_created_by FOREIGN KEY (created_by) REFERENCES users(id)
    );
END;
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_policy_rules_active' AND object_id = OBJECT_ID('policy_rules'))
    CREATE INDEX idx_policy_rules_active ON policy_rules(active, priority);
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_policy_rules_company' AND object_id = OBJECT_ID('policy_rules'))
    CREATE INDEX idx_policy_rules_company ON policy_rules(company_id, active);
GO

-- Auto-update trigger (T-SQL AFTER UPDATE because MSSQL has no BEFORE triggers).
IF OBJECT_ID('trg_policy_rules_updated_at', 'TR') IS NOT NULL
    DROP TRIGGER trg_policy_rules_updated_at;
GO
CREATE TRIGGER trg_policy_rules_updated_at ON policy_rules
AFTER UPDATE AS
BEGIN
    IF NOT UPDATE(updated_at)
    BEGIN
        UPDATE pr
        SET updated_at = SYSUTCDATETIME()
        FROM policy_rules pr
        INNER JOIN inserted i ON pr.id = i.id;
    END
END;
GO

-- ============================================================================
-- Seed policies
-- ============================================================================
INSERT INTO policy_rules (name, description, policy_text, priority) VALUES
(
    'admins_can_manage_users',
    'System administrators and Administrators can create, update, delete, lock, and unlock any user account.',
    N'permit (principal in Role::"system_administrator", action in [Action::"create", Action::"update", Action::"delete", Action::"lock", Action::"unlock"], resource); permit (principal in Role::"administrator", action in [Action::"create", Action::"update", Action::"delete", Action::"lock", Action::"unlock"], resource);',
    10
),
(
    'self_service_profile_update',
    'Any user can update their own profile (email, full_name, password).',
    N'permit (principal, action == Action::"update", resource) when { principal == resource };',
    20
),
(
    'forbid_delete_system_company',
    'The seeded system company must never be deleted.',
    N'forbid (principal, action == Action::"delete", resource == Company::"00000000-0000-0000-0000-000000000001");',
    1
),
(
    'auditors_can_verify_chain',
    'Users with the auditor role can verify and read the audit chain.',
    N'permit (principal in Role::"auditor", action in [Action::"read", Action::"verify"], resource);',
    40
);
GO

-- System attestation audit entry.
INSERT INTO audit_log (
    user_id, username, action, resource_type, details,
    cip_requirement, security_level, success
) VALUES (
    NULL,
    'system',
    'POLICY_ENGINE_ENABLED',
    'policy_rules',
    '{"migration":"115_policy_engine","engine":"cedar-policy","seed_policies":4}',
    'CIP-004-7 R4',
    'HIGH',
    1
);
GO
