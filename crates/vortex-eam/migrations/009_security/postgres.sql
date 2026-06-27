-- Migration 111: EAM Security Groups and Access Control Rules
-- Implements 4-tier RBAC hierarchy matching Odoo SESB EAM module:
--   User < Officer < Manager < Admin
--
-- User:    Read all EAM data, Create/Edit maintenance and inspections
-- Officer: + Manage equipment, approve inspections, create condition monitoring
-- Manager: + Full CRUD on all operational data
-- Admin:   + Configuration access (manufacturers, voltage levels, templates)

-- ============================================================================
-- EAM SECURITY ROLES
-- ============================================================================

-- Note: These are global roles (company_id IS NULL). The multi-tenant
-- record_rules below handle company-level isolation.

INSERT INTO roles (id, company_id, name, description, permissions, is_system, created_at)
VALUES
    ('a0000000-0000-0000-0000-e00000000001'::uuid, NULL, 'eam_user',
     'EAM User - Read all, Create/Edit maintenance and inspections',
     '{"module": "asset_management", "level": 1}'::jsonb,
     FALSE, NOW()),
    ('a0000000-0000-0000-0000-e00000000002'::uuid, NULL, 'eam_officer',
     'EAM Officer - Manage equipment, approve inspections',
     '{"module": "asset_management", "level": 2}'::jsonb,
     FALSE, NOW()),
    ('a0000000-0000-0000-0000-e00000000003'::uuid, NULL, 'eam_manager',
     'EAM Manager - Full CRUD on all operational data',
     '{"module": "asset_management", "level": 3}'::jsonb,
     FALSE, NOW()),
    ('a0000000-0000-0000-0000-e00000000004'::uuid, NULL, 'eam_admin',
     'EAM Administrator - Configuration access',
     '{"module": "asset_management", "level": 4}'::jsonb,
     FALSE, NOW())
ON CONFLICT DO NOTHING;

-- ============================================================================
-- MODEL ACCESS RULES
-- ============================================================================
-- Mirrors Odoo ir.model.access.csv: (model, role, read, write, create, delete)
-- Higher roles inherit lower role permissions via application-level logic.
-- These rules define the MAXIMUM permissions per role.

-- Helper: Shorthand variables for role IDs
-- eam_user:    a0000000-0000-0000-0000-e00000000001
-- eam_officer: a0000000-0000-0000-0000-e00000000002
-- eam_manager: a0000000-0000-0000-0000-e00000000003
-- eam_admin:   a0000000-0000-0000-0000-e00000000004

-- ---------- Configuration (read-only for users, full for admin) ----------

-- Voltage Levels
INSERT INTO model_access (id, model_name, role_id, perm_read, perm_write, perm_create, perm_delete, company_id) VALUES
    (gen_random_uuid(), 'eam.voltage.level', 'a0000000-0000-0000-0000-e00000000001'::uuid, TRUE, FALSE, FALSE, FALSE, NULL),
    (gen_random_uuid(), 'eam.voltage.level', 'a0000000-0000-0000-0000-e00000000004'::uuid, TRUE, TRUE, TRUE, TRUE, NULL)
ON CONFLICT (model_name, role_id, company_id) DO NOTHING;

-- Manufacturers
INSERT INTO model_access (id, model_name, role_id, perm_read, perm_write, perm_create, perm_delete, company_id) VALUES
    (gen_random_uuid(), 'eam.manufacturer', 'a0000000-0000-0000-0000-e00000000001'::uuid, TRUE, FALSE, FALSE, FALSE, NULL),
    (gen_random_uuid(), 'eam.manufacturer', 'a0000000-0000-0000-0000-e00000000004'::uuid, TRUE, TRUE, TRUE, TRUE, NULL)
ON CONFLICT (model_name, role_id, company_id) DO NOTHING;

-- ---------- Hierarchy (read for users, write for officers, full CRUD for managers) ----------

-- Regions
INSERT INTO model_access (id, model_name, role_id, perm_read, perm_write, perm_create, perm_delete, company_id) VALUES
    (gen_random_uuid(), 'eam.region', 'a0000000-0000-0000-0000-e00000000001'::uuid, TRUE, FALSE, FALSE, FALSE, NULL),
    (gen_random_uuid(), 'eam.region', 'a0000000-0000-0000-0000-e00000000002'::uuid, TRUE, TRUE, FALSE, FALSE, NULL),
    (gen_random_uuid(), 'eam.region', 'a0000000-0000-0000-0000-e00000000003'::uuid, TRUE, TRUE, TRUE, TRUE, NULL)
ON CONFLICT (model_name, role_id, company_id) DO NOTHING;

-- Sites
INSERT INTO model_access (id, model_name, role_id, perm_read, perm_write, perm_create, perm_delete, company_id) VALUES
    (gen_random_uuid(), 'eam.site', 'a0000000-0000-0000-0000-e00000000001'::uuid, TRUE, FALSE, FALSE, FALSE, NULL),
    (gen_random_uuid(), 'eam.site', 'a0000000-0000-0000-0000-e00000000002'::uuid, TRUE, TRUE, FALSE, FALSE, NULL),
    (gen_random_uuid(), 'eam.site', 'a0000000-0000-0000-0000-e00000000003'::uuid, TRUE, TRUE, TRUE, TRUE, NULL)
ON CONFLICT (model_name, role_id, company_id) DO NOTHING;

-- Substations
INSERT INTO model_access (id, model_name, role_id, perm_read, perm_write, perm_create, perm_delete, company_id) VALUES
    (gen_random_uuid(), 'eam.substation', 'a0000000-0000-0000-0000-e00000000001'::uuid, TRUE, FALSE, FALSE, FALSE, NULL),
    (gen_random_uuid(), 'eam.substation', 'a0000000-0000-0000-0000-e00000000002'::uuid, TRUE, TRUE, FALSE, FALSE, NULL),
    (gen_random_uuid(), 'eam.substation', 'a0000000-0000-0000-0000-e00000000003'::uuid, TRUE, TRUE, TRUE, TRUE, NULL)
ON CONFLICT (model_name, role_id, company_id) DO NOTHING;

-- Bays
INSERT INTO model_access (id, model_name, role_id, perm_read, perm_write, perm_create, perm_delete, company_id) VALUES
    (gen_random_uuid(), 'eam.bay', 'a0000000-0000-0000-0000-e00000000001'::uuid, TRUE, FALSE, FALSE, FALSE, NULL),
    (gen_random_uuid(), 'eam.bay', 'a0000000-0000-0000-0000-e00000000002'::uuid, TRUE, TRUE, FALSE, FALSE, NULL),
    (gen_random_uuid(), 'eam.bay', 'a0000000-0000-0000-0000-e00000000003'::uuid, TRUE, TRUE, TRUE, TRUE, NULL)
ON CONFLICT (model_name, role_id, company_id) DO NOTHING;

-- ---------- Equipment (read for users, write+create for officers, full for managers) ----------

-- Equipment base
INSERT INTO model_access (id, model_name, role_id, perm_read, perm_write, perm_create, perm_delete, company_id) VALUES
    (gen_random_uuid(), 'eam.equipment', 'a0000000-0000-0000-0000-e00000000001'::uuid, TRUE, FALSE, FALSE, FALSE, NULL),
    (gen_random_uuid(), 'eam.equipment', 'a0000000-0000-0000-0000-e00000000002'::uuid, TRUE, TRUE, TRUE, FALSE, NULL),
    (gen_random_uuid(), 'eam.equipment', 'a0000000-0000-0000-0000-e00000000003'::uuid, TRUE, TRUE, TRUE, TRUE, NULL)
ON CONFLICT (model_name, role_id, company_id) DO NOTHING;

-- Equipment specializations (all follow same pattern as equipment base)
INSERT INTO model_access (id, model_name, role_id, perm_read, perm_write, perm_create, perm_delete, company_id)
SELECT gen_random_uuid(), m.model_name, r.role_id, r.perm_read, r.perm_write, r.perm_create, r.perm_delete, NULL
FROM (VALUES
    ('eam.equipment.transformer'), ('eam.equipment.switchgear'), ('eam.equipment.rmu'),
    ('eam.equipment.protection'), ('eam.equipment.scada'), ('eam.equipment.battery'),
    ('eam.equipment.feeder_pillar'), ('eam.equipment.ct_vt'), ('eam.equipment.surge_arrester'),
    ('eam.equipment.cable'), ('eam.equipment.busbar'), ('eam.equipment.isolator'),
    ('eam.equipment.earthing')
) AS m(model_name)
CROSS JOIN (VALUES
    ('a0000000-0000-0000-0000-e00000000001'::uuid, TRUE, FALSE, FALSE, FALSE),
    ('a0000000-0000-0000-0000-e00000000002'::uuid, TRUE, TRUE, TRUE, FALSE),
    ('a0000000-0000-0000-0000-e00000000003'::uuid, TRUE, TRUE, TRUE, TRUE)
) AS r(role_id, perm_read, perm_write, perm_create, perm_delete)
ON CONFLICT (model_name, role_id, company_id) DO NOTHING;

-- Components
INSERT INTO model_access (id, model_name, role_id, perm_read, perm_write, perm_create, perm_delete, company_id) VALUES
    (gen_random_uuid(), 'eam.component', 'a0000000-0000-0000-0000-e00000000001'::uuid, TRUE, FALSE, FALSE, FALSE, NULL),
    (gen_random_uuid(), 'eam.component', 'a0000000-0000-0000-0000-e00000000002'::uuid, TRUE, TRUE, TRUE, FALSE, NULL),
    (gen_random_uuid(), 'eam.component', 'a0000000-0000-0000-0000-e00000000003'::uuid, TRUE, TRUE, TRUE, TRUE, NULL)
ON CONFLICT (model_name, role_id, company_id) DO NOTHING;

-- Parts
INSERT INTO model_access (id, model_name, role_id, perm_read, perm_write, perm_create, perm_delete, company_id) VALUES
    (gen_random_uuid(), 'eam.part', 'a0000000-0000-0000-0000-e00000000001'::uuid, TRUE, FALSE, FALSE, FALSE, NULL),
    (gen_random_uuid(), 'eam.part', 'a0000000-0000-0000-0000-e00000000002'::uuid, TRUE, TRUE, TRUE, FALSE, NULL),
    (gen_random_uuid(), 'eam.part', 'a0000000-0000-0000-0000-e00000000003'::uuid, TRUE, TRUE, TRUE, TRUE, NULL)
ON CONFLICT (model_name, role_id, company_id) DO NOTHING;

-- ---------- Maintenance (users can create/edit, managers full CRUD) ----------

-- Maintenance / Work Orders
INSERT INTO model_access (id, model_name, role_id, perm_read, perm_write, perm_create, perm_delete, company_id) VALUES
    (gen_random_uuid(), 'eam.maintenance', 'a0000000-0000-0000-0000-e00000000001'::uuid, TRUE, TRUE, TRUE, FALSE, NULL),
    (gen_random_uuid(), 'eam.maintenance', 'a0000000-0000-0000-0000-e00000000003'::uuid, TRUE, TRUE, TRUE, TRUE, NULL)
ON CONFLICT (model_name, role_id, company_id) DO NOTHING;

-- Inspections (users can create/edit, officers can create/edit, managers full)
INSERT INTO model_access (id, model_name, role_id, perm_read, perm_write, perm_create, perm_delete, company_id) VALUES
    (gen_random_uuid(), 'eam.inspection', 'a0000000-0000-0000-0000-e00000000001'::uuid, TRUE, TRUE, TRUE, FALSE, NULL),
    (gen_random_uuid(), 'eam.inspection', 'a0000000-0000-0000-0000-e00000000002'::uuid, TRUE, TRUE, TRUE, FALSE, NULL),
    (gen_random_uuid(), 'eam.inspection', 'a0000000-0000-0000-0000-e00000000003'::uuid, TRUE, TRUE, TRUE, TRUE, NULL)
ON CONFLICT (model_name, role_id, company_id) DO NOTHING;

-- Condition Monitoring (read for users, write+create for officers, full for managers)
INSERT INTO model_access (id, model_name, role_id, perm_read, perm_write, perm_create, perm_delete, company_id) VALUES
    (gen_random_uuid(), 'eam.condition.monitoring', 'a0000000-0000-0000-0000-e00000000001'::uuid, TRUE, FALSE, FALSE, FALSE, NULL),
    (gen_random_uuid(), 'eam.condition.monitoring', 'a0000000-0000-0000-0000-e00000000002'::uuid, TRUE, TRUE, TRUE, FALSE, NULL),
    (gen_random_uuid(), 'eam.condition.monitoring', 'a0000000-0000-0000-0000-e00000000003'::uuid, TRUE, TRUE, TRUE, TRUE, NULL)
ON CONFLICT (model_name, role_id, company_id) DO NOTHING;

-- ---------- Checklists ----------

-- Checklist Templates (read for users, full for admin)
INSERT INTO model_access (id, model_name, role_id, perm_read, perm_write, perm_create, perm_delete, company_id) VALUES
    (gen_random_uuid(), 'eam.checklist.template', 'a0000000-0000-0000-0000-e00000000001'::uuid, TRUE, FALSE, FALSE, FALSE, NULL),
    (gen_random_uuid(), 'eam.checklist.template', 'a0000000-0000-0000-0000-e00000000004'::uuid, TRUE, TRUE, TRUE, TRUE, NULL)
ON CONFLICT (model_name, role_id, company_id) DO NOTHING;

-- Checklist Template Items (same as templates)
INSERT INTO model_access (id, model_name, role_id, perm_read, perm_write, perm_create, perm_delete, company_id) VALUES
    (gen_random_uuid(), 'eam.checklist.template.item', 'a0000000-0000-0000-0000-e00000000001'::uuid, TRUE, FALSE, FALSE, FALSE, NULL),
    (gen_random_uuid(), 'eam.checklist.template.item', 'a0000000-0000-0000-0000-e00000000004'::uuid, TRUE, TRUE, TRUE, TRUE, NULL)
ON CONFLICT (model_name, role_id, company_id) DO NOTHING;

-- Checklist Lines (users can read/write, officers can create, managers full)
INSERT INTO model_access (id, model_name, role_id, perm_read, perm_write, perm_create, perm_delete, company_id) VALUES
    (gen_random_uuid(), 'eam.checklist.line', 'a0000000-0000-0000-0000-e00000000001'::uuid, TRUE, TRUE, FALSE, FALSE, NULL),
    (gen_random_uuid(), 'eam.checklist.line', 'a0000000-0000-0000-0000-e00000000002'::uuid, TRUE, TRUE, TRUE, FALSE, NULL),
    (gen_random_uuid(), 'eam.checklist.line', 'a0000000-0000-0000-0000-e00000000003'::uuid, TRUE, TRUE, TRUE, TRUE, NULL)
ON CONFLICT (model_name, role_id, company_id) DO NOTHING;

-- Part Lines (users can create/edit, managers full)
INSERT INTO model_access (id, model_name, role_id, perm_read, perm_write, perm_create, perm_delete, company_id) VALUES
    (gen_random_uuid(), 'eam.maintenance.part.line', 'a0000000-0000-0000-0000-e00000000001'::uuid, TRUE, TRUE, TRUE, FALSE, NULL),
    (gen_random_uuid(), 'eam.maintenance.part.line', 'a0000000-0000-0000-0000-e00000000003'::uuid, TRUE, TRUE, TRUE, TRUE, NULL)
ON CONFLICT (model_name, role_id, company_id) DO NOTHING;

-- ---------- Maintenance Plans (read for users, write+create for officers, full for managers) ----------

INSERT INTO model_access (id, model_name, role_id, perm_read, perm_write, perm_create, perm_delete, company_id) VALUES
    (gen_random_uuid(), 'eam.maintenance.plan', 'a0000000-0000-0000-0000-e00000000001'::uuid, TRUE, FALSE, FALSE, FALSE, NULL),
    (gen_random_uuid(), 'eam.maintenance.plan', 'a0000000-0000-0000-0000-e00000000002'::uuid, TRUE, TRUE, TRUE, FALSE, NULL),
    (gen_random_uuid(), 'eam.maintenance.plan', 'a0000000-0000-0000-0000-e00000000003'::uuid, TRUE, TRUE, TRUE, TRUE, NULL)
ON CONFLICT (model_name, role_id, company_id) DO NOTHING;

-- ---------- Transmission (read for users, write+create for officers, full for managers) ----------

INSERT INTO model_access (id, model_name, role_id, perm_read, perm_write, perm_create, perm_delete, company_id) VALUES
    (gen_random_uuid(), 'eam.transmission.line', 'a0000000-0000-0000-0000-e00000000001'::uuid, TRUE, FALSE, FALSE, FALSE, NULL),
    (gen_random_uuid(), 'eam.transmission.line', 'a0000000-0000-0000-0000-e00000000002'::uuid, TRUE, TRUE, TRUE, FALSE, NULL),
    (gen_random_uuid(), 'eam.transmission.line', 'a0000000-0000-0000-0000-e00000000003'::uuid, TRUE, TRUE, TRUE, TRUE, NULL)
ON CONFLICT (model_name, role_id, company_id) DO NOTHING;

INSERT INTO model_access (id, model_name, role_id, perm_read, perm_write, perm_create, perm_delete, company_id) VALUES
    (gen_random_uuid(), 'eam.transmission.tower', 'a0000000-0000-0000-0000-e00000000001'::uuid, TRUE, FALSE, FALSE, FALSE, NULL),
    (gen_random_uuid(), 'eam.transmission.tower', 'a0000000-0000-0000-0000-e00000000002'::uuid, TRUE, TRUE, TRUE, FALSE, NULL),
    (gen_random_uuid(), 'eam.transmission.tower', 'a0000000-0000-0000-0000-e00000000003'::uuid, TRUE, TRUE, TRUE, TRUE, NULL)
ON CONFLICT (model_name, role_id, company_id) DO NOTHING;

-- ============================================================================
-- RECORD RULES (Multi-tenant isolation)
-- ============================================================================
-- Global rule: Users can only see records from their own company.
-- These apply to all roles.

INSERT INTO record_rules (id, name, model_name, domain_expression, role_id, perm_read, perm_write, perm_create, perm_delete, is_global, priority)
SELECT
    gen_random_uuid(),
    'EAM multi-tenant: ' || m.model_name,
    m.model_name,
    '[("company_id", "=", current_company)]',
    NULL,  -- Global rule (applies to all roles)
    TRUE, TRUE, TRUE, TRUE,
    TRUE,  -- is_global
    10     -- Default priority
FROM (VALUES
    ('eam.region'), ('eam.site'), ('eam.substation'), ('eam.bay'),
    ('eam.equipment'), ('eam.maintenance'), ('eam.inspection'),
    ('eam.condition.monitoring'), ('eam.checklist.template'),
    ('eam.maintenance.plan'), ('eam.transmission.line'), ('eam.transmission.tower'),
    ('eam.voltage.level'), ('eam.manufacturer')
) AS m(model_name)
ON CONFLICT DO NOTHING;

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE roles IS 'Security roles including EAM-specific groups';
